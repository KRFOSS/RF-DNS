use crate::config::*;
use crate::errors::*;
use crate::common::*;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

pub struct DnsResolver {
    dns_servers: Arc<[SocketAddr]>, // Vec 대신 Arc<[T]> 사용
    active_queries: Arc<AtomicUsize>,
}

impl DnsResolver {
    pub fn new() -> DnsResult<Self> {
        let dns_servers: Arc<[SocketAddr]> = ROOT_DNS_SERVERS
            .iter()
            .map(|ip| SocketAddr::new(ip.parse().unwrap(), 53))
            .collect();

        info!(
            "🔄 DNS resolver initialized with {} DNS servers",
            dns_servers.len()
        );

        Ok(Self {
            dns_servers,
            active_queries: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub async fn resolve_domain(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> DnsResult<Message> {
        debug!("🔍 Resolving domain: {}, type: {:?}", domain, record_type);

        // 도메인 검증 및 정규화
        let normalized_domain = normalize_domain(domain)?;
        
        let domain_name = Name::from_str(&normalized_domain)
            .map_err(|e| DnsError::ParseError(format!("Invalid domain name: {}", e)))?;

        // 병렬 DNS 쿼리
        match self.query_servers_parallel(&domain_name, record_type).await {
            Ok(Some(response)) => {
                match response.response_code() {
                    ResponseCode::NoError | ResponseCode::NXDomain => Ok(response),
                    _ => {
                        warn!("⚠️ DNS server returned error for domain {}: {:?}",
                            domain, response.response_code());
                        Ok(response)
                    }
                }
            }
            Ok(None) => {
                warn!("⚠️ No response from DNS servers for domain: {}", domain);
                Ok(create_error_response(generate_query_id(), ResponseCode::ServFail))
            }
            Err(e) => {
                error!("❌ Error querying DNS servers for domain {}: {}", domain, e);
                Ok(create_error_response(generate_query_id(), ResponseCode::ServFail))
            }
        }
    }

    async fn query_servers_parallel(
        &self,
        name: &Name,
        record_type: RecordType,
    ) -> DnsResult<Option<Message>> {
        self.active_queries.fetch_add(1, Ordering::Relaxed);
        
        // 서버 최적화
        let optimized_servers = get_optimal_servers(&self.dns_servers);
        
        // 빠른 실패를 위한 타임아웃 설정
        let query_timeout = std::cmp::min(QUERY_TIMEOUT, std::time::Duration::from_millis(3000));
        
        // 병렬 쿼리 (처음 성공하는 응답 반환)
        let mut tasks = Vec::with_capacity(optimized_servers.len().min(4)); // 최대 4개 서버만 동시 쿼리
        
        for &server in optimized_servers.iter().take(4) {
            let name_clone = name.clone();
            let task = tokio::spawn(async move {
                Self::query_single_server(server, &name_clone, record_type).await
            });
            tasks.push(task);
        }

        // 첫 번째 성공 응답 대기
        let mut result = None;
        while let Some(task_result) = tasks.pop() {
            if let Ok(response_result) = timeout(query_timeout, task_result).await {
                if let Ok(Ok(response)) = response_result {
                    result = Some(response);
                    break;
                }
            }
        }

        // 남은 태스크들 취소
        for task in tasks {
            task.abort();
        }

        self.active_queries.fetch_sub(1, Ordering::Relaxed);
        Ok(result)
    }

    async fn query_single_server(
        server: SocketAddr,
        name: &Name,
        record_type: RecordType,
    ) -> DnsResult<Message> {
        let socket = get_pooled_socket().await?;

        // DNS 쿼리 생성
        let mut query = Message::new();
        query.set_id(generate_query_id());
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(true);
        query.add_query(Query::query(name.clone(), record_type));

        let query_bytes = query.to_vec()?;

        // UDP 전송
        socket.send_to(&query_bytes, server).await?;

        // 응답 수신
        let mut buffer = vec![0u8; SOCKET_BUFFER_SIZE];
        let (len, received_addr) = socket.recv_from(&mut buffer).await?;

        // 보안 검증
        if received_addr.ip() != server.ip() {
            return_pooled_socket(socket).await;
            return Err(DnsError::NetworkError(format!(
                "Response from unexpected address: expected {}, got {}",
                server.ip(),
                received_addr.ip()
            )));
        }

        buffer.truncate(len);
        return_pooled_socket(socket).await;

        let response = Message::from_vec(&buffer)?;

        // 응답 검증
        if response.id() != query.id() {
            return Err(DnsError::NetworkError(format!(
                "Response ID mismatch: expected {}, got {}",
                query.id(),
                response.id()
            )));
        }

        debug!(
            "📨 Response from {}: {} answers, rcode: {:?}",
            server,
            response.answers().len(),
            response.response_code()
        );

        Ok(response)
    }

    pub fn get_active_queries(&self) -> usize {
        self.active_queries.load(Ordering::Relaxed)
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new().expect("Failed to create DNS resolver")
    }
}

impl std::fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsResolver")
            .field("dns_servers_count", &self.dns_servers.len())
            .field("active_queries", &self.active_queries.load(Ordering::Relaxed))
            .finish()
    }
}
