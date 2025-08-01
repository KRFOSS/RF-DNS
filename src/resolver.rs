use crate::config::*;
use crate::errors::*;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use once_cell::sync::Lazy;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

// 버퍼 풀을 위한 간단한 구조체
struct BufferPool {
    buffers: RwLock<Vec<Vec<u8>>>,
}

impl BufferPool {
    fn new() -> Self {
        Self {
            buffers: RwLock::new(Vec::new()),
        }
    }

    async fn get_buffer(&self, size: usize) -> Vec<u8> {
        let mut pool = self.buffers.write().await;
        if let Some(mut buffer) = pool.pop() {
            buffer.clear();
            buffer.resize(size, 0);
            buffer
        } else {
            vec![0u8; size]
        }
    }

    async fn return_buffer(&self, buffer: Vec<u8>) {
        let mut pool = self.buffers.write().await;
        if pool.len() < 50 { // 최대 50개 버퍼만 풀에 보관
            pool.push(buffer);
        }
    }
}

static BUFFER_POOL: Lazy<BufferPool> = Lazy::new(|| BufferPool::new());

pub struct DnsResolver {
    dns_servers: Vec<SocketAddr>,
    socket_pool: Arc<RwLock<Vec<UdpSocket>>>,
    query_semaphore: Arc<Semaphore>,
    active_queries: Arc<AtomicUsize>,
}

impl DnsResolver {
    pub fn new() -> DnsResult<Self> {
        let dns_servers: Vec<SocketAddr> = ROOT_DNS_SERVERS
            .iter()
            .map(|ip| SocketAddr::new(ip.parse().unwrap(), 53))
            .collect();

        info!(
            "🔄 DNS resolver initialized with {} DNS servers",
            dns_servers.len()
        );

        let resolver = Self {
            dns_servers,
            socket_pool: Arc::new(RwLock::new(Vec::new())),
            query_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES)),
            active_queries: Arc::new(AtomicUsize::new(0)),
        };

        Ok(resolver)
    }

    pub async fn resolve_domain(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> DnsResult<Message> {
        debug!(
            "🔍 Starting DNS resolution for domain: {}, type: {:?}",
            domain, record_type
        );

        // 도메인 보안 검증 추가
        crate::utils::validate_domain_security(domain)?;

        let domain_name = Name::from_str(domain)
            .map_err(|e| DnsError::ParseError(format!("Invalid domain name: {}", e)))?;

        // DNS 서버들에 병렬로 쿼리
        match self
            .query_servers_parallel(&domain_name, record_type, &self.dns_servers)
            .await
        {
            Ok(Some(response)) => match response.response_code() {
                ResponseCode::NoError => Ok(response),
                ResponseCode::NXDomain => Ok(response),
                _ => {
                    warn!(
                        "⚠️ DNS server returned error for domain {}: {:?}",
                        domain,
                        response.response_code()
                    );
                    Ok(response)
                }
            },
            Ok(None) => {
                warn!("⚠️ No response from DNS servers for domain: {}", domain);
                // 모든 서버가 응답하지 않을 때 SERVFAIL 반환
                let mut response = Message::new();
                response.set_response_code(ResponseCode::ServFail);
                response.set_message_type(MessageType::Response);
                response.set_recursion_available(true);
                response.add_query(Query::query(domain_name, record_type));
                Ok(response)
            }
            Err(e) => {
                error!("❌ Error querying DNS servers for domain {}: {}", domain, e);

                // 네트워크 에러 시 SERVFAIL 응답 생성
                let mut response = Message::new();
                response.set_response_code(ResponseCode::ServFail);
                response.set_message_type(MessageType::Response);
                response.set_recursion_available(true);
                response.add_query(Query::query(domain_name, record_type));
                Ok(response)
            }
        }
    }

    async fn query_servers_parallel(
        &self,
        name: &Name,
        record_type: RecordType,
        servers: &[SocketAddr],
    ) -> DnsResult<Option<Message>> {
        use futures::stream::{FuturesUnordered, StreamExt};
        use tokio_util::sync::CancellationToken;

        let _permit = self
            .query_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| DnsError::ServerError("Too many concurrent queries".to_string()))?;

        self.active_queries.fetch_add(1, Ordering::Relaxed);

        let cancel_token = CancellationToken::new();
        let mut futures = FuturesUnordered::new();

        for &server in servers.iter() {
            let name = name.clone();
            let cancel_token = cancel_token.clone();

            let future = async move {
                let query_future = self.query_server_optimized(server, &name, record_type);
                tokio::select! {
                    result = timeout(QUERY_TIMEOUT, query_future) => {
                        match result {
                            Ok(Ok(response)) => {
                                debug!("✅ Got response from {}: rcode={:?}", server, response.response_code());

                                // NXDOMAIN도 유효한 응답으로 처리
                                match response.response_code() {
                                    ResponseCode::NoError | ResponseCode::NXDomain => {
                                        Ok(response)
                                    },
                                    ResponseCode::ServFail | ResponseCode::Refused => {
                                        debug!("❌ Server {} returned error: {:?}", server, response.response_code());
                                        Err(DnsError::ServerError(format!("Server {} returned {:?}", server, response.response_code())))
                                    },
                                    _ => {
                                        debug!("⚠️ Server {} returned unexpected response: {:?}", server, response.response_code());
                                        Ok(response) // 기타 응답도 일단 받아들임
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                debug!("❌ Query failed for {}: {}", server, e);
                                Err(e)
                            }
                            Err(_) => {
                                debug!("⏰ Query timeout for {}", server);
                                Err(DnsError::TimeoutError(format!("Query timeout for server {}", server)))
                            }
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        debug!("🚫 Query to {} cancelled", server);
                        Err(DnsError::ServerError("Query cancelled".to_string()))
                    }
                }
            };

            futures.push(future);
        }

        if futures.is_empty() {
            self.active_queries.fetch_sub(1, Ordering::Relaxed);
            return Ok(None);
        }

        let mut result = None;
        let mut errors = Vec::new();

        while let Some(query_result) = futures.next().await {
            match query_result {
                Ok(response) => {
                    debug!(
                        "🎯 Got successful response, canceling remaining {} queries",
                        futures.len()
                    );
                    cancel_token.cancel();
                    result = Some(response);
                    break;
                }
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            }
        }

        self.active_queries.fetch_sub(1, Ordering::Relaxed);

        if result.is_none() && !errors.is_empty() {
            warn!("❌ All DNS servers failed. Errors: {:?}", errors);
        }

        Ok(result)
    }

    async fn query_server_optimized(
        &self,
        server: SocketAddr,
        name: &Name,
        record_type: RecordType,
    ) -> DnsResult<Message> {
        let socket = self.get_socket().await?;

        let mut query = Message::new();
        query.set_id(rand::random::<u16>());
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(true);
        query.add_query(Query::query(name.clone(), record_type));

        let query_bytes = query.to_vec()?;

        // UDP는 연결이 필요 없음, 직접 send_to 사용
        socket.send_to(&query_bytes, server).await?;

        // 버퍼 풀에서 버퍼 가져오기
        let mut buffer = BUFFER_POOL.get_buffer(SOCKET_BUFFER_SIZE).await;
        let (len, received_addr) = socket.recv_from(&mut buffer).await?;

        // 응답이 올바른 서버에서 온 것인지 확인
        if received_addr.ip() != server.ip() {
            BUFFER_POOL.return_buffer(buffer).await;
            return Err(DnsError::NetworkError(format!(
                "Response from unexpected address: expected {}, got {}",
                server.ip(),
                received_addr.ip()
            )));
        }

        buffer.truncate(len);

        self.return_socket(socket).await;

        let response = Message::from_vec(&buffer)?;

        // 버퍼를 풀에 반환
        BUFFER_POOL.return_buffer(buffer).await;

        // 응답의 유효성 검증
        if response.id() != query.id() {
            return Err(DnsError::NetworkError(format!(
                "Response ID mismatch: expected {}, got {}",
                query.id(),
                response.id()
            )));
        }

        debug!(
            "📨 Received response from {}: {} answers, {} authorities, {} additionals, rcode: {:?}",
            server,
            response.answers().len(),
            response.name_servers().len(),
            response.additionals().len(),
            response.response_code()
        );

        Ok(response)
    }

    async fn get_socket(&self) -> DnsResult<UdpSocket> {
        // 먼저 읽기 락으로 빠르게 확인
        let pool_reader = self.socket_pool.read().await;
        if !pool_reader.is_empty() {
            drop(pool_reader);
            // 쓰기 락으로 실제 소켓 가져오기
            let mut pool = self.socket_pool.write().await;
            if let Some(socket) = pool.pop() {
                return Ok(socket);
            }
        } else {
            drop(pool_reader);
        }

        // 풀이 비어있으면 새 소켓 생성 (락 없이)
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| DnsError::NetworkError(format!("Failed to create socket: {}", e)))
    }

    async fn return_socket(&self, socket: UdpSocket) {
        let mut pool = self.socket_pool.write().await;
        if pool.len() < SOCKET_POOL_SIZE {
            pool.push(socket);
        }
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
            .field(
                "active_queries",
                &self.active_queries.load(Ordering::Relaxed),
            )
            .finish()
    }
}
