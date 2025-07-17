use crate::config::*;
use crate::errors::*;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout;
use tracing::{debug, info, warn};

pub struct RecursiveDnsResolver {
    root_servers: Vec<SocketAddr>,
    ns_cache: Arc<RwLock<HashMap<String, Vec<SocketAddr>>>>,
    socket_pool: Arc<RwLock<Vec<UdpSocket>>>,
    query_semaphore: Arc<Semaphore>,
    active_queries: Arc<AtomicUsize>,
}

impl RecursiveDnsResolver {
    pub fn new() -> DnsResult<Self> {
        let root_servers: Vec<SocketAddr> = ROOT_DNS_SERVERS
            .iter()
            .map(|ip| SocketAddr::new(ip.parse().unwrap(), 53))
            .collect();

        info!(
            "🔄 Recursive DNS resolver initialized with {} root servers",
            root_servers.len()
        );

        let resolver = Self {
            root_servers,
            ns_cache: Arc::new(RwLock::new(HashMap::new())),
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
            "🔍 Starting recursive DNS resolution for domain: {}, type: {:?}",
            domain, record_type
        );

        let domain_name = Name::from_str(domain)
            .map_err(|e| DnsError::ParseError(format!("Invalid domain name: {}", e)))?;

        // 캐시된 네임서버 확인
        let cached_servers = {
            let cache = self.ns_cache.read().await;
            cache.get(domain).cloned()
        };

        let mut current_servers = cached_servers.unwrap_or_else(|| self.root_servers.clone());
        let mut attempts = 0;

        loop {
            attempts += 1;
            if attempts > MAX_QUERY_RETRIES {
                warn!(
                    "❌ Max attempts ({}) reached for domain: {}",
                    MAX_QUERY_RETRIES, domain
                );
                return Err(DnsError::TimeoutError(format!(
                    "Max retries exceeded for domain: {}",
                    domain
                )));
            }

            match self
                .query_servers_parallel(&domain_name, record_type, &current_servers)
                .await
            {
                Ok(Some(response)) => {
                    if response.response_code() == ResponseCode::NXDomain {
                        debug!("🚫 NXDOMAIN response for domain: {}", domain);
                        return Ok(response);
                    }

                    if !response.answers().is_empty() {
                        info!(
                            "✅ Recursive DNS resolution completed for domain: {}, found {} records",
                            domain,
                            response.answers().len()
                        );
                        return Ok(response);
                    }

                    if !response.name_servers().is_empty() {
                        let next_servers = self.extract_nameservers(&response).await?;
                        if !next_servers.is_empty() && next_servers != current_servers {
                            // 네임서버 정보 캐시
                            {
                                let mut cache = self.ns_cache.write().await;
                                cache.insert(domain.to_string(), next_servers.clone());
                            }
                            current_servers = next_servers;
                            continue;
                        }
                    }
                    break;
                }
                Ok(None) => {
                    warn!("⚠️ No response from servers for domain: {}", domain);
                    break;
                }
                Err(e) => {
                    warn!("❌ Error querying servers for domain {}: {}", domain, e);
                    if attempts >= MAX_QUERY_RETRIES {
                        return Err(e);
                    }

                    // 지수 백오프 적용
                    let backoff_ms = std::cmp::min(100 * (1 << (attempts - 1)), 2000);
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

                    // 첫 번째 시도가 실패한 경우에만 루트 서버로 돌아가기
                    if attempts == 1 {
                        current_servers = self.root_servers.clone();
                    }
                    continue;
                }
            }
        }

        // 모든 시도가 실패한 경우 NXDOMAIN 반환
        warn!("🚫 Failed to resolve domain: {}", domain);
        let mut response = Message::new();
        response.set_response_code(ResponseCode::NXDomain);
        response.set_message_type(MessageType::Response);
        response.set_recursion_available(true);
        response.add_query(Query::query(domain_name, record_type));
        Ok(response)
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
                                debug!("✅ Got successful response from {}", server);
                                Ok(response)
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
                Err(_) => {
                    continue;
                }
            }
        }

        self.active_queries.fetch_sub(1, Ordering::Relaxed);
        Ok(result)
    }

    async fn query_server_optimized(
        &self,
        server: SocketAddr,
        name: &Name,
        record_type: RecordType,
    ) -> DnsResult<Message> {
        let socket = self.get_socket().await?;
        socket.connect(server).await?;

        let mut query = Message::new();
        query.set_id(rand::random::<u16>());
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(true);
        query.add_query(Query::query(name.clone(), record_type));

        let query_bytes = query.to_vec()?;
        socket.send(&query_bytes).await?;

        let mut buffer = vec![0u8; SOCKET_BUFFER_SIZE];
        let len = socket.recv(&mut buffer).await?;
        buffer.truncate(len);

        self.return_socket(socket).await;

        let response = Message::from_vec(&buffer)?;
        debug!(
            "📨 Received response from {}: {} answers, {} authorities, {} additionals",
            server,
            response.answers().len(),
            response.name_servers().len(),
            response.additionals().len()
        );

        Ok(response)
    }

    async fn extract_nameservers(&self, response: &Message) -> DnsResult<Vec<SocketAddr>> {
        let mut servers = Vec::new();

        for ns_record in response.name_servers() {
            if ns_record.record_type() == RecordType::NS {
                let rdata = ns_record.data();
                if let Some(ns_name) = rdata.as_ns() {
                    // Additional 섹션에서 해당 네임서버의 A/AAAA 레코드 찾기
                    for additional in response.additionals() {
                        if additional.name() == &ns_name.0 {
                            match additional.record_type() {
                                RecordType::A => {
                                    if let Some(ip) = additional.data().as_a() {
                                        let ipv4 = ip.0;
                                        servers.push(SocketAddr::new(ipv4.into(), 53));
                                    }
                                }
                                RecordType::AAAA => {
                                    if let Some(ip) = additional.data().as_aaaa() {
                                        let ipv6 = ip.0;
                                        servers.push(SocketAddr::new(ipv6.into(), 53));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        // Additional 섹션에 IP가 없는 경우 루트 서버 사용
        if servers.is_empty() {
            servers = self.root_servers.clone();
        }

        Ok(servers)
    }

    async fn get_socket(&self) -> DnsResult<UdpSocket> {
        let mut pool = self.socket_pool.write().await;
        if let Some(socket) = pool.pop() {
            Ok(socket)
        } else {
            drop(pool);
            UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| DnsError::NetworkError(format!("Failed to create socket: {}", e)))
        }
    }

    async fn return_socket(&self, socket: UdpSocket) {
        let mut pool = self.socket_pool.write().await;
        if pool.len() < SOCKET_POOL_SIZE {
            pool.push(socket);
        }
    }

    pub fn get_stats(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let mut stats = std::collections::HashMap::new();

        stats.insert(
            "root_servers_count".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.root_servers.len())),
        );
        stats.insert(
            "active_queries".to_string(),
            serde_json::Value::Number(serde_json::Number::from(
                self.active_queries.load(Ordering::Relaxed),
            )),
        );

        // 비동기 캐시 정보는 현재 상태에서 동기적으로 접근할 수 없으므로 placeholder 값 사용
        stats.insert(
            "cached_nameservers".to_string(),
            serde_json::Value::String("N/A (async access required)".to_string()),
        );

        stats
    }
}

impl Default for RecursiveDnsResolver {
    fn default() -> Self {
        Self::new().expect("Failed to create recursive DNS resolver")
    }
}

impl std::fmt::Debug for RecursiveDnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecursiveDnsResolver")
            .field("root_servers_count", &self.root_servers.len())
            .field(
                "active_queries",
                &self.active_queries.load(Ordering::Relaxed),
            )
            .finish()
    }
}
