use crate::config::*;
use crate::errors::*;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout;
use tracing::{debug, info, warn};

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

        let domain_name = Name::from_str(domain)
            .map_err(|e| DnsError::ParseError(format!("Invalid domain name: {}", e)))?;

        // DNS 서버들에 병렬로 쿼리
        match self
            .query_servers_parallel(&domain_name, record_type, &self.dns_servers)
            .await
        {
            Ok(Some(response)) => {
                info!(
                    "✅ DNS resolution completed for domain: {}, found {} records",
                    domain,
                    response.answers().len()
                );
                Ok(response)
            }
            Ok(None) => {
                warn!("⚠️ No response from DNS servers for domain: {}", domain);
                // NXDOMAIN 반환
                let mut response = Message::new();
                response.set_response_code(ResponseCode::NXDomain);
                response.set_message_type(MessageType::Response);
                response.set_recursion_available(true);
                response.add_query(Query::query(domain_name, record_type));
                Ok(response)
            }
            Err(e) => {
                warn!("❌ Error querying DNS servers for domain {}: {}", domain, e);
                Err(e)
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
            "dns_servers_count".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.dns_servers.len())),
        );
        stats.insert(
            "active_queries".to_string(),
            serde_json::Value::Number(serde_json::Number::from(
                self.active_queries.load(Ordering::Relaxed),
            )),
        );

        stats
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
