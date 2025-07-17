use anyhow::Result;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

pub struct RecursiveDnsResolver {
    // 루트 네임서버 목록
    root_servers: Vec<SocketAddr>,
    // 캐시된 네임서버 정보
    ns_cache: Arc<RwLock<HashMap<String, Vec<SocketAddr>>>>,
}

// 루트 네임서버 IP 주소들 (13개의 루트 서버)
// 최신 업데이트: 2025년 6월 26일 (root zone version: 2025062601)
const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "170.247.170.2",  // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33",   // m.root-servers.net
];

impl RecursiveDnsResolver {
    pub fn new() -> Result<Self> {
        // 루트 서버들을 SocketAddr로 변환
        let root_servers: Vec<SocketAddr> = ROOT_SERVERS
            .iter()
            .map(|ip| SocketAddr::new(ip.parse().unwrap(), 53))
            .collect();

        info!(
            "Recursive DNS resolver initialized with {} root servers",
            root_servers.len()
        );

        Ok(Self {
            root_servers,
            ns_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// 완전한 재귀 DNS 해결 (루트부터 시작)
    pub async fn resolve_domain(&self, domain: &str, record_type: RecordType) -> Result<Message> {
        debug!(
            "Starting recursive DNS resolution for domain: {}, type: {:?}",
            domain, record_type
        );

        let domain_name = Name::from_str(domain)?;

        // 캐시에서 네임서버 정보 확인
        let cached_servers = {
            let cache = self.ns_cache.read().await;
            cache.get(domain).cloned()
        };

        // 루트 서버부터 시작하여 재귀적으로 해결
        let mut current_servers = cached_servers.unwrap_or_else(|| self.root_servers.clone());
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 10;

        loop {
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                warn!("Max attempts reached for domain: {}", domain);
                break;
            }

            match self
                .query_servers(&domain_name, record_type, &current_servers)
                .await
            {
                Ok(Some(response)) => {
                    // 답변이 있는 경우
                    if !response.answers().is_empty() {
                        info!(
                            "Recursive DNS resolution completed for domain: {}, found {} records",
                            domain,
                            response.answers().len()
                        );
                        return Ok(response);
                    }

                    // 권한 있는 답변이 없지만 추가 정보가 있는 경우
                    if !response.name_servers().is_empty() {
                        // 네임서버 정보에서 다음 서버들을 찾음
                        let next_servers = self.extract_nameservers(&response).await?;

                        if !next_servers.is_empty() && next_servers != current_servers {
                            // 네임서버 정보를 캐시에 저장
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
                    warn!("No response from servers for domain: {}", domain);
                    break;
                }
                Err(e) => {
                    warn!("Error querying servers for domain {}: {}", domain, e);
                    break;
                }
            }
        }

        // 실패한 경우 빈 응답 반환
        let mut message = Message::new();
        message.set_recursion_available(false);
        message.set_authoritative(false);
        message.add_query(Query::query(domain_name, record_type));

        Ok(message)
    }

    /// 서버 목록에서 DNS 쿼리 수행
    async fn query_servers(
        &self,
        name: &Name,
        record_type: RecordType,
        servers: &[SocketAddr],
    ) -> Result<Option<Message>> {
        for server in servers {
            debug!("Querying server: {}", server);

            match self.query_server(*server, name, record_type).await {
                Ok(response) => {
                    return Ok(Some(response));
                }
                Err(e) => {
                    warn!("Failed to query server {}: {}", server, e);
                    continue;
                }
            }
        }
        Ok(None)
    }

    /// 특정 서버에 DNS 쿼리 수행
    async fn query_server(
        &self,
        server: SocketAddr,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Message> {
        // UDP 소켓 생성
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server).await?;

        // DNS 쿼리 메시지 생성
        let mut query = Message::new();
        query.set_id(rand::random::<u16>());
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(false); // 재귀를 원하지 않음 (우리가 직접 처리)
        query.add_query(Query::query(name.clone(), record_type));

        // 쿼리를 바이트로 직렬화
        let query_bytes = query.to_vec()?;

        // UDP로 쿼리 전송
        socket.send(&query_bytes).await?;

        // 응답 받기
        let mut buffer = vec![0u8; 512];
        let len = socket.recv(&mut buffer).await?;
        buffer.truncate(len);

        // 응답 파싱
        let response = Message::from_vec(&buffer)?;

        debug!(
            "Received response from {}: {} answers, {} authorities, {} additionals",
            server,
            response.answers().len(),
            response.name_servers().len(),
            response.additionals().len()
        );

        Ok(response)
    }

    /// 응답에서 네임서버 정보를 추출
    async fn extract_nameservers(&self, response: &Message) -> Result<Vec<SocketAddr>> {
        let mut servers = Vec::new();

        // Authority 섹션에서 NS 레코드 찾기
        for ns_record in response.name_servers() {
            if ns_record.record_type() == RecordType::NS {
                if let Some(rdata) = ns_record.data() {
                    if let Some(ns_name) = rdata.as_ns() {
                        // Additional 섹션에서 해당 네임서버의 A 레코드 찾기
                        for additional in response.additionals() {
                            if additional.name() == &ns_name.0
                                && additional.record_type() == RecordType::A
                            {
                                if let Some(a_rdata) = additional.data() {
                                    if let Some(ip) = a_rdata.as_a() {
                                        let ipv4 = ip.0;
                                        servers.push(SocketAddr::new(ipv4.into(), 53));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Additional 섹션에 IP가 없는 경우, 네임서버 자체를 재귀적으로 해결해야 함
        // 이 부분은 복잡성을 피하기 위해 생략하고 루트 서버 사용
        if servers.is_empty() {
            servers = self.root_servers.clone();
        }

        Ok(servers)
    }
}

impl Default for RecursiveDnsResolver {
    fn default() -> Self {
        Self::new().expect("Failed to create recursive DNS resolver")
    }
}
