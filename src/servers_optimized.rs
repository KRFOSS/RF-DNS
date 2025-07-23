use crate::config::*;
use crate::errors::*;
use crate::metrics::Protocol;
use crate::state::AppState;
use crate::common::*;
use hickory_proto::op::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

// 통합 서버 구조체 (메모리 최적화)
pub struct DnsServer {
    state: AppState,
    connection_limiter: Arc<Semaphore>,
    active_connections: Arc<AtomicUsize>,
}

impl DnsServer {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            connection_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    // UDP 서버 (최적화된 단일 스레드 버전)
    pub async fn run_udp(&self, port: u16) -> DnsResult<()> {
        let bind_addr = format!("0.0.0.0:{}", port);
        let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
        info!("📡 UDP DNS server listening on {}", bind_addr);

        // 통계 태스크
        let active_connections = self.active_connections.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(STATS_INTERVAL);
            loop {
                interval.tick().await;
                debug!("📊 UDP connections: {}", active_connections.load(Ordering::Relaxed));
            }
        });

        // 메인 UDP 루프 (단일 스레드로 최적화)
        let mut buffer = vec![0u8; SOCKET_BUFFER_SIZE];
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((len, addr)) => {
                    // 연결 제한 확인
                    if let Ok(_permit) = self.connection_limiter.clone().try_acquire_owned() {
                        self.active_connections.fetch_add(1, Ordering::Relaxed);
                        let query_data = buffer[..len].to_vec();
                        
                        // 빠른 인라인 처리
                        if let Ok(response) = self.state.process_dns_query(&query_data, Protocol::UDP).await {
                            let response_len = std::cmp::min(response.len(), 512); // UDP 제한
                            if socket.send_to(&response[..response_len], addr).await.is_err() {
                                debug!("Failed to send UDP response to {}", addr);
                            }
                        }
                        
                        self.active_connections.fetch_sub(1, Ordering::Relaxed);
                    } else {
                        warn!("🚫 UDP connection limit reached, dropping packet from {}", addr);
                    }
                }
                Err(e) => {
                    error!("❌ UDP receive error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    }

    // TCP 서버 (최적화된 연결 관리)
    pub async fn run_tcp(&self, port: u16) -> DnsResult<()> {
        let bind_addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&bind_addr).await?;
        info!("📡 TCP DNS server listening on {}", bind_addr);

        // 통계 태스크
        let active_connections = self.active_connections.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(STATS_INTERVAL);
            loop {
                interval.tick().await;
                debug!("📊 TCP connections: {}", active_connections.load(Ordering::Relaxed));
            }
        });

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    if let Ok(permit) = self.connection_limiter.clone().try_acquire_owned() {
                        self.active_connections.fetch_add(1, Ordering::Relaxed);
                        let state = self.state.clone();
                        let active_connections = self.active_connections.clone();

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = Self::handle_tcp_connection(stream, addr, state).await {
                                debug!("TCP connection error from {}: {}", addr, e);
                            }
                            active_connections.fetch_sub(1, Ordering::Relaxed);
                        });
                    } else {
                        warn!("🚫 TCP connection limit reached, dropping connection from {}", addr);
                    }
                }
                Err(e) => {
                    error!("❌ TCP accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    // 최적화된 TCP 연결 핸들러
    async fn handle_tcp_connection(
        mut stream: tokio::net::TcpStream,
        addr: SocketAddr,
        state: AppState,
    ) -> DnsResult<()> {
        debug!("📥 TCP connection from {}", addr);

        let mut buffer = vec![0u8; SOCKET_BUFFER_SIZE];

        loop {
            // TCP 길이 프리픽스 읽기 (2바이트)
            let mut len_bytes = [0u8; 2];
            if stream.read_exact(&mut len_bytes).await.is_err() {
                break; // 연결 종료
            }

            let message_len = u16::from_be_bytes(len_bytes) as usize;
            if message_len > SOCKET_BUFFER_SIZE || message_len < MIN_DNS_MESSAGE_SIZE {
                error!("❌ Invalid TCP message length: {} bytes", message_len);
                break;
            }

            // 메시지 읽기
            if buffer.len() < message_len {
                buffer.resize(message_len, 0);
            }
            if stream.read_exact(&mut buffer[..message_len]).await.is_err() {
                break;
            }

            let query_data = buffer[..message_len].to_vec();

            // DNS 쿼리 처리
            match state.process_dns_query(&query_data, Protocol::TCP).await {
                Ok(response_data) => {
                    // TCP 길이 프리픽스 + 응답 전송
                    let encoded_response = encode_tcp_length(&response_data);
                    
                    if stream.write_all(&encoded_response).await.is_err() {
                        break;
                    }

                    debug!("📤 Sent TCP response to {}, size: {}", addr, response_data.len());
                }
                Err(e) => {
                    debug!("❌ Error processing TCP query from {}: {}", addr, e);
                    break;
                }
            }
        }

        debug!("📤 TCP connection closed: {}", addr);
        Ok(())
    }

    pub fn get_connection_count(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
}

// 간단한 팩토리 함수들 (코드 중복 제거)
pub async fn run_udp_server(state: AppState, port: u16) -> DnsResult<()> {
    let server = DnsServer::new(state);
    server.run_udp(port).await
}

pub async fn run_tcp_server(state: AppState, port: u16) -> DnsResult<()> {
    let server = DnsServer::new(state);
    server.run_tcp(port).await
}
