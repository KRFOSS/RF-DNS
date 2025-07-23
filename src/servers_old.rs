use crate::config::*;
use crate::errors::*;
use crate::metrics::Protocol;
use crate::state::AppState;
use hickory_proto::op::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

// UDP DNS 서버
pub struct UdpDnsServer {
    state: AppState,
    connection_limiter: Arc<Semaphore>,
    active_connections: Arc<AtomicUsize>,
}

impl UdpDnsServer {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            connection_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn run(&self, port: u16) -> DnsResult<()> {
        let bind_addr = format!("0.0.0.0:{}", port);
        let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);

        info!("📡 UDP DNS server listening on {}", bind_addr);

        // 워커 스레드 생성
        let mut tasks = Vec::new();
        for worker_id in 0..UDP_WORKERS {
            let socket = socket.clone();
            let state = self.state.clone();
            let connection_limiter = self.connection_limiter.clone();
            let active_connections = self.active_connections.clone();

            let task = tokio::spawn(async move {
                debug!("🔧 UDP worker {} started", worker_id);
                Self::worker_loop(
                    worker_id,
                    socket,
                    state,
                    connection_limiter,
                    active_connections,
                )
                .await;
            });
            tasks.push(task);
        }

        // 통계 출력 태스크
        let active_connections = self.active_connections.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(STATS_INTERVAL);
            loop {
                interval.tick().await;
                debug!(
                    "📊 UDP active connections: {}",
                    active_connections.load(Ordering::Relaxed)
                );
            }
        });

        // 모든 워커 완료 대기
        for task in tasks {
            let _ = task.await;
        }

        Ok(())
    }

    async fn worker_loop(
        worker_id: usize,
        socket: Arc<UdpSocket>,
        state: AppState,
        connection_limiter: Arc<Semaphore>,
        active_connections: Arc<AtomicUsize>,
    ) {
        let mut buffer = vec![0u8; SOCKET_BUFFER_SIZE];

        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((size, addr)) => {
                    let query_data = buffer[..size].to_vec();

                    // 연결 제한 확인
                    let permit = match connection_limiter.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(
                                "🚫 Too many concurrent connections, dropping UDP query from {}",
                                addr
                            );
                            continue;
                        }
                    };

                    active_connections.fetch_add(1, Ordering::Relaxed);

                    let socket = socket.clone();
                    let state = state.clone();
                    let active_connections = active_connections.clone();

                    tokio::spawn(async move {
                        let _permit = permit;

                        if let Err(e) = Self::handle_query(query_data, addr, &socket, state).await {
                            error!("❌ Error handling UDP query from {}: {}", addr, e);
                        }

                        active_connections.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    error!("❌ UDP socket error in worker {}: {}", worker_id, e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_query(
        query_data: Vec<u8>,
        addr: SocketAddr,
        socket: &UdpSocket,
        state: AppState,
    ) -> DnsResult<()> {
        debug!(
            "📥 Received UDP query from {}, size: {}",
            addr,
            query_data.len()
        );

        let response_data = state.process_dns_query(&query_data, Protocol::UDP).await?;

        // UDP 응답 크기 제한 (512 바이트)
        if response_data.len() > 512 {
            warn!(
                "⚠️ Response too large for UDP ({}), truncating",
                response_data.len()
            );

            // 잘린 응답 생성
            if let Ok(mut response) = Message::from_vec(&response_data) {
                response.set_truncated(true);
                response.insert_answers(vec![]);

                if let Ok(truncated_data) = response.to_vec() {
                    socket.send_to(&truncated_data, addr).await?;
                } else {
                    socket.send_to(&response_data[..512], addr).await?;
                }
            } else {
                socket.send_to(&response_data[..512], addr).await?;
            }
        } else {
            socket.send_to(&response_data, addr).await?;
        }

        debug!(
            "📤 Sent UDP response to {}, size: {}",
            addr,
            response_data.len()
        );
        Ok(())
    }
}

// TCP DNS 서버
pub struct TcpDnsServer {
    state: AppState,
    connection_limiter: Arc<Semaphore>,
    active_connections: Arc<AtomicUsize>,
}

impl TcpDnsServer {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            connection_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn run(&self, port: u16) -> DnsResult<()> {
        let bind_addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&bind_addr).await?;

        info!("📡 TCP DNS server listening on {}", bind_addr);

        // 통계 출력 태스크
        let active_connections = self.active_connections.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(STATS_INTERVAL);
            loop {
                interval.tick().await;
                debug!(
                    "📊 TCP active connections: {}",
                    active_connections.load(Ordering::Relaxed)
                );
            }
        });

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // 연결 제한 확인
                    let permit = match self.connection_limiter.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(
                                "🚫 Too many concurrent connections, dropping TCP connection from {}",
                                addr
                            );
                            continue;
                        }
                    };

                    self.active_connections.fetch_add(1, Ordering::Relaxed);
                    let state = self.state.clone();
                    let active_connections = self.active_connections.clone();

                    tokio::spawn(async move {
                        let _permit = permit;

                        if let Err(e) = Self::handle_connection(stream, addr, state).await {
                            error!("❌ Error handling TCP connection from {}: {}", addr, e);
                        }

                        active_connections.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    error!("❌ TCP accept error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_connection(
        mut stream: tokio::net::TcpStream,
        addr: SocketAddr,
        state: AppState,
    ) -> DnsResult<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        debug!("📥 TCP connection from {}", addr);

        let mut buffer = vec![0u8; SOCKET_BUFFER_SIZE];

        loop {
            // 길이 읽기 (2바이트)
            let mut len_bytes = [0u8; 2];
            match stream.read_exact(&mut len_bytes).await {
                Ok(_) => {}
                Err(_) => break, // 연결 종료
            }

            let message_len = u16::from_be_bytes(len_bytes) as usize;
            if message_len > SOCKET_BUFFER_SIZE {
                error!("❌ TCP message too large: {} bytes", message_len);
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
                    // 응답 길이 + 응답 데이터 전송
                    let response_len = response_data.len() as u16;
                    let len_bytes = response_len.to_be_bytes();

                    if stream.write_all(&len_bytes).await.is_err() {
                        break;
                    }

                    if stream.write_all(&response_data).await.is_err() {
                        break;
                    }

                    debug!(
                        "📤 Sent TCP response to {}, size: {}",
                        addr,
                        response_data.len()
                    );
                }
                Err(e) => {
                    error!("❌ Error processing TCP query from {}: {}", addr, e);
                    break;
                }
            }
        }

        debug!("📤 TCP connection closed: {}", addr);
        Ok(())
    }
}

// 서버 실행 함수들
pub async fn run_udp_server(state: AppState, port: u16) -> DnsResult<()> {
    let server = UdpDnsServer::new(state);
    server.run(port).await
}

pub async fn run_tcp_server(state: AppState, port: u16) -> DnsResult<()> {
    let server = TcpDnsServer::new(state);
    server.run(port).await
}
