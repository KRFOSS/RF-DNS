use crate::config::*;
use crate::errors::*;
use crate::metrics::Protocol;
use crate::state::AppState;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tracing::{debug, error, info, warn};

pub struct DoTServer {
    state: AppState,
    connection_limiter: Arc<Semaphore>,
    active_connections: Arc<AtomicUsize>,
}

impl DoTServer {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            connection_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn run(
        &self,
        port: u16,
        cert_path: Option<String>,
        key_path: Option<String>,
    ) -> DnsResult<()> {
        let tls_acceptor = self.create_tls_acceptor(cert_path, key_path).await?;
        let bind_addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&bind_addr).await?;

        info!("🔐 DoT server listening on {}", bind_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let permit = match self.connection_limiter.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(
                                "🚫 Too many concurrent connections, dropping DoT connection from {}",
                                addr
                            );
                            continue;
                        }
                    };

                    self.active_connections.fetch_add(1, Ordering::Relaxed);

                    let tls_acceptor = tls_acceptor.clone();
                    let state = self.state.clone();
                    let active_connections = self.active_connections.clone();

                    tokio::spawn(async move {
                        let _permit = permit;

                        match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                debug!("🔐 TLS connection established from {}", addr);
                                if let Err(e) =
                                    Self::handle_tls_connection(tls_stream, addr, state).await
                                {
                                    error!("❌ Error handling DoT connection from {}: {}", addr, e);
                                }
                            }
                            Err(e) => {
                                error!("❌ TLS handshake failed from {}: {}", addr, e);
                            }
                        }

                        active_connections.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(e) => {
                    error!("❌ DoT accept error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn create_tls_acceptor(
        &self,
        cert_path: Option<String>,
        key_path: Option<String>,
    ) -> DnsResult<TlsAcceptor> {
        let (cert_pem, key_pem) = match (cert_path, key_path) {
            (Some(cert_file), Some(key_file)) => {
                info!("🔐 Loading TLS certificate from: {}", cert_file);
                info!("🔐 Loading TLS private key from: {}", key_file);

                let cert_pem = tokio::fs::read(&cert_file).await.map_err(|e| {
                    DnsError::TlsError(format!("Failed to read certificate file: {}", e))
                })?;
                let key_pem = tokio::fs::read(&key_file)
                    .await
                    .map_err(|e| DnsError::TlsError(format!("Failed to read key file: {}", e)))?;

                (cert_pem, key_pem)
            }
            (None, None) => {
                info!("🔐 No certificate provided, generating self-signed certificate for DoT");
                self.generate_self_signed_cert()?
            }
            _ => {
                return Err(DnsError::ConfigurationError(
                    "Both certificate and key file must be provided, or neither".to_string(),
                ));
            }
        };

        let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DnsError::TlsError(format!("Failed to parse certificates: {}", e)))?;

        let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_slice()))
            .map_err(|e| DnsError::TlsError(format!("Failed to parse private key: {}", e)))?
            .ok_or_else(|| DnsError::TlsError("No private key found".to_string()))?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| DnsError::TlsError(format!("Failed to create TLS config: {}", e)))?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    async fn handle_tls_connection(
        mut stream: tokio_rustls::server::TlsStream<TcpStream>,
        addr: std::net::SocketAddr,
        state: AppState,
    ) -> DnsResult<()> {
        debug!("📥 DoT connection from {}", addr);

        let mut buffer = vec![0u8; SOCKET_BUFFER_SIZE];

        loop {
            let mut len_bytes = [0u8; 2];
            match stream.read_exact(&mut len_bytes).await {
                Ok(_) => {}
                Err(_) => break,
            }

            let message_len = u16::from_be_bytes(len_bytes) as usize;
            if message_len > SOCKET_BUFFER_SIZE {
                error!("❌ DoT message too large: {} bytes", message_len);
                break;
            }

            if buffer.len() < message_len {
                buffer.resize(message_len, 0);
            }

            if stream.read_exact(&mut buffer[..message_len]).await.is_err() {
                break;
            }

            let query_data = buffer[..message_len].to_vec();

            match state.process_dns_query(&query_data, Protocol::DoT).await {
                Ok(response_data) => {
                    let response_len = response_data.len() as u16;
                    let len_bytes = response_len.to_be_bytes();

                    if stream.write_all(&len_bytes).await.is_err() {
                        break;
                    }

                    if stream.write_all(&response_data).await.is_err() {
                        break;
                    }

                    debug!(
                        "📤 Sent DoT response to {}, size: {}",
                        addr,
                        response_data.len()
                    );
                }
                Err(e) => {
                    error!("❌ Error processing DoT query from {}: {}", addr, e);
                    break;
                }
            }
        }

        debug!("📤 DoT connection closed: {}", addr);
        Ok(())
    }

    fn generate_self_signed_cert(&self) -> DnsResult<(Vec<u8>, Vec<u8>)> {
        use rcgen::generate_simple_self_signed;

        let subject_alt_names = vec!["localhost".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names)
            .map_err(|e| DnsError::TlsError(format!("Failed to generate certificate: {}", e)))?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        Ok((cert_pem.as_bytes().to_vec(), key_pem.as_bytes().to_vec()))
    }
}

pub async fn run_dot_server(
    state: AppState,
    port: u16,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> DnsResult<()> {
    let server = DoTServer::new(state);
    server.run(port, cert_path, key_path).await
}
