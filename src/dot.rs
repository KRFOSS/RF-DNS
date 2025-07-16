use anyhow::Result;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::io::{self, BufReader};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tracing::{debug, error, info};

use crate::app::DnsState;

pub struct DoTServer {
    state: DnsState,
}

impl DoTServer {
    pub fn new(state: DnsState) -> Self {
        Self { state }
    }

    async fn handle_connection(
        &self,
        mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    ) -> Result<()> {
        loop {
            // Read the length prefix (2 bytes)
            let mut len_bytes = [0; 2];
            if stream.read_exact(&mut len_bytes).await.is_err() {
                break;
            }

            let message_len = u16::from_be_bytes(len_bytes) as usize;
            if message_len > 4096 {
                error!("DNS message too large: {} bytes", message_len);
                break;
            }

            // Read the DNS message
            let mut message_bytes = vec![0; message_len];
            if stream.read_exact(&mut message_bytes).await.is_err() {
                break;
            }

            // Parse the DNS message
            let message = match Message::from_bytes(&message_bytes) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("Failed to parse DNS message: {}", e);
                    continue;
                }
            };

            debug!(
                "Received DNS query over TLS: {:?}",
                message.queries().first()
            );

            // Handle the DNS request
            let response =
                match crate::dns_utils::handle_dns_request(message, self.state.clone()).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!("Failed to handle DNS request: {}", e);
                        let mut error_response = Message::new();
                        error_response.set_response_code(ResponseCode::ServFail);
                        error_response
                    }
                };

            // Serialize the response
            let response_bytes = match response.to_bytes() {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to serialize DNS response: {}", e);
                    continue;
                }
            };

            // Send the response with length prefix
            let response_len = response_bytes.len() as u16;
            let len_bytes = response_len.to_be_bytes();

            if stream.write_all(&len_bytes).await.is_err() {
                break;
            }
            if stream.write_all(&response_bytes).await.is_err() {
                break;
            }
        }

        Ok(())
    }
}

fn load_certs(cert_pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut cert_reader = BufReader::new(cert_pem);
    rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_certs_from_file(cert_path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let cert_pem = std::fs::read(cert_path)?;
    load_certs(&cert_pem)
}

fn load_keys(key_pem: &[u8]) -> io::Result<Vec<PrivateKeyDer<'static>>> {
    let mut key_reader = BufReader::new(key_pem);
    rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map(|key| key.map(PrivateKeyDer::from))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}

fn load_keys_from_file(key_path: &str) -> io::Result<Vec<PrivateKeyDer<'static>>> {
    let key_pem = std::fs::read(key_path)?;
    load_keys(&key_pem)
}

fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    Ok((cert_pem.as_bytes().to_vec(), key_pem.as_bytes().to_vec()))
}

pub async fn run_dot_server(
    state: DnsState,
    port: u16,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> Result<()> {
    let (certs, mut keys) = match (cert_path, key_path) {
        (Some(cert_file), Some(key_file)) => {
            info!("Loading TLS certificate from: {}", cert_file);
            info!("Loading TLS private key from: {}", key_file);

            let certs = load_certs_from_file(&cert_file).map_err(|e| {
                anyhow::anyhow!("Failed to load certificate file {}: {}", cert_file, e)
            })?;
            let keys = load_keys_from_file(&key_file).map_err(|e| {
                anyhow::anyhow!("Failed to load private key file {}: {}", key_file, e)
            })?;

            (certs, keys)
        }
        (None, None) => {
            info!("No certificate provided, generating self-signed certificate");
            let (cert_pem, key_pem) = generate_self_signed_cert()?;
            let certs = load_certs(&cert_pem)?;
            let keys = load_keys(&key_pem)?;
            (certs, keys)
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Both certificate and key file must be provided, or neither"
            ));
        }
    };

    if keys.is_empty() {
        return Err(anyhow::anyhow!("No private keys found"));
    }

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|e| anyhow::anyhow!("TLS configuration error: {}", e))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    let server = Arc::new(DoTServer::new(state));

    info!("DNS over TLS server listening on 0.0.0.0:{}", port);

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("New DoT connection from: {}", addr);

        let acceptor = acceptor.clone();
        let server = server.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    debug!("TLS handshake successful for {}", addr);
                    if let Err(e) = server.handle_connection(tls_stream).await {
                        error!("Error handling DoT connection from {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    error!("TLS handshake failed for {}: {}", addr, e);
                }
            }
        });
    }
}
