use crate::errors::*;
use crate::metrics::Protocol;
use crate::state::AppState;
use quinn::{Connection, Endpoint, ServerConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

const MAX_DNS_MESSAGE_SIZE: usize = 65535;

pub struct DoQServer {
    state: AppState,
}

impl DoQServer {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn run(
        &self,
        port: u16,
        cert_path: Option<String>,
        key_path: Option<String>,
    ) -> DnsResult<()> {
        let server_config = self.create_server_config(cert_path, key_path).await?;

        let addr: SocketAddr = format!("0.0.0.0:{}", port)
            .parse()
            .map_err(|e| DnsError::ConfigurationError(format!("Invalid address: {}", e)))?;

        let endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| DnsError::ServerError(format!("Failed to create QUIC endpoint: {}", e)))?;

        info!("🚀 DoQ server listening on {}", addr);

        while let Some(conn) = endpoint.accept().await {
            let state = self.state.clone();
            tokio::spawn(async move {
                match conn.await {
                    Ok(connection) => {
                        if let Err(e) = Self::handle_connection(connection, state).await {
                            error!("❌ DoQ connection error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("❌ DoQ connection failed: {}", e);
                    }
                }
            });
        }

        Ok(())
    }

    async fn create_server_config(
        &self,
        cert_path: Option<String>,
        key_path: Option<String>,
    ) -> DnsResult<ServerConfig> {
        let (cert_chain, private_key) = match (cert_path, key_path) {
            (Some(cert_file), Some(key_file)) => {
                info!("🔐 Loading TLS certificate from: {}", cert_file);
                info!("🔐 Loading TLS private key from: {}", key_file);
                self.load_certificates(&cert_file, &key_file).await?
            }
            (None, None) => {
                info!("🔐 No certificate provided, generating self-signed certificate for DoQ");
                self.generate_self_signed_cert()?
            }
            _ => {
                return Err(DnsError::ConfigurationError(
                    "Both certificate and key file must be provided, or neither".to_string(),
                ));
            }
        };

        let mut server_config = ServerConfig::with_single_cert(cert_chain, private_key)
            .map_err(|e| DnsError::TlsError(format!("Failed to create server config: {}", e)))?;

        // QUIC 전송 설정
        let transport_config = Arc::get_mut(&mut server_config.transport).ok_or_else(|| {
            DnsError::ConfigurationError("Failed to get transport config".to_string())
        })?;

        // DoQ 특화 설정
        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(100));
        transport_config.max_concurrent_uni_streams(VarInt::from_u32(100));
        transport_config
            .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));

        Ok(server_config)
    }

    async fn load_certificates(
        &self,
        cert_file: &str,
        key_file: &str,
    ) -> DnsResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let cert_chain = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(cert_file).map_err(|e| {
                DnsError::TlsError(format!("Failed to open certificate file: {}", e))
            })?,
        ))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DnsError::TlsError(format!("Failed to parse certificate: {}", e)))?;

        let private_key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(key_file)
                .map_err(|e| DnsError::TlsError(format!("Failed to open key file: {}", e)))?,
        ))
        .map_err(|e| DnsError::TlsError(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| DnsError::TlsError("No private key found".to_string()))?;

        Ok((cert_chain, private_key))
    }

    fn generate_self_signed_cert(
        &self,
    ) -> DnsResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        use rcgen::generate_simple_self_signed;

        let subject_alt_names = vec!["localhost".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names)
            .map_err(|e| DnsError::TlsError(format!("Failed to generate certificate: {}", e)))?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        // PEM을 DER로 변환
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                DnsError::TlsError(format!("Failed to parse generated certificate: {}", e))
            })?;

        let key_der = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .map_err(|e| {
                DnsError::TlsError(format!("Failed to parse generated private key: {}", e))
            })?
            .ok_or_else(|| {
                DnsError::TlsError("No private key found in generated certificate".to_string())
            })?;

        Ok((cert_der, key_der))
    }

    async fn handle_connection(connection: Connection, state: AppState) -> DnsResult<()> {
        info!(
            "🔗 New DoQ connection from: {}",
            connection.remote_address()
        );

        // 연결당 스트림 처리
        loop {
            tokio::select! {
                stream = connection.accept_bi() => {
                    match stream {
                        Ok((send, recv)) => {
                            let state = state.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_stream(send, recv, state).await {
                                    error!("❌ DoQ stream error: {}", e);
                                }
                            });
                        }
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                            info!("🔗 DoQ connection closed by client");
                            break;
                        }
                        Err(e) => {
                            error!("❌ DoQ stream accept error: {}", e);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    // 타임아웃 처리
                    warn!("⏰ DoQ connection timeout");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        state: AppState,
    ) -> DnsResult<()> {
        // DNS 메시지 길이 읽기 (2바이트)
        let mut len_bytes = [0u8; 2];
        recv.read_exact(&mut len_bytes)
            .await
            .map_err(|e| DnsError::NetworkError(format!("Failed to read message length: {}", e)))?;

        let message_len = u16::from_be_bytes(len_bytes) as usize;

        // DNS 메시지가 너무 큰 경우 방지
        if message_len > MAX_DNS_MESSAGE_SIZE {
            return Err(DnsError::ParseError(format!(
                "DNS message too large: {}",
                message_len
            )));
        }

        // DNS 메시지 읽기
        let mut dns_message = vec![0u8; message_len];
        recv.read_exact(&mut dns_message)
            .await
            .map_err(|e| DnsError::NetworkError(format!("Failed to read DNS message: {}", e)))?;

        debug!(
            "📨 Received DoQ DNS query, size: {} bytes",
            dns_message.len()
        );

        // DNS 쿼리 처리
        match state.process_dns_query(&dns_message, Protocol::DoQ).await {
            Ok(response) => {
                // 응답 길이 전송
                let response_len = response.len() as u16;
                send.write_all(&response_len.to_be_bytes())
                    .await
                    .map_err(|e| {
                        DnsError::NetworkError(format!("Failed to write response length: {}", e))
                    })?;

                // 응답 데이터 전송
                send.write_all(&response).await.map_err(|e| {
                    DnsError::NetworkError(format!("Failed to write response: {}", e))
                })?;

                send.finish().map_err(|e| {
                    DnsError::NetworkError(format!("Failed to finish stream: {}", e))
                })?;

                debug!("📤 Sent DoQ DNS response, size: {} bytes", response.len());
            }
            Err(e) => {
                error!("❌ DoQ DNS query processing error: {}", e);

                // 에러 응답 생성 및 전송
                let error_response = Self::create_error_response(&dns_message);
                let response_len = error_response.len() as u16;

                let _ = send.write_all(&response_len.to_be_bytes()).await;
                let _ = send.write_all(&error_response).await;
                let _ = send.finish();
            }
        }

        Ok(())
    }

    fn create_error_response(query_data: &[u8]) -> Vec<u8> {
        use hickory_proto::op::{Message, ResponseCode};

        // 원본 쿼리 파싱 시도
        if let Ok(query) = Message::from_vec(query_data) {
            let mut response = Message::new();
            response.set_id(query.id());
            response.set_message_type(hickory_proto::op::MessageType::Response);
            response.set_response_code(ResponseCode::ServFail);
            response.add_queries(query.queries().iter().cloned());

            response.to_vec().unwrap_or_else(|_| vec![])
        } else {
            // 파싱 실패 시 빈 응답
            vec![]
        }
    }
}

// 메인 실행 함수
pub async fn run_doq_server(
    state: AppState,
    port: u16,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> DnsResult<()> {
    let server = DoQServer::new(state);
    server.run(port, cert_path, key_path).await
}
