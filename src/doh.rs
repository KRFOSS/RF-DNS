use crate::errors::*;
use crate::metrics::Protocol;
use crate::state::AppState;
use crate::common::*;
use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, options},
};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use std::collections::HashMap;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

pub struct DoHServer {
    state: AppState,
}

impl DoHServer {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn run(
        &self,
        port: u16,
        cert_path: Option<String>,
        key_path: Option<String>,
    ) -> DnsResult<()> {
        let app = self.create_router();

        let tls_config = match (cert_path, key_path) {
            (Some(cert_file), Some(key_file)) => {
                info!("🔐 Loading TLS certificate from: {}", cert_file);
                RustlsConfig::from_pem_file(cert_file, key_file)
                    .await
                    .map_err(|e| DnsError::TlsError(format!("Failed to load TLS: {}", e)))?
            }
            (None, None) => {
                info!("🔐 Generating self-signed certificate for DoH");
                let (cert_pem, key_pem) = self.generate_self_signed_cert()?;
                RustlsConfig::from_pem(cert_pem, key_pem)
                    .await
                    .map_err(|e| DnsError::TlsError(format!("Failed to create TLS: {}", e)))?
            }
            _ => {
                return Err(DnsError::ConfigurationError(
                    "Both cert and key must be provided, or neither".to_string(),
                ));
            }
        };

        let addr = format!("0.0.0.0:{}", port);
        info!("🌐 DoH server listening on https://{}", addr);

        axum_server::bind_rustls(addr.parse().unwrap(), tls_config)
            .serve(app.into_make_service())
            .await
            .map_err(|e| DnsError::ServerError(format!("DoH server error: {}", e)))?;

        Ok(())
    }

    fn create_router(&self) -> Router {
        Router::new()
            .route("/dns-query", get(dns_query_get_handler))
            .route("/dns-query", post(dns_query_post_handler))
            .route("/dns-query", options(dns_query_options_handler))
            .layer(CorsLayer::permissive())
            .with_state(self.state.clone())
    }

    fn generate_self_signed_cert(&self) -> DnsResult<(Vec<u8>, Vec<u8>)> {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        
        let subject_alt_names = vec!["localhost".to_string()];
        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names)
            .map_err(|e| DnsError::TlsError(format!("Failed to generate cert: {}", e)))?;

        let cert_pem = cert.pem().into_bytes();
        let key_pem = signing_key.serialize_pem().into_bytes();

        Ok((cert_pem, key_pem))
    }
}

// 최적화된 핸들러 함수들
async fn dns_query_get_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, StatusCode> {
    let dns_param = params.get("dns").ok_or(StatusCode::BAD_REQUEST)?;
    let query_data = decode_base64_dns_query(dns_param)?;

    state.metrics.record_request();
    
    match state.process_dns_query(&query_data, Protocol::DoH).await {
        Ok(response_data) => {
            state.metrics.record_success();
            Ok(create_dns_response(response_data))
        }
        Err(e) => {
            state.metrics.record_error();
            error!("❌ DoH GET error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn dns_query_post_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    validate_dns_headers(&headers)?;
    
    // DNS 메시지 검증
    if let Err(_) = validate_dns_message(&body) {
        return Err(StatusCode::BAD_REQUEST);
    }

    state.metrics.record_request();

    match state.process_dns_query(&body, Protocol::DoH).await {
        Ok(response_data) => {
            state.metrics.record_success();
            Ok(create_dns_response(response_data))
        }
        Err(e) => {
            state.metrics.record_error();
            error!("❌ DoH POST error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn dns_query_options_handler() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "content-type, accept")
        .header("access-control-max-age", "86400")
        .body(axum::body::Body::empty())
        .unwrap()
}

// 최적화된 헬퍼 함수들
fn decode_base64_dns_query(query_b64: &str) -> Result<Vec<u8>, StatusCode> {
    if query_b64.len() > crate::config::MAX_BASE64_QUERY_LENGTH {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let query_b64 = query_b64.replace('_', "/").replace('-', "+");
    
    base64::engine::general_purpose::STANDARD
        .decode(query_b64.as_bytes())
        .map_err(|_| StatusCode::BAD_REQUEST)
}

fn validate_dns_headers(headers: &HeaderMap) -> Result<(), StatusCode> {
    if let Some(content_type) = headers.get("content-type") {
        if content_type != "application/dns-message" {
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
    }
    Ok(())
}

fn create_dns_response(response_data: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/dns-message")
        .header("cache-control", "max-age=300")
        .header("access-control-allow-origin", "*")
        .body(axum::body::Body::from(response_data))
        .unwrap()
}

// 간단한 팩토리 함수
pub async fn run_doh_server(
    state: AppState,
    port: u16,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> DnsResult<()> {
    let server = DoHServer::new(state);
    server.run(port, cert_path, key_path).await
}
