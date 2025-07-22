use crate::errors::*;
use crate::metrics::Protocol;
use crate::state::AppState;
use axum::{
    Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use std::collections::HashMap;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info};

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
                info!("🔐 Loading TLS private key from: {}", key_file);

                RustlsConfig::from_pem_file(cert_file, key_file)
                    .await
                    .map_err(|e| {
                        DnsError::TlsError(format!("Failed to load TLS configuration: {}", e))
                    })?
            }
            (None, None) => {
                info!("🔐 No certificate provided, generating self-signed certificate for DoH");
                let (cert_pem, key_pem) = self.generate_self_signed_cert()?;

                RustlsConfig::from_pem(cert_pem, key_pem)
                    .await
                    .map_err(|e| {
                        DnsError::TlsError(format!("Failed to create TLS configuration: {}", e))
                    })?
            }
            _ => {
                return Err(DnsError::ConfigurationError(
                    "Both certificate and key file must be provided, or neither".to_string(),
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
            .route("/", get(root_handler))
            .route("/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .route("/cache/stats", get(cache_stats_handler))
            .route("/cache/clear", delete(clear_cache_handler))
            .route("/cache/domain/{domain}", delete(clear_domain_cache_handler))
            .route("/.well-known/doh", get(doh_metadata_handler))
            .route(
                "/dns-query",
                get(dns_query_get_handler)
                    .post(dns_query_post_handler)
                    .options(dns_query_options_handler),
            )
            .route(
                "/up/{upstream}",
                get(dns_query_upstream_get_handler)
                    .post(dns_query_upstream_post_handler)
                    .options(dns_query_options_handler),
            )
            .layer(CorsLayer::permissive())
            .with_state(self.state.clone())
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

// HTTP 핸들러들
async fn root_handler() -> impl IntoResponse {
    axum::response::Redirect::permanent("https://krfoss.org")
}

async fn health_handler() -> impl IntoResponse {
    "OK"
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = state.get_metrics();

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(metrics.to_string()))
        .unwrap()
}

async fn cache_stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.get_cache_stats();

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(stats.to_string()))
        .unwrap()
}

async fn clear_cache_handler(State(state): State<AppState>) -> impl IntoResponse {
    state.clear_cache();

    let response = serde_json::json!({
        "status": "success",
        "message": "All cache entries cleared"
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(response.to_string()))
        .unwrap()
}

async fn clear_domain_cache_handler(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let removed_count = state.remove_domain_from_cache(&domain);

    let response = serde_json::json!({
        "status": "success",
        "message": format!("Cleared cache for domain: {}", domain),
        "removed_entries": removed_count
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(response.to_string()))
        .unwrap()
}

async fn doh_metadata_handler() -> impl IntoResponse {
    let metadata = serde_json::json!({
        "template": "https://dns.dev.c01.kr/dns-query{?dns}",
        "methods": ["GET", "POST"],
        "formats": ["dns-message"]
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "public, max-age=86400")
        .body(axum::body::Body::from(metadata.to_string()))
        .unwrap()
}

async fn dns_query_get_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, StatusCode> {
    let dns_param = params.get("dns").ok_or(StatusCode::BAD_REQUEST)?;
    let query_data = decode_base64_dns_query(dns_param)?;

    match state.process_dns_query(&query_data, Protocol::DoH).await {
        Ok(response_data) => Ok(create_dns_response(response_data)),
        Err(e) => {
            error!("❌ DoH GET query error: {}", e);
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

    // 요청 본문 크기 검증
    if body.len() > crate::config::MAX_DNS_MESSAGE_SIZE {
        error!("🚨 DNS POST body too large: {} bytes", body.len());
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    if body.len() < crate::config::MIN_DNS_MESSAGE_SIZE {
        error!("🚨 DNS POST body too small: {} bytes", body.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    match state.process_dns_query(&body, Protocol::DoH).await {
        Ok(response_data) => Ok(create_dns_response(response_data)),
        Err(e) => {
            error!("❌ DoH POST query error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn dns_query_upstream_get_handler(
    State(state): State<AppState>,
    Path(upstream_path): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, StatusCode> {
    let dns_param = params.get("dns").ok_or(StatusCode::BAD_REQUEST)?;
    let query_data = decode_base64_dns_query(dns_param)?;

    // 업스트림 서버를 통한 DNS 쿼리 처리
    match state
        .process_dns_query_with_upstream(&query_data, Protocol::DoH, &upstream_path)
        .await
    {
        Ok(response_data) => Ok(create_dns_response(response_data)),
        Err(e) => {
            error!("❌ DoH upstream query error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn dns_query_upstream_post_handler(
    State(state): State<AppState>,
    Path(upstream_path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    validate_dns_headers(&headers)?;

    // 요청 본문 크기 검증
    if body.len() > crate::config::MAX_DNS_MESSAGE_SIZE {
        error!("🚨 DNS upstream POST body too large: {} bytes", body.len());
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    if body.len() < crate::config::MIN_DNS_MESSAGE_SIZE {
        error!("🚨 DNS upstream POST body too small: {} bytes", body.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // 업스트림 서버를 통한 DNS 쿼리 처리
    match state
        .process_dns_query_with_upstream(&body, Protocol::DoH, &upstream_path)
        .await
    {
        Ok(response_data) => Ok(create_dns_response(response_data)),
        Err(e) => {
            error!("❌ DoH upstream POST query error: {}", e);
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

// 헬퍼 함수들
fn decode_base64_dns_query(query_b64: &str) -> Result<Vec<u8>, StatusCode> {
    debug!("🔍 Decoding base64 DNS query: '{}' (length: {})", query_b64, query_b64.len());
    
    // 0. 빈 문자열 체크
    if query_b64.is_empty() {
        error!("🚨 Empty base64 query string");
        return Err(StatusCode::BAD_REQUEST);
    }

    // 1. 길이 검증 (base64로 인코딩된 DNS 메시지 최대 크기)
    if query_b64.len() > crate::config::MAX_BASE64_QUERY_LENGTH {
        error!("🚨 Base64 query too long: {} characters", query_b64.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // 2. 특수문자 검증 (base64 + URL-safe 문자만 허용)
    if !query_b64.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    }) {
        error!("🚨 Invalid characters in base64 query");
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut query_b64 = query_b64.to_string();

    // URL-safe base64를 표준 base64로 변환
    query_b64 = query_b64.replace('-', "+").replace('_', "/");

    // 패딩 추가
    let padding_needed = 4 - (query_b64.len() % 4);
    if padding_needed != 4 {
        query_b64.push_str(&"=".repeat(padding_needed));
    }

    debug!("🔍 Normalized base64 string: '{}'", query_b64);

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&query_b64)
        .map_err(|e| {
            error!("❌ Base64 decode error: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    debug!("🔍 Decoded DNS message: {} bytes", decoded.len());

    // 3. 디코딩된 데이터 크기 검증
    if decoded.len() < crate::config::MIN_DNS_MESSAGE_SIZE {
        error!("🚨 DNS query too short: {} bytes", decoded.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    if decoded.len() > crate::config::MAX_DNS_MESSAGE_SIZE {
        error!("🚨 DNS query too long: {} bytes", decoded.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // 4. DNS 헤더 기본 검증
    if decoded.len() >= 12 {
        let header_hex: String = decoded[..12]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        debug!("🔍 DNS header: {}", header_hex);
    }

    debug!(
        "✅ Base64 DNS query validation passed: {} bytes",
        decoded.len()
    );
    Ok(decoded)
}

fn validate_dns_headers(headers: &HeaderMap) -> Result<(), StatusCode> {
    let content_type = headers.get("content-type").and_then(|v| v.to_str().ok());

    if content_type != Some("application/dns-message") {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // Content-Length 검증
    if let Some(content_length) = headers.get("content-length") {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > crate::config::MAX_DNS_MESSAGE_SIZE {
                    error!("🚨 DNS message too large: {} bytes", length);
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                if length < crate::config::MIN_DNS_MESSAGE_SIZE {
                    error!("🚨 DNS message too small: {} bytes", length);
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
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
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "content-type, accept")
        .body(axum::body::Body::from(response_data))
        .unwrap()
}

// 메인 실행 함수
pub async fn run_doh_server(
    state: AppState,
    port: u16,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> DnsResult<()> {
    let server = DoHServer::new(state);
    server.run(port, cert_path, key_path).await
}
