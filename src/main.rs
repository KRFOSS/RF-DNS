mod app;
mod cache;
mod cloudflare;
mod dns_server;
mod dns_utils;
mod dot;
mod recursive_dns;

use axum::{
    Router,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get},
};
use base64::Engine;
use clap::Parser;
use std::collections::HashMap;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::info;

pub use app::*;
pub use cache::*;
pub use cloudflare::*;
pub use dns_server::*;
pub use dns_utils::*;
pub use dot::*;
pub use recursive_dns::*;

#[derive(Parser)]
#[command(name = "rfdns")]
#[command(about = "A DNS server with DNS over HTTPS (DoH) and DNS over TLS (DoT) support")]
struct Args {
    /// Path to TLS certificate file for DNS over TLS
    #[arg(long, help = "Path to TLS certificate file (.pem or .crt)")]
    cert: Option<String>,

    /// Path to TLS private key file for DNS over TLS
    #[arg(long, help = "Path to TLS private key file (.pem or .key)")]
    key: Option<String>,

    /// DoH server port
    #[arg(long, default_value = "30057", help = "Port for DNS over HTTPS server")]
    doh_port: u16,

    /// DoT server port
    #[arg(long, default_value = "853", help = "Port for DNS over TLS server")]
    dot_port: u16,

    /// Plain DNS server port
    #[arg(long, default_value = "53", help = "Port for plain DNS server")]
    dns_port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let state = DnsState::new();
    let app = create_app(state.clone());

    // Start plain DNS server in background
    let dns_server = tokio::spawn(run_dns_server(state.clone(), args.dns_port));

    // Start DoT server in background
    let dot_server = tokio::spawn(run_dot_server(state, args.dot_port, args.cert, args.key));

    let listener = TcpListener::bind(format!("0.0.0.0:{}", args.doh_port)).await?;

    info!("DoH Server running on http://0.0.0.0:{}", args.doh_port);
    info!("DoT Server running on 0.0.0.0:{}", args.dot_port);
    info!("Plain DNS Server running on 0.0.0.0:{}", args.dns_port);

    // Start DoH server
    let doh_server = tokio::spawn(async move { axum::serve(listener, app).await });

    // Wait for all servers
    tokio::select! {
        result = dns_server => {
            if let Err(e) = result? {
                eprintln!("DNS server error: {}", e);
            }
        }
        result = dot_server => {
            if let Err(e) = result? {
                eprintln!("DoT server error: {}", e);
            }
        }
        result = doh_server => {
            if let Err(e) = result? {
                eprintln!("DoH server error: {}", e);
            }
        }
    }

    Ok(())
}

fn create_app(state: DnsState) -> Router {
    Router::new()
        .route("/", get(root_page))
        .route("/health", get(health))
        .route("/cache-stats", get(cache_stats))
        .route("/cache/clear", delete(clear_all_cache))
        .route("/cache/domain/:domain", delete(clear_domain_cache))
        .route("/.well-known/doh", get(doh_metadata))
        .route(
            "/dns-query",
            get(dns_query_get)
                .post(dns_query_post)
                .options(dns_query_options),
        )
        .route(
            "/*upstream",
            get(dns_query_with_upstream_get)
                .post(dns_query_with_upstream_post)
                .options(dns_query_options),
        )
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn root_page() -> impl IntoResponse {
    Redirect::permanent("https://krfoss.org")
}

async fn health() -> impl IntoResponse {
    "OK"
}

async fn cache_stats(
    axum::extract::State(state): axum::extract::State<DnsState>,
) -> impl IntoResponse {
    let (entry_count, weighted_size) = state.cache.cache_stats();
    let stats = serde_json::json!({
        "cache_entries": entry_count,
        "cache_size": weighted_size,
        "max_capacity": MAX_CACHE_SIZE,
        "max_ttl": MAX_TTL
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(stats.to_string()))
        .unwrap()
}

async fn clear_all_cache(
    axum::extract::State(state): axum::extract::State<DnsState>,
) -> impl IntoResponse {
    state.cache.clear_all();

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

async fn clear_domain_cache(
    axum::extract::State(state): axum::extract::State<DnsState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let removed_count = state.cache.remove_domain(&domain);

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

async fn dns_query_options() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "content-type, accept")
        .header("access-control-max-age", "86400")
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn doh_metadata() -> impl IntoResponse {
    let metadata = r#"{
        "template": "https://test.a85.kr/dns-query{?dns}",
        "methods": ["GET", "POST"],
        "formats": ["dns-message"]
    }"#;

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "public, max-age=86400")
        .body(axum::body::Body::from(metadata))
        .unwrap()
}

async fn dns_query_get(
    axum::extract::State(state): axum::extract::State<DnsState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, StatusCode> {
    use tracing::error;

    let dns_param = params.get("dns").ok_or(StatusCode::BAD_REQUEST)?;
    let query = decode_dns_query(dns_param)?;

    let answer = get_record(&query, None, state).await.map_err(|e| {
        error!("Error in get_record: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(create_dns_response(answer))
}

async fn dns_query_post(
    axum::extract::State(state): axum::extract::State<DnsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    use tracing::error;

    validate_dns_headers(&headers)?;
    let answer = get_record(&body, None, state).await.map_err(|e| {
        error!("Error in get_record: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(create_dns_response(answer))
}

async fn dns_query_with_upstream_get(
    axum::extract::State(state): axum::extract::State<DnsState>,
    Path(upstream): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, StatusCode> {
    use tracing::error;

    let dns_param = params.get("dns").ok_or(StatusCode::BAD_REQUEST)?;
    let query = decode_dns_query(dns_param)?;

    let answer = get_record(&query, Some(upstream), state)
        .await
        .map_err(|e| {
            error!("Error in get_record: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(create_dns_response(answer))
}

async fn dns_query_with_upstream_post(
    axum::extract::State(state): axum::extract::State<DnsState>,
    Path(upstream): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    use tracing::error;

    validate_dns_headers(&headers)?;
    let answer = get_record(&body, Some(upstream), state)
        .await
        .map_err(|e| {
            error!("Error in get_record: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(create_dns_response(answer))
}

fn decode_dns_query(query_b64: &str) -> Result<Vec<u8>, StatusCode> {
    use tracing::error;

    let mut query_b64 = query_b64.to_string();

    // Convert URL-safe base64 to standard base64
    query_b64 = query_b64.replace('-', "+").replace('_', "/");

    // Deal with padding
    let padding_needed = 4 - (query_b64.len() % 4);
    if padding_needed != 4 {
        query_b64.push_str(&"=".repeat(padding_needed));
    }

    base64::engine::general_purpose::STANDARD
        .decode(&query_b64)
        .map_err(|e| {
            error!("Base64 decode error: {}", e);
            StatusCode::BAD_REQUEST
        })
}

fn validate_dns_headers(headers: &HeaderMap) -> Result<(), StatusCode> {
    let content_type = headers.get("content-type").and_then(|v| v.to_str().ok());

    if content_type != Some("application/dns-message") {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    Ok(())
}

fn create_dns_response(answer: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/dns-message")
        .header("cache-control", "max-age=300")
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "content-type, accept")
        .body(axum::body::Body::from(answer))
        .unwrap()
}
