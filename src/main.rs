mod app;
mod cloudflare;
mod dns_utils;
mod cache;

use axum::{
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use base64::Engine;
use std::collections::HashMap;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::info;

pub use app::*;
pub use cloudflare::*;
pub use dns_utils::*;
pub use cache::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let app = create_app();

    let listener = TcpListener::bind("0.0.0.0:30057").await?;
    info!("Server running on http://0.0.0.0:30057");

    axum::serve(listener, app).await?;

    Ok(())
}

fn create_app() -> Router {
    Router::new()
        .route("/", get(root_page))
        .route("/health", get(health))
        .route("/dns-query", get(dns_query_get).post(dns_query_post).options(dns_query_options))
        .route("/dns-query/*upstream", get(dns_query_with_upstream_get).post(dns_query_with_upstream_post).options(dns_query_options))
        .route("/.well-known/doh", get(doh_metadata))
        .layer(CorsLayer::permissive())
}

async fn root_page() -> impl IntoResponse {
    Redirect::permanent("https://krfoss.org")
}

async fn health() -> impl IntoResponse {
    "OK"
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
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, StatusCode> {
    use tracing::error;
    
    let dns_param = params.get("dns").ok_or(StatusCode::BAD_REQUEST)?;
    let query = decode_dns_query(dns_param)?;
    
    let answer = get_record(&query, None).await
        .map_err(|e| {
            error!("Error in get_record: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(create_dns_response(answer))
}

async fn dns_query_post(
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    use tracing::error;
    
    validate_dns_headers(&headers)?;
    let answer = get_record(&body, None).await
        .map_err(|e| {
            error!("Error in get_record: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(create_dns_response(answer))
}

async fn dns_query_with_upstream_get(
    Path(upstream): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, StatusCode> {
    use tracing::error;
    
    let dns_param = params.get("dns").ok_or(StatusCode::BAD_REQUEST)?;
    let query = decode_dns_query(dns_param)?;
    
    let answer = get_record(&query, Some(upstream)).await
        .map_err(|e| {
            error!("Error in get_record: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(create_dns_response(answer))
}

async fn dns_query_with_upstream_post(
    Path(upstream): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    use tracing::error;
    
    validate_dns_headers(&headers)?;
    let answer = get_record(&body, Some(upstream)).await
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
