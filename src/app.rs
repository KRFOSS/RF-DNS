use crate::state::AppState;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get},
};

pub fn create_app_router() -> Router<AppState> {
    Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/cache/stats", get(cache_stats_handler))
        .route("/cache/clear", delete(clear_cache_handler))
        .route("/cache/domain/{domain}", delete(clear_domain_cache_handler))
        .route("/.well-known/doh", get(doh_metadata_handler))
}

// HTTP 핸들러들
async fn root_handler() -> impl IntoResponse {
    axum::response::Redirect::permanent("https://docs.krfoss.org/rokfoss/RF-DNS")
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
