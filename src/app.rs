use crate::state::AppState;
use crate::utils;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};

/// RF-DNS 애플리케이션의 주요 라우터를 생성합니다.
/// 
/// 이 함수는 모든 HTTP 엔드포인트를 설정하고 각각의 핸들러 함수와 연결합니다.
/// 포함된 엔드포인트:
/// - `/`: 루트 페이지 (문서로 리다이렉트)
/// - `/health`: 서비스 상태 확인
/// - `/metrics`: 시스템 메트릭 조회
/// - `/cache/*`: 캐시 관리 API
/// - `/update/cloudflare`: Cloudflare IP 범위 업데이트
/// - `/info/cloudflare`: Cloudflare 정보 조회
/// - `/.well-known/doh`: DNS over HTTPS 메타데이터
/// 
/// # Returns
/// `Router<AppState>` - 설정된 라우터 인스턴스
pub fn create_app_router() -> Router<AppState> {
    Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/cache/stats", get(cache_stats_handler))
        .route("/cache/clear", delete(clear_cache_handler))
        .route("/cache/domain/{domain}", delete(clear_domain_cache_handler))
        .route("/update/cloudflare", post(update_cloudflare_handler))
        .route("/info/cloudflare", get(cloudflare_info_handler))
        .route("/.well-known/doh", get(doh_metadata_handler))
}

// HTTP 핸들러들

/// 루트 경로 핸들러 (`/`)
/// 
/// 사용자가 루트 URL에 접근할 때 RF-DNS 문서 페이지로 영구 리다이렉트합니다.
/// 
/// # Returns
/// `Redirect` - 문서 페이지로의 영구 리다이렉트 응답
async fn root_handler() -> impl IntoResponse {
    axum::response::Redirect::permanent("https://docs.krfoss.org/rokfoss/RF-DNS")
}

/// 헬스 체크 핸들러 (`/health`)
/// 
/// 서비스의 기본적인 상태를 확인하는 간단한 엔드포인트입니다.
/// 로드 밸런서나 모니터링 시스템에서 서비스 가용성을 확인하는 데 사용됩니다.
/// 
/// # Returns
/// `&'static str` - "OK" 문자열 응답
async fn health_handler() -> impl IntoResponse {
    "OK"
}

/// 메트릭 조회 핸들러 (`/metrics`)
/// 
/// 시스템의 성능 지표와 통계 정보를 JSON 형태로 반환합니다.
/// DNS 쿼리 수, 응답 시간, 캐시 히트율 등의 정보를 제공합니다.
/// 
/// # Arguments
/// * `State(state)` - 애플리케이션 상태 객체
/// 
/// # Returns
/// `Response` - JSON 형태의 메트릭 데이터
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = state.get_metrics();

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(metrics.to_string()))
        .unwrap()
}

/// 캐시 통계 조회 핸들러 (`/cache/stats`)
/// 
/// DNS 캐시의 현재 상태와 통계 정보를 JSON 형태로 반환합니다.
/// 캐시된 항목 수, 캐시 크기, 히트율 등의 정보를 제공합니다.
/// 
/// # Arguments
/// * `State(state)` - 애플리케이션 상태 객체
/// 
/// # Returns
/// `Response` - JSON 형태의 캐시 통계 데이터
async fn cache_stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.get_cache_stats();

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(stats.to_string()))
        .unwrap()
}

/// 전체 캐시 삭제 핸들러 (`/cache/clear`)
/// 
/// DNS 캐시의 모든 항목을 삭제합니다.
/// 캐시 문제를 해결하거나 강제로 새로운 DNS 조회를 수행해야 할 때 사용됩니다.
/// 
/// # Arguments
/// * `State(state)` - 애플리케이션 상태 객체
/// 
/// # Returns
/// `Response` - 작업 결과를 포함한 JSON 응답
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

/// 특정 도메인 캐시 삭제 핸들러 (`/cache/domain/{domain}`)
/// 
/// 지정된 도메인과 관련된 DNS 캐시 항목만 선택적으로 삭제합니다.
/// 특정 도메인의 DNS 정보가 변경되었을 때 해당 도메인의 캐시만 갱신하고 싶을 때 사용됩니다.
/// 
/// # Arguments
/// * `State(state)` - 애플리케이션 상태 객체
/// * `Path(domain)` - 캐시에서 삭제할 도메인 이름
/// 
/// # Returns
/// `Response` - 삭제된 항목 수와 작업 결과를 포함한 JSON 응답
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

/// Cloudflare IP 범위 업데이트 핸들러 (`/update/cloudflare`)
/// 
/// Cloudflare의 최신 IP 범위 목록을 수동으로 갱신합니다.
/// Cloudflare IP 범위는 보안상 중요한 정보로, 정기적으로 업데이트되어야 합니다.
/// 이 엔드포인트를 통해 수동으로 즉시 업데이트를 트리거할 수 있습니다.
/// 
/// # Returns
/// `Response` - 업데이트 결과와 새로운 IP 범위 개수를 포함한 JSON 응답
/// 
/// # Errors
/// 네트워크 오류나 Cloudflare API 문제 시 500 상태 코드와 에러 메시지를 반환합니다.
async fn update_cloudflare_handler() -> impl IntoResponse {
    use tracing::{error, info};

    info!("🔄 Manual Cloudflare IP ranges update requested via API");

    match utils::force_update_cloudflare_networks(3).await {
        Ok(()) => {
            let (count, _) = utils::get_cloudflare_networks_info().await;
            let response = serde_json::json!({
                "status": "success",
                "message": "Cloudflare IP ranges updated successfully",
                "total_ranges": count,
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });

            info!("✅ Manual Cloudflare IP ranges update completed successfully");

            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(response.to_string()))
                .unwrap()
        }
        Err(e) => {
            error!("❌ Manual Cloudflare IP ranges update failed: {}", e);

            let response = serde_json::json!({
                "status": "error",
                "message": format!("Failed to update Cloudflare IP ranges: {}", e),
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            });

            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(response.to_string()))
                .unwrap()
        }
    }
}

/// Cloudflare 정보 조회 핸들러 (`/info/cloudflare`)
/// 
/// 현재 로드된 Cloudflare IP 범위에 대한 정보를 반환합니다.
/// 총 IP 범위 개수, 마지막 업데이트 시간, 캐시 상태 등을 조회할 수 있습니다.
/// 시스템 상태 모니터링이나 디버깅 목적으로 사용됩니다.
/// 
/// # Returns
/// `Response` - Cloudflare IP 범위 정보와 관련 엔드포인트 목록을 포함한 JSON 응답
async fn cloudflare_info_handler() -> impl IntoResponse {
    let (count, last_update) = utils::get_cloudflare_networks_info().await;

    let last_update_timestamp = last_update
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs());

    let response = serde_json::json!({
        "status": "success",
        "cloudflare_ranges": {
            "total_count": count,
            "last_update_timestamp": last_update_timestamp,
            "cache_status": if count > 0 { "loaded" } else { "empty" }
        },
        "endpoints": {
            "update": "/update/cloudflare (POST)",
            "info": "/info/cloudflare (GET)"
        },
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(response.to_string()))
        .unwrap()
}

/// DNS over HTTPS 메타데이터 핸들러 (`/.well-known/doh`)
/// 
/// RFC 8484에 정의된 DNS over HTTPS (DoH) 서비스의 메타데이터를 제공합니다.
/// 클라이언트가 DoH 서비스를 자동으로 발견하고 설정할 수 있도록 돕습니다.
/// 템플릿 URL, 지원하는 HTTP 메서드, 데이터 형식 등의 정보를 포함합니다.
/// 
/// # Returns
/// `Response` - DoH 서비스 메타데이터를 포함한 JSON 응답 (24시간 캐시 설정)
/// 
/// # Note
/// 이 엔드포인트는 RFC 8484 표준을 따르며, DoH 클라이언트의 자동 설정을 지원합니다.
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
