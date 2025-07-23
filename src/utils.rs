use crate::config::*;
use crate::errors::*;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};
use once_cell::sync::Lazy;

// 전역 HTTP 클라이언트 (메모리 최적화)
static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(4)
        .build()
        .expect("Failed to create HTTP client")
});

/// 최적화된 로깅 설정
pub fn setup_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(LOG_LEVEL));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .init();

    info!("📝 Logging initialized with level: {}", LOG_LEVEL);
}

/// 빠른 도메인 보안 검증
pub fn validate_domain_security(domain: &str) -> DnsResult<()> {
    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(DnsError::InvalidQuery("Domain too long".to_string()));
    }

    // 기본적인 악성 패턴 체크
    if domain.contains("..") || domain.starts_with('.') {
        return Err(DnsError::InvalidQuery("Invalid domain format".to_string()));
    }

    Ok(())
}

/// 간소화된 업스트림 DNS 요청
pub async fn fetch_dns_from_upstream(
    domain: &str,
    record_type: &hickory_proto::rr::RecordType,
    upstream: &str,
) -> DnsResult<Vec<u8>> {
    use hickory_proto::op::{Message, MessageType, Query, OpCode};
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    // DNS 쿼리 생성
    let mut query = Message::new();
    query.set_id(crate::common::generate_query_id());
    query.set_message_type(MessageType::Query);
    query.set_op_code(OpCode::Query);
    query.set_recursion_desired(true);

    let name = Name::from_str(domain)
        .map_err(|e| DnsError::ParseError(format!("Invalid domain: {}", e)))?;
    query.add_query(Query::query(name, *record_type));

    let query_data = query.to_vec()?;

    // 업스트림 URL 정규화
    let upstream_url = if upstream.starts_with("https://") {
        upstream.to_string()
    } else {
        format!("https://{}/dns-query", upstream)
    };

    // HTTP 요청 (재시도 로직 제거하여 단순화)
    let response = HTTP_CLIENT
        .post(&upstream_url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .header("User-Agent", "rfdns/6.0")
        .body(query_data)
        .send()
        .await?;

    if response.status().is_success() {
        let response_data = response.bytes().await?;
        Ok(response_data.to_vec())
    } else {
        Err(DnsError::UpstreamError(format!(
            "Upstream server returned status: {}",
            response.status()
        )))
    }
}

/// 업스트림 프리셋 해결
pub fn resolve_upstream_preset(upstream: &str) -> String {
    UPSTREAM_PRESETS
        .iter()
        .find(|(preset, _)| *preset == upstream)
        .map(|(_, url)| url.to_string())
        .unwrap_or_else(|| upstream.to_string())
}

/// 압축된 도메인 검증 (중복 코드 제거)
#[inline]
pub fn is_valid_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '.'
}

/// 빠른 바이트 검증
#[inline]
pub fn validate_dns_packet_header(data: &[u8]) -> bool {
    data.len() >= 12 && // 최소 DNS 헤더 크기
    (data[2] & 0x80) == 0 // QR 비트가 0 (쿼리)
}

/// CPU 최적화를 위한 빠른 문자열 검색
pub fn fast_domain_match(domain: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|&pattern| {
        if pattern.starts_with('.') {
            domain.ends_with(pattern) || domain == &pattern[1..]
        } else {
            domain.contains(pattern)
        }
    })
}

/// 메모리 효율적인 응답 크기 체크
#[inline]
pub fn should_truncate_udp_response(response_size: usize) -> bool {
    response_size > 512
}

/// 간단한 로드 밸런싱 (라운드 로빈)
pub fn select_upstream_server<'a>(servers: &'a [&'a str], request_count: usize) -> &'a str {
    if servers.is_empty() {
        "1.1.1.1"
    } else {
        servers[request_count % servers.len()]
    }
}

/// 컴팩트한 에러 메시지 생성
pub fn create_compact_error(error_type: &str, message: &str) -> String {
    format!("{}: {}", error_type, message)
}

/// 성능 측정용 간단한 벤치마크
pub struct SimpleBenchmark {
    start: std::time::Instant,
    name: String,
}

impl SimpleBenchmark {
    pub fn start(name: &str) -> Self {
        Self {
            start: std::time::Instant::now(),
            name: name.to_string(),
        }
    }

    pub fn finish(self) {
        let elapsed = self.start.elapsed();
        if elapsed.as_millis() > 100 {
            info!("⏱️ {}: {}ms", self.name, elapsed.as_millis());
        }
    }
}

/// 메모리 사용량 체크 (디버그용)
#[cfg(debug_assertions)]
pub fn log_memory_usage() {
    // 간단한 메모리 사용량 로깅 (procfs 의존성 제거)
    info!("🧠 Memory logging disabled in optimized build");
}

#[cfg(not(debug_assertions))]
pub fn log_memory_usage() {
    // 릴리즈 빌드에서는 메모리 로깅 비활성화
}

/// 최적화된 랜덤 ID 생성
pub fn generate_random_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
