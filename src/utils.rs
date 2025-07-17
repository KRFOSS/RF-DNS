use crate::config::*;
use crate::errors::*;
use crate::state::AppState;
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use once_cell::sync::Lazy;
use reqwest::Client;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

// HTTP 클라이언트 (재사용)
pub static HTTP_CLIENT: Lazy<Arc<Client>> = Lazy::new(|| {
    Arc::new(
        Client::builder()
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(Duration::from_millis(1000))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(50)
            .tcp_keepalive(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client"),
    )
});

// 우회 도메인 목록
pub static BYPASS_DOMAINS_SET: Lazy<HashSet<String>> =
    Lazy::new(|| BYPASS_DOMAINS.iter().map(|s| s.to_string()).collect());

// 우회 도메인 체크
pub fn should_bypass_domain(domain: &str) -> bool {
    BYPASS_DOMAINS_SET.iter().any(|bypass_domain| {
        if bypass_domain.starts_with('.') {
            domain.ends_with(bypass_domain) || domain == &bypass_domain[1..]
        } else {
            domain == bypass_domain
        }
    })
}

// TTL 추출
pub fn extract_ttl_from_response(response: &Message) -> u64 {
    let mut min_ttl = MAX_TTL;

    for record in response.answers() {
        min_ttl = min_ttl.min(record.ttl() as u64);
    }

    for record in response.name_servers() {
        min_ttl = min_ttl.min(record.ttl() as u64);
    }

    // 최소 TTL 보장
    min_ttl.max(60)
}

// 업스트림 DNS 서버로부터 DNS 조회
pub async fn fetch_dns_from_upstream(
    domain: &str,
    record_type: &RecordType,
    upstream: &str,
) -> DnsResult<Vec<u8>> {
    let name = hickory_proto::rr::Name::from_str(domain)?;
    let mut message = Message::new();
    message.add_query(hickory_proto::op::Query::query(name, *record_type));
    message.set_recursion_desired(true);
    message.set_id(rand::random::<u16>());

    let query_data = message.to_vec()?;

    debug!(
        "🌐 Fetching DNS from upstream: {} for domain: {}",
        upstream, domain
    );

    let upstream_url = if upstream.starts_with("https://") || upstream.starts_with("http://") {
        upstream.to_string()
    } else {
        format!("https://{}/dns-query", upstream)
    };

    // 재시도 로직 추가
    let mut last_error = None;
    for attempt in 1..=3 {
        let result = HTTP_CLIENT
            .post(&upstream_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .header("User-Agent", "rfdns/6.0")
            .timeout(Duration::from_secs(10)) // 개별 요청 타임아웃
            .body(query_data.clone())
            .send()
            .await;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    match response.bytes().await {
                        Ok(response_data) => {
                            let response_data = response_data.to_vec();

                            // 응답 검증
                            if response_data.len() >= 12 {
                                debug!(
                                    "✅ Successfully fetched DNS response from upstream: {} ({} bytes) on attempt {}",
                                    upstream,
                                    response_data.len(),
                                    attempt
                                );
                                return Ok(response_data);
                            } else {
                                warn!(
                                    "⚠️ Invalid DNS response from {}: too short ({} bytes)",
                                    upstream,
                                    response_data.len()
                                );
                            }
                        }
                        Err(e) => {
                            warn!("⚠️ Failed to read response body from {}: {}", upstream, e);
                            last_error = Some(DnsError::UpstreamError(e.to_string()));
                        }
                    }
                } else {
                    warn!(
                        "⚠️ HTTP {} from upstream server: {} (attempt {})",
                        response.status(),
                        upstream_url,
                        attempt
                    );
                    last_error = Some(DnsError::UpstreamError(format!(
                        "HTTP {} from upstream server: {}",
                        response.status(),
                        upstream_url
                    )));
                }
            }
            Err(e) => {
                warn!(
                    "⚠️ Request failed to {}: {} (attempt {})",
                    upstream_url, e, attempt
                );
                last_error = Some(DnsError::UpstreamError(e.to_string()));
            }
        }

        // 마지막 시도가 아니면 잠시 대기
        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
        }
    }

    // 모든 시도 실패
    Err(last_error
        .unwrap_or_else(|| DnsError::UpstreamError("All retry attempts failed".to_string())))
}

// Cloudflare IP 체크
pub fn is_cloudflare_ip(ip: &str) -> bool {
    use ipnet::IpNet;
    use std::net::IpAddr;

    // Cloudflare IP 범위들
    static CF_NETWORKS: &[&str] = &[
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "108.162.192.0/18",
        "131.0.72.0/22",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "172.64.0.0/13",
        "173.245.48.0/20",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ];

    match IpAddr::from_str(ip) {
        Ok(addr) => CF_NETWORKS.iter().any(|network| {
            if let Ok(net) = IpNet::from_str(network) {
                net.contains(&addr)
            } else {
                false
            }
        }),
        Err(_) => false,
    }
}

// Cloudflare 패치 필요 여부 체크
pub fn should_patch_cloudflare(domain: &str, record_type: &RecordType) -> bool {
    // A 또는 AAAA 레코드만 패치 대상
    matches!(record_type, RecordType::A | RecordType::AAAA) &&
    // 우회 도메인이 아닌 경우에만 패치
    !should_bypass_domain(domain)
}

// Cloudflare 응답 패치
pub async fn patch_cloudflare_response(
    response: &mut Message,
    domain: &str,
    record_type: &RecordType,
    app_state: &AppState,
) -> DnsResult<()> {
    // 응답에서 첫 번째 IP 추출
    let first_ip = response
        .answers()
        .iter()
        .find_map(|answer| match answer.data() {
            RData::A(ip) => Some(ip.to_string()),
            RData::AAAA(ip) => Some(ip.to_string()),
            _ => None,
        });

    if let Some(ip) = first_ip {
        if is_cloudflare_ip(&ip) {
            debug!("🔧 Detected Cloudflare IP: {}, patching to alternative", ip);

            // 대체 도메인 목록 (kali.download 외 추가 옵션)
            let fallback_domains = ["kali.download", "httpbin.org", "example.com"];

            for fallback_domain in fallback_domains {
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    app_state
                        .resolver
                        .resolve_domain(fallback_domain, *record_type),
                )
                .await
                {
                    Ok(Ok(fallback_response)) => {
                        // 응답 메시지 재구성
                        let mut new_response = Message::new();
                        new_response.set_id(response.id());
                        new_response.set_message_type(response.message_type());
                        new_response.set_op_code(response.op_code());
                        new_response.set_authoritative(response.authoritative());
                        new_response.set_truncated(response.truncated());
                        new_response.set_recursion_desired(response.recursion_desired());
                        new_response.set_recursion_available(response.recursion_available());
                        new_response.set_response_code(response.response_code());
                        new_response.add_queries(response.queries().to_vec());

                        // 대체 도메인 응답의 레코드들을 원본 도메인으로 변경
                        let original_domain = hickory_proto::rr::Name::from_str(domain)?;
                        let new_answers: Vec<_> = fallback_response
                            .answers()
                            .iter()
                            .filter_map(|answer| {
                                // IP 주소 레코드만 필터링
                                match answer.data() {
                                    RData::A(_) | RData::AAAA(_) => {
                                        let mut new_record = answer.clone();
                                        new_record.set_name(original_domain.clone());
                                        new_record.set_ttl(std::cmp::max(answer.ttl(), 300)); // 최소 5분 TTL
                                        Some(new_record)
                                    }
                                    _ => None,
                                }
                            })
                            .collect();

                        if !new_answers.is_empty() {
                            new_response.add_answers(new_answers);
                            *response = new_response;

                            debug!(
                                "✅ Successfully patched Cloudflare response for domain: {} using {}",
                                domain, fallback_domain
                            );
                            return Ok(());
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("⚠️ Failed to fetch {} for patching: {}", fallback_domain, e);
                        continue;
                    }
                    Err(_) => {
                        warn!("⚠️ Timeout while fetching {} for patching", fallback_domain);
                        continue;
                    }
                }
            }

            // 모든 대체 도메인이 실패한 경우 원본 응답 유지
            warn!(
                "⚠️ All fallback domains failed for Cloudflare patching, keeping original response"
            );
        }
    }

    Ok(())
}

// 로그 레벨 설정
pub fn setup_logging() {
    use tracing_subscriber::prelude::*;

    let log_level = match LOG_LEVEL {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_level(true)
                .with_ansi(true),
        )
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            log_level,
        ))
        .init();

    tracing::info!("📝 Logging initialized with level: {}", LOG_LEVEL);
}
