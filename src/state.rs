use crate::cache::DnsCache;
// use crate::config; // use via module path
use crate::errors::*;
use crate::metrics::{Metrics, Protocol, ResponseTimer};
use crate::resolver::DnsResolver;
use crate::utils::*;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<DnsCache>,
    pub resolver: Arc<DnsResolver>,
    pub metrics: Arc<Metrics>,
}

impl AppState {
    pub fn new() -> DnsResult<Self> {
        let cache = Arc::new(DnsCache::new());
        let resolver = Arc::new(DnsResolver::new()?);
        let metrics = Arc::new(Metrics::new());

        // 백그라운드 작업 시작
        cache.start_cleanup_task();
        metrics.start_periodic_logging();

        let state = Self {
            cache,
            resolver,
            metrics,
        };

        info!("🚀 Application state initialized successfully");
        Ok(state)
    }

    pub async fn process_dns_query(&self, query: &[u8], protocol: Protocol) -> DnsResult<Vec<u8>> {
        self.metrics.record_request(protocol);

        // DNS 메시지 파싱 시 더 자세한 오류 정보 제공
        let message = match Message::from_vec(query) {
            Ok(msg) => msg,
            Err(e) => {
                error!(
                    "🚨 Failed to parse DNS message: {} (size: {} bytes)",
                    e,
                    query.len()
                );
                if query.len() >= 12 {
                    // 최소 DNS 헤더 크기가 있으면 헥스 덤프 출력
                    let hex_dump: String = query[..std::cmp::min(query.len(), 32)]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    debug!("🔍 DNS message hex dump (first 32 bytes): {}", hex_dump);
                }
                return Err(DnsError::InvalidQuery(format!(
                    "Failed to parse DNS message: {}",
                    e
                )));
            }
        };

        let query_info = self.extract_query_info(&message)?;

        debug!(
            "📥 Processing DNS query: domain={}, type={:?}, protocol={:?}",
            query_info.domain, query_info.record_type, protocol
        );

        let timer = ResponseTimer::new(query_info.domain.clone(), self.metrics.clone());

        // 캐시 확인
        if let Ok(Some(cached_response)) =
            self.cache
                .get_with_id(&query_info.domain, &query_info.record_type, message.id())
        {
            debug!("⚡ Cache hit for domain: {}", query_info.domain);
            self.metrics.record_cache_hit();
            self.metrics.record_success();
            timer.finish().await;
            return Ok(cached_response);
        }

        self.metrics.record_cache_miss();

        // 우회 도메인 체크
        if should_bypass_domain(&query_info.domain) {
            debug!("🚫 Bypassing domain: {}", query_info.domain);
            return self.fetch_from_upstream(&query_info, message.id()).await;
        }

        // 재귀 DNS 해결
        match self
            .resolver
            .resolve_domain(&query_info.domain, query_info.record_type)
            .await
        {
            Ok(mut response) => {
                response.set_id(message.id());

                // 응답 후처리 (필요시 패치)
                if let Err(e) = self.apply_response_patches(&mut response).await {
                    warn!("⚠️ Failed to apply response patches: {}", e);
                }

                // 캐시 저장
                let response_bytes = response.to_vec()?;
                let ttl = extract_ttl_from_response(&response);
                self.cache
                    .store(
                        &query_info.domain,
                        &query_info.record_type,
                        response_bytes.clone(),
                        ttl,
                    )
                    .await;

                self.metrics.record_success();
                timer.finish().await;
                Ok(response_bytes)
            }
            Err(e) => {
                error!("❌ Failed to resolve domain {}: {}", query_info.domain, e);
                self.metrics.record_failure();

                // 업스트림 fallback
                self.fetch_from_upstream(&query_info, message.id()).await
            }
        }
    }

    pub async fn process_dns_query_with_upstream(
        &self,
        query: &[u8],
        protocol: Protocol,
        upstream: &str,
    ) -> DnsResult<Vec<u8>> {
        self.metrics.record_request(protocol);

        // DNS 메시지 파싱 시 더 자세한 오류 정보 제공
        let message = match Message::from_vec(query) {
            Ok(msg) => msg,
            Err(e) => {
                error!(
                    "🚨 Failed to parse DNS message for upstream {}: {} (size: {} bytes)",
                    upstream,
                    e,
                    query.len()
                );
                if query.len() >= 12 {
                    // 최소 DNS 헤더 크기가 있으면 헥스 덤프 출력
                    let hex_dump: String = query[..std::cmp::min(query.len(), 32)]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    debug!("🔍 DNS message hex dump (first 32 bytes): {}", hex_dump);
                }
                return Err(DnsError::InvalidQuery(format!(
                    "Failed to parse DNS message: {}",
                    e
                )));
            }
        };

        let query_info = self.extract_query_info(&message)?;

        debug!(
            "📥 Processing DNS query with upstream: domain={}, type={:?}, protocol={:?}, upstream={}",
            query_info.domain, query_info.record_type, protocol, upstream
        );

        let timer = ResponseTimer::new(query_info.domain.clone(), self.metrics.clone());

        // 업스트림을 통한 DNS 쿼리 처리
        match self
            .fetch_from_specific_upstream(&query_info, message.id(), upstream)
            .await
        {
            Ok(response_data) => {
                self.metrics.record_success();
                timer.finish().await;
                Ok(response_data)
            }
            Err(e) => {
                error!(
                    "❌ Failed to resolve domain {} via upstream {}: {}",
                    query_info.domain, upstream, e
                );
                self.metrics.record_failure();

                // 업스트림 실패 시 기본 처리로 폴백
                self.process_dns_query(query, protocol).await
            }
        }
    }

    async fn fetch_from_upstream(
        &self,
        query_info: &QueryInfo,
        query_id: u16,
    ) -> DnsResult<Vec<u8>> {
        debug!(
            "🔄 Fetching from upstream for domain: {}",
            query_info.domain
        );
        self.metrics.record_upstream_request();

        let upstream_response = fetch_dns_from_upstream(
            &query_info.domain,
            &query_info.record_type,
            crate::config::get()
                .root_dns_servers
                .get(0)
                .map(|s| s.as_str())
                .unwrap_or("1.1.1.1"), // 기본 업스트림 서버
        )
        .await;

        match upstream_response {
            Ok(response_data) => {
                let mut response = Message::from_vec(&response_data)?;
                response.set_id(query_id);

                // 캐시 저장
                let ttl = extract_ttl_from_response(&response);
                self.cache
                    .store(
                        &query_info.domain,
                        &query_info.record_type,
                        response_data.clone(),
                        ttl,
                    )
                    .await;

                self.metrics.record_success();
                Ok(response.to_vec()?)
            }
            Err(e) => {
                error!(
                    "❌ Upstream request failed for domain {}: {}",
                    query_info.domain, e
                );
                self.metrics.record_upstream_failure();
                self.metrics.record_failure();

                // 에러 응답 생성
                let error_response = crate::errors::create_error_response(
                    query_id,
                    vec![hickory_proto::op::Query::query(
                        Name::from_str(&query_info.domain).unwrap(),
                        query_info.record_type,
                    )],
                    ResponseCode::ServFail,
                );

                Ok(error_response.to_vec()?)
            }
        }
    }

    async fn fetch_from_specific_upstream(
        &self,
        query_info: &QueryInfo,
        query_id: u16,
        upstream: &str,
    ) -> DnsResult<Vec<u8>> {
        debug!(
            "🔄 Fetching from specific upstream {} for domain: {}",
            upstream, query_info.domain
        );
        self.metrics.record_upstream_request();

        // 업스트림 서버 변환 및 검증
        let upstream_server = self.resolve_upstream_name(upstream)?;

        let upstream_response = fetch_dns_from_upstream(
            &query_info.domain,
            &query_info.record_type,
            &upstream_server,
        )
        .await;

        match upstream_response {
            Ok(response_data) => {
                let mut response = Message::from_vec(&response_data)?;
                response.set_id(query_id);

                // 캐시 저장
                let ttl = extract_ttl_from_response(&response);
                self.cache
                    .store(
                        &query_info.domain,
                        &query_info.record_type,
                        response_data.clone(),
                        ttl,
                    )
                    .await;

                debug!("✅ Successfully fetched from upstream {}", upstream);
                self.metrics.record_success();
                Ok(response.to_vec()?)
            }
            Err(e) => {
                error!(
                    "❌ Specific upstream request failed for domain {} via {}: {}",
                    query_info.domain, upstream, e
                );
                self.metrics.record_upstream_failure();
                self.metrics.record_failure();

                // 에러 응답 생성
                let error_response = crate::errors::create_error_response(
                    query_id,
                    vec![hickory_proto::op::Query::query(
                        Name::from_str(&query_info.domain).unwrap(),
                        query_info.record_type,
                    )],
                    ResponseCode::ServFail,
                );

                Ok(error_response.to_vec()?)
            }
        }
    }

    fn resolve_upstream_name(&self, upstream: &str) -> DnsResult<String> {
        let upstream_lower = upstream.to_lowercase();

        // 프리셋에서 검색
        for preset in &crate::config::get().upstream_presets {
            if upstream_lower == preset.name {
                return Ok(preset.ip.clone());
            }
        }

        // IP 주소나 URL 형태인지 확인
        if upstream.parse::<std::net::IpAddr>().is_ok()
            || upstream.starts_with("https://")
            || upstream.starts_with("http://")
        {
            Ok(upstream.to_string())
        } else {
            let preset_names: Vec<String> = crate::config::get()
                .upstream_presets
                .iter()
                .map(|p| p.name.clone())
                .collect();
            Err(DnsError::ConfigurationError(format!(
                "Unknown upstream server: {}. Available options: {}, or IP address/URL",
                upstream,
                preset_names.join(", ")
            )))
        }
    }

    async fn apply_response_patches(&self, response: &mut Message) -> DnsResult<()> {
        // Cloudflare IP 패치 로직 (필요시)
        if let Some(query) = response.queries().first() {
            let domain = query.name().to_string();
            let record_type = query.query_type();

            if should_patch_cloudflare(&domain, &record_type) {
                debug!("🔧 Applying Cloudflare patch for domain: {}", domain);
                patch_cloudflare_response(response, &domain, &record_type, self).await?;
            }
        }

        Ok(())
    }

    fn extract_query_info(&self, message: &Message) -> DnsResult<QueryInfo> {
        // DNS 메시지 기본 검증
        if message.queries().is_empty() {
            error!("🚨 DNS message contains no queries");
            return Err(DnsError::InvalidQuery(
                "No queries in DNS message".to_string(),
            ));
        }

        let query = message
            .queries()
            .first()
            .ok_or_else(|| DnsError::InvalidQuery("No query found in message".to_string()))?;

        let raw_domain = query.name().to_string();
        debug!("📝 Raw domain from query: '{}'", raw_domain);

        let domain = raw_domain.trim_end_matches('.').to_string();
        let record_type = query.query_type();

        debug!(
            "📝 Processed domain: '{}', record_type: {:?}",
            domain, record_type
        );

        // 루트 도메인 (.) 처리
        if domain.is_empty() && raw_domain == "." {
            return Ok(QueryInfo {
                domain: ".".to_string(),
                record_type,
            });
        }

        // 빈 도메인 체크
        if domain.is_empty() {
            error!(
                "🚨 Empty domain name after processing. Raw: '{}', Processed: '{}'",
                raw_domain, domain
            );
            return Err(DnsError::InvalidQuery(format!(
                "Empty domain name (raw: '{}', processed: '{}')",
                raw_domain, domain
            )));
        }

        // 도메인 보안 검증
        crate::utils::validate_domain_security(&domain)?;

        Ok(QueryInfo {
            domain,
            record_type,
        })
    }

    pub fn get_cache_stats(&self) -> serde_json::Value {
        self.cache.cache_info()
    }

    pub fn get_metrics(&self) -> serde_json::Value {
        serde_json::json!({
            "total_requests": self.metrics.total_requests.load(std::sync::atomic::Ordering::Relaxed),
            "successful_requests": self.metrics.successful_requests.load(std::sync::atomic::Ordering::Relaxed),
            "failed_requests": self.metrics.failed_requests.load(std::sync::atomic::Ordering::Relaxed),
            "cache_hits": self.metrics.cache_hits.load(std::sync::atomic::Ordering::Relaxed),
            "cache_misses": self.metrics.cache_misses.load(std::sync::atomic::Ordering::Relaxed),
            "upstream_requests": self.metrics.upstream_requests.load(std::sync::atomic::Ordering::Relaxed),
            "upstream_failures": self.metrics.upstream_failures.load(std::sync::atomic::Ordering::Relaxed),
            "active_connections": self.metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed),
            "cache_hit_rate": self.metrics.get_cache_hit_rate(),
            "success_rate": self.metrics.get_success_rate(),
            "avg_response_time": self.metrics.avg_response_time.load(std::sync::atomic::Ordering::Relaxed),
            "protocols": {
                "udp": self.metrics.udp_requests.load(std::sync::atomic::Ordering::Relaxed),
                "tcp": self.metrics.tcp_requests.load(std::sync::atomic::Ordering::Relaxed),
                "doh": self.metrics.doh_requests.load(std::sync::atomic::Ordering::Relaxed),
                "dot": self.metrics.dot_requests.load(std::sync::atomic::Ordering::Relaxed)
            }
        })
    }

    pub fn clear_cache(&self) {
        self.cache.clear_all();
    }

    pub fn remove_domain_from_cache(&self, domain: &str) -> u64 {
        self.cache.remove_domain(domain)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new().expect("Failed to create application state")
    }
}

#[derive(Debug, Clone)]
struct QueryInfo {
    domain: String,
    record_type: RecordType,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("cache", &self.cache)
            .field("resolver", &self.resolver)
            .finish()
    }
}
