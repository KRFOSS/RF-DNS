use crate::cache::DnsCache;
use crate::config::*;
use crate::errors::*;
use crate::metrics::{Metrics, Protocol, ResponseTimer};
use crate::resolver::RecursiveDnsResolver;
use crate::utils::*;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<DnsCache>,
    pub resolver: Arc<RecursiveDnsResolver>,
    pub metrics: Arc<Metrics>,
}

impl AppState {
    pub fn new() -> DnsResult<Self> {
        let cache = Arc::new(DnsCache::new());
        let resolver = Arc::new(RecursiveDnsResolver::new()?);
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

        let message = Message::from_vec(query)?;
        let query_info = self.extract_query_info(&message)?;

        debug!(
            "📥 Processing DNS query: domain={}, type={:?}, protocol={:?}",
            query_info.domain, query_info.record_type, protocol
        );

        let timer = ResponseTimer::new(query_info.domain.clone(), self.metrics.clone());

        // 캐시 확인
        if let Some(cached_response) =
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
                self.cache.store(
                    &query_info.domain,
                    &query_info.record_type,
                    response_bytes.clone(),
                    ttl,
                );

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
            ROOT_DNS_SERVERS[0], // 기본 업스트림 서버
        )
        .await;

        match upstream_response {
            Ok(response_data) => {
                let mut response = Message::from_vec(&response_data)?;
                response.set_id(query_id);

                // 캐시 저장
                let ttl = extract_ttl_from_response(&response);
                self.cache.store(
                    &query_info.domain,
                    &query_info.record_type,
                    response_data.clone(),
                    ttl,
                );

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
        let query = message
            .queries()
            .first()
            .ok_or_else(|| DnsError::InvalidQuery("No query found in message".to_string()))?;

        let domain = query.name().to_string().trim_end_matches('.').to_string();
        let record_type = query.query_type();

        Ok(QueryInfo {
            domain,
            record_type,
        })
    }

    pub fn get_cache_stats(&self) -> serde_json::Value {
        self.cache.cache_info()
    }

    pub fn get_resolver_stats(&self) -> serde_json::Value {
        let stats = self.resolver.get_stats();
        serde_json::json!(stats)
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
                "dot": self.metrics.dot_requests.load(std::sync::atomic::Ordering::Relaxed),
                "doq": self.metrics.doq_requests.load(std::sync::atomic::Ordering::Relaxed)
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
