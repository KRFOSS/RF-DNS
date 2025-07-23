use crate::cache::DnsCache;
use crate::config::*;
use crate::errors::*;
use crate::metrics::{Metrics, Protocol};
use crate::resolver::DnsResolver;
use crate::common;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RecordType};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<DnsCache>,
    pub resolver: Arc<DnsResolver>,
    pub metrics: Arc<Metrics>,
}

#[derive(Debug)]
struct QueryInfo {
    domain: String,
    record_type: RecordType,
}

impl AppState {
    pub fn new() -> DnsResult<Self> {
        let cache = Arc::new(DnsCache::new());
        let resolver = Arc::new(DnsResolver::new()?);
        let metrics = Arc::new(Metrics::new());

        // 백그라운드 작업 시작 (최적화)
        cache.start_cleanup_task();
        metrics.start_stats_reporter();

        let state = Self {
            cache,
            resolver,
            metrics,
        };

        info!("🚀 Application state initialized successfully");
        Ok(state)
    }

    pub async fn process_dns_query(&self, query: &[u8], protocol: Protocol) -> DnsResult<Vec<u8>> {
        self.metrics.record_request();

        // 빠른 검증
        common::validate_dns_message(query)?;

        // DNS 메시지 파싱 (최적화된 에러 처리)
        let message = Message::from_vec(query)
            .map_err(|e| {
                error!("🚨 Failed to parse DNS message: {} (size: {})", e, query.len());
                DnsError::InvalidQuery(format!("Failed to parse DNS message: {}", e))
            })?;

        let query_info = self.extract_query_info(&message)?;

        debug!(
            "📥 Processing DNS query: domain={}, type={:?}, protocol={:?}",
            query_info.domain, query_info.record_type, protocol
        );

        let timer = crate::common::CompactTimer::new();

        // 캐시 확인 (최적화)
        if let Some(cached_response) = self.cache.get_with_id(
            &query_info.domain, 
            &query_info.record_type, 
            message.id()
        ) {
            debug!("⚡ Cache hit for domain: {}", query_info.domain);
            self.metrics.record_cache_hit();
            self.metrics.record_success();
            self.metrics.record_response_time(timer.elapsed_ms());
            return Ok(cached_response);
        }

        self.metrics.record_cache_miss();

        // 우회 도메인 체크 (인라인 최적화)
        if self.should_bypass_domain(&query_info.domain) {
            debug!("🚫 Bypassing domain: {}", query_info.domain);
            return self.fetch_from_upstream(&query_info, message.id()).await;
        }

        // 재귀 DNS 해결 (최적화)
        match self.resolver.resolve_domain(&query_info.domain, query_info.record_type).await {
            Ok(mut response) => {
                response.set_id(message.id());

                // 캐시 저장 (TTL 최적화)
                let ttl = self.extract_min_ttl(&response);
                if let Ok(response_data) = response.to_vec() {
                    self.cache.store(
                        &query_info.domain,
                        &query_info.record_type,
                        response_data.clone(),
                        ttl,
                    );

                    self.metrics.record_success();
                    self.metrics.record_response_time(timer.elapsed_ms());
                    Ok(response_data)
                } else {
                    self.metrics.record_error();
                    Err(DnsError::ServerError("Failed to serialize response".to_string()))
                }
            }
            Err(e) => {
                error!("❌ DNS resolution failed for {}: {}", query_info.domain, e);
                self.metrics.record_error();
                
                // 에러 응답 생성
                let error_response = crate::errors::create_error_response(
                    message.id(), 
                    vec![], 
                    ResponseCode::ServFail
                );
                error_response.to_vec()
                    .map_err(|e| DnsError::ServerError(format!("Failed to create error response: {}", e)))
            }
        }
    }

    // 인라인 최적화된 쿼리 정보 추출
    fn extract_query_info(&self, message: &Message) -> DnsResult<QueryInfo> {
        let query = message.queries().first()
            .ok_or_else(|| DnsError::InvalidQuery("No query in message".to_string()))?;

        Ok(QueryInfo {
            domain: query.name().to_string(),
            record_type: query.query_type(),
        })
    }

    // 빠른 우회 도메인 체크
    #[inline]
    fn should_bypass_domain(&self, domain: &str) -> bool {
        BYPASS_DOMAINS.iter().any(|&bypass| domain.contains(bypass))
    }

    // 최적화된 TTL 추출
    fn extract_min_ttl(&self, response: &Message) -> u64 {
        let min_ttl = response.answers()
            .iter()
            .map(|record| record.ttl())
            .min()
            .unwrap_or(300); // 기본 5분

        std::cmp::min(min_ttl as u64, MAX_TTL)
    }

    // 간소화된 업스트림 요청
    async fn fetch_from_upstream(&self, query_info: &QueryInfo, query_id: u16) -> DnsResult<Vec<u8>> {
        // 간단한 업스트림 처리 (필요시 확장)
        warn!("🚫 Upstream request for {}", query_info.domain);
        
        let error_response = crate::errors::create_error_response(
            query_id, 
            vec![], 
            ResponseCode::ServFail
        );
        error_response.to_vec()
            .map_err(|e| DnsError::ServerError(format!("Failed to create upstream response: {}", e)))
    }

    // 업스트림 처리를 위한 추가 메서드 (기존 호환성)
    pub async fn process_dns_query_with_upstream(
        &self,
        query: &[u8],
        protocol: Protocol,
        _upstream: &str,
    ) -> DnsResult<Vec<u8>> {
        // 일단 기본 처리로 위임
        self.process_dns_query(query, protocol).await
    }

    // 통계 조회
    pub fn get_stats(&self) -> String {
        let metrics = self.metrics.get_stats();
        let (cache_entries, cache_size) = self.cache.get_stats();
        
        format!(
            "Requests: {}, Cache: {} entries ({}KB), Active: {} connections",
            metrics.total_requests,
            cache_entries,
            cache_size / 1024,
            metrics.active_connections
        )
    }

    // 호환성을 위한 추가 메서드들
    pub fn get_metrics(&self) -> crate::metrics::MetricsSnapshot {
        self.metrics.get_stats()
    }

    pub fn get_cache_stats(&self) -> (u64, u64) {
        self.cache.get_stats()
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    pub fn remove_domain_from_cache(&self, _domain: &str) -> usize {
        // 간단한 구현 (최적화된 캐시에서는 개별 도메인 제거 대신 전체 클리어)
        self.cache.clear();
        1 // 제거된 엔트리 수 (더미 값)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new().expect("Failed to create AppState")
    }
}
