use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tracing::info;

// 압축된 메트릭 구조체 (메모리 최적화)
#[derive(Clone)]
pub struct Metrics {
    // 핵심 통계만 유지 (메모리 절약)
    requests: Arc<AtomicU64>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    active_connections: Arc<AtomicUsize>,
    
    // 응답 시간 (간단한 이동 평균)
    avg_response_time: Arc<AtomicU64>,
    response_count: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    UDP,
    TCP,
    DoH,
    DoT,
    DoQ,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            avg_response_time: Arc::new(AtomicU64::new(0)),
            response_count: Arc::new(AtomicU64::new(0)),
        }
    }

    // 인라인 최적화된 메트릭 업데이트 함수들
    #[inline]
    pub fn record_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_success(&self) {
        // 성공은 별도 카운터 없이 계산으로 처리 (메모리 절약)
    }

    #[inline]
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_connection(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn remove_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    // 빠른 응답 시간 업데이트 (이동 평균)
    pub fn record_response_time(&self, elapsed_ms: u64) {
        let count = self.response_count.fetch_add(1, Ordering::Relaxed);
        let current_avg = self.avg_response_time.load(Ordering::Relaxed);
        
        // 간단한 이동 평균 계산
        let new_avg = if count == 0 {
            elapsed_ms
        } else {
            (current_avg * count + elapsed_ms) / (count + 1)
        };
        
        self.avg_response_time.store(new_avg, Ordering::Relaxed);
    }

    // 통계 조회 (최소한의 오버헤드)
    pub fn get_stats(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_requests: self.requests.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            avg_response_time: self.avg_response_time.load(Ordering::Relaxed),
        }
    }

    // 주기적 통계 출력
    pub fn start_stats_reporter(&self) {
        let metrics = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(crate::config::STATS_INTERVAL);
            loop {
                interval.tick().await;
                let stats = metrics.get_stats();
                
                let cache_ratio = if stats.cache_hits + stats.cache_misses > 0 {
                    (stats.cache_hits as f64 / (stats.cache_hits + stats.cache_misses) as f64) * 100.0
                } else {
                    0.0
                };
                
                let success_ratio = if stats.total_requests > 0 {
                    ((stats.total_requests - stats.errors) as f64 / stats.total_requests as f64) * 100.0
                } else {
                    0.0
                };
                
                info!(
                    "📊 Stats: {} reqs, {:.1}% cache hit, {:.1}% success, {}ms avg, {} active conns",
                    stats.total_requests,
                    cache_ratio,
                    success_ratio,
                    stats.avg_response_time,
                    stats.active_connections
                );
            }
        });
    }
}

#[derive(Debug)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub errors: u64,
    pub active_connections: usize,
    pub avg_response_time: u64,
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cache_ratio = if self.cache_hits + self.cache_misses > 0 {
            (self.cache_hits as f64 / (self.cache_hits + self.cache_misses) as f64) * 100.0
        } else {
            0.0
        };
        
        let success_ratio = if self.total_requests > 0 {
            ((self.total_requests - self.errors) as f64 / self.total_requests as f64) * 100.0
        } else {
            0.0
        };
        
        write!(
            f,
            "Requests: {}, Cache Hit: {:.1}%, Success: {:.1}%, Avg Response: {}ms, Active: {}",
            self.total_requests,
            cache_ratio,
            success_ratio,
            self.avg_response_time,
            self.active_connections
        )
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

// 컴팩트한 응답 타이머
pub struct ResponseTimer {
    start: Instant,
    domain: String,
    metrics: Metrics,
}

impl ResponseTimer {
    pub fn new(domain: String, metrics: Metrics) -> Self {
        Self {
            start: Instant::now(),
            domain,
            metrics,
        }
    }

    pub async fn finish(self) {
        let elapsed_ms = self.start.elapsed().as_millis() as u64;
        self.metrics.record_response_time(elapsed_ms);
    }
}
