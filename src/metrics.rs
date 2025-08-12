use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Clone)]
pub struct Metrics {
    // 요청 통계
    pub total_requests: Arc<AtomicU64>,
    pub successful_requests: Arc<AtomicU64>,
    pub failed_requests: Arc<AtomicU64>,

    // 캐시 통계
    pub cache_hits: Arc<AtomicU64>,
    pub cache_misses: Arc<AtomicU64>,

    // 업스트림 통계
    pub upstream_requests: Arc<AtomicU64>,
    pub upstream_failures: Arc<AtomicU64>,

    // 연결 통계
    pub active_connections: Arc<AtomicUsize>,
    pub total_connections: Arc<AtomicU64>,

    // 응답 시간 통계
    pub response_times: Arc<RwLock<HashMap<String, u64>>>,
    pub avg_response_time: Arc<AtomicU64>,

    // 프로토콜별 통계
    pub udp_requests: Arc<AtomicU64>,
    pub tcp_requests: Arc<AtomicU64>,
    pub doh_requests: Arc<AtomicU64>,
    pub dot_requests: Arc<AtomicU64>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            successful_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            upstream_requests: Arc::new(AtomicU64::new(0)),
            upstream_failures: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            total_connections: Arc::new(AtomicU64::new(0)),
            response_times: Arc::new(RwLock::new(HashMap::new())),
            avg_response_time: Arc::new(AtomicU64::new(0)),
            udp_requests: Arc::new(AtomicU64::new(0)),
            tcp_requests: Arc::new(AtomicU64::new(0)),
            doh_requests: Arc::new(AtomicU64::new(0)),
            dot_requests: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_request(&self, protocol: Protocol) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        match protocol {
            Protocol::UDP => self.udp_requests.fetch_add(1, Ordering::Relaxed),
            Protocol::TCP => self.tcp_requests.fetch_add(1, Ordering::Relaxed),
            Protocol::DoH => self.doh_requests.fetch_add(1, Ordering::Relaxed),
            Protocol::DoT => self.dot_requests.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn record_success(&self) {
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_request(&self) {
        self.upstream_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_failure(&self) {
        self.upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn record_response_time(&self, domain: &str, time_ms: u64) {
        let mut times = self.response_times.write().await;
        times.insert(domain.to_string(), time_ms);

        // 평균 응답 시간 업데이트
        let avg = if times.is_empty() {
            0
        } else {
            times.values().sum::<u64>() / times.len() as u64
        };
        self.avg_response_time.store(avg, Ordering::Relaxed);

        // 최근 1000개 항목만 유지
        if times.len() > 1000 {
            let keys_to_remove: Vec<_> = times.keys().take(times.len() - 1000).cloned().collect();
            for key in keys_to_remove {
                times.remove(&key);
            }
        }
    }

    pub fn get_cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn get_success_rate(&self) -> f64 {
        let success = self.successful_requests.load(Ordering::Relaxed);
        let total = self.total_requests.load(Ordering::Relaxed);

        if total > 0 {
            (success as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn log_stats(&self) {
        let total_requests = self.total_requests.load(Ordering::Relaxed);
        let successful_requests = self.successful_requests.load(Ordering::Relaxed);
        let failed_requests = self.failed_requests.load(Ordering::Relaxed);
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);
        let upstream_requests = self.upstream_requests.load(Ordering::Relaxed);
        let upstream_failures = self.upstream_failures.load(Ordering::Relaxed);
        let active_connections = self.active_connections.load(Ordering::Relaxed);
        let total_connections = self.total_connections.load(Ordering::Relaxed);
        let avg_response_time = self.avg_response_time.load(Ordering::Relaxed);

        let udp_requests = self.udp_requests.load(Ordering::Relaxed);
        let tcp_requests = self.tcp_requests.load(Ordering::Relaxed);
        let doh_requests = self.doh_requests.load(Ordering::Relaxed);
        let dot_requests = self.dot_requests.load(Ordering::Relaxed);

        info!(
            "📊 DNS Server Statistics:\n\
            📈 Requests: Total={}, Success={}, Failed={} (Success Rate: {:.1}%)\n\
            🎯 Cache: Hits={}, Misses={} (Hit Rate: {:.1}%)\n\
            🔄 Upstream: Requests={}, Failures={} (Failure Rate: {:.1}%)\n\
            🔗 Connections: Active={}, Total={}\n\
            ⏱️  Avg Response Time: {}ms\n\
            🌐 Protocols: UDP={}, TCP={}, DoH={}, DoT={}",
            total_requests,
            successful_requests,
            failed_requests,
            self.get_success_rate(),
            cache_hits,
            cache_misses,
            self.get_cache_hit_rate(),
            upstream_requests,
            upstream_failures,
            if upstream_requests > 0 {
                (upstream_failures as f64 / upstream_requests as f64) * 100.0
            } else {
                0.0
            },
            active_connections,
            total_connections,
            avg_response_time,
            udp_requests,
            tcp_requests,
            doh_requests,
            dot_requests
        );
    }

    pub fn start_periodic_logging(&self) {
        let metrics = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(crate::config::stats_interval());
            loop {
                interval.tick().await;
                metrics.log_stats();
            }
        });
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    UDP,
    TCP,
    DoH,
    DoT,
}

pub struct ResponseTimer {
    start_time: Instant,
    domain: String,
    metrics: Arc<Metrics>,
}

impl ResponseTimer {
    pub fn new(domain: String, metrics: Arc<Metrics>) -> Self {
        Self {
            start_time: Instant::now(),
            domain,
            metrics,
        }
    }

    pub async fn finish(self) {
        let elapsed = self.start_time.elapsed().as_millis() as u64;
        debug!("Query for '{}' took {}ms", self.domain, elapsed);
        self.metrics
            .record_response_time(&self.domain, elapsed)
            .await;
    }
}
