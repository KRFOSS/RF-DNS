use crate::config::*;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use moka::sync::Cache;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

// 최적화된 캐시 키 (메모리 효율성)
type CacheKey = u64; // 해시된 키 사용

#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<Cache<CacheKey, CacheEntry>>,
}

// 압축된 캐시 엔트리 (메모리 최적화)
#[derive(Clone)]
struct CacheEntry {
    data: Box<[u8]>, // Vec 대신 Box 사용으로 메모리 절약
    ttl: u32,        // u64 -> u32로 크기 절약
    created_at: u64, // SystemTime -> u64 타임스탬프
}

impl DnsCache {
    pub fn new() -> Self {
        info!(
            "🗄️ Initializing optimized DNS cache with max_capacity={} and max_ttl={}s",
            MAX_CACHE_SIZE, MAX_TTL
        );

        let cache = Cache::builder()
            .max_capacity(MAX_CACHE_SIZE)
            .time_to_live(Duration::from_secs(MAX_TTL))
            .time_to_idle(Duration::from_secs(CACHE_IDLE_TIME))
            .initial_capacity(10000) // 초기 용량 감소
            .weigher(|_key: &CacheKey, value: &CacheEntry| -> u32 {
                (value.data.len() as u32 + 16).max(1) // 메타데이터 크기 최적화
            })
            .build();

        Self {
            cache: Arc::new(cache),
        }
    }

    // 최적화된 키 해싱
    fn hash_key(domain: &str, record_type: &RecordType) -> CacheKey {
        let mut hasher = DefaultHasher::new();
        domain.to_lowercase().hash(&mut hasher);
        record_type.hash(&mut hasher);
        hasher.finish()
    }

    // 현재 타임스탬프 (빠른 계산)
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn get(&self, domain: &str, record_type: &RecordType) -> Option<Vec<u8>> {
        let key = Self::hash_key(domain, record_type);

        if let Some(entry) = self.cache.get(&key) {
            if self.is_entry_valid(&entry) {
                debug!("Cache HIT: {}", domain);
                return Some(entry.data.to_vec());
            } else {
                debug!("Cache EXPIRED: {}", domain);
                self.cache.remove(&key);
            }
        }

        debug!("Cache MISS: {}", domain);
        None
    }

    pub fn get_with_id(
        &self,
        domain: &str,
        record_type: &RecordType,
        query_id: u16,
    ) -> Option<Vec<u8>> {
        if let Some(cached_data) = self.get(domain, record_type) {
            if let Ok(mut cached_response) = Message::from_vec(&cached_data) {
                cached_response.set_id(query_id);
                if let Ok(updated_data) = cached_response.to_vec() {
                    return Some(updated_data);
                }
            }
        }
        None
    }

    pub fn store(&self, domain: &str, record_type: &RecordType, data: Vec<u8>, ttl: u64) {
        let key = Self::hash_key(domain, record_type);
        let effective_ttl = std::cmp::min(ttl, MAX_TTL) as u32;

        let entry = CacheEntry {
            data: data.into_boxed_slice(),
            ttl: effective_ttl,
            created_at: Self::current_timestamp(),
        };

        debug!(
            "Cache STORE: {} (TTL: {}s, Size: {}B)",
            domain, effective_ttl, entry.data.len()
        );

        self.cache.insert(key, entry);
    }

    // 빠른 TTL 검증
    fn is_entry_valid(&self, entry: &CacheEntry) -> bool {
        let current_time = Self::current_timestamp();
        current_time.saturating_sub(entry.created_at) <= entry.ttl as u64
    }

    pub fn get_stats(&self) -> (u64, u64) {
        (self.cache.entry_count(), self.cache.weighted_size())
    }

    pub fn clear(&self) {
        self.cache.invalidate_all();
        info!("🧹 DNS cache cleared");
    }

    // 백그라운드 정리 태스크 시작
    pub fn start_cleanup_task(&self) {
        let cache = self.cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5분마다
            loop {
                interval.tick().await;
                cache.run_pending_tasks();
                debug!("🧹 Cache cleanup completed");
            }
        });
    }

    // 캐시 워밍업 (성능 최적화)
    pub async fn warmup(&self, domains: &[(&str, RecordType)]) {
        info!("🔥 Starting cache warmup for {} domains", domains.len());
        for (domain, record_type) in domains {
            let key = Self::hash_key(domain, record_type);
            // 미리 해시 계산하여 캐시 워밍업
            let _ = self.cache.get(&key);
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}
