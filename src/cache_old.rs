use crate::config::*;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use moka::sync::Cache;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

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

impl DnsCache {
    pub fn new() -> Self {
        info!(
            "🗄️ Initializing DNS cache with max_capacity={} and max_ttl={}s",
            MAX_CACHE_SIZE, MAX_TTL
        );

        let cache = Cache::builder()
            .max_capacity(MAX_CACHE_SIZE)
            .time_to_live(Duration::from_secs(MAX_TTL))
            .time_to_idle(Duration::from_secs(CACHE_IDLE_TIME))
            .initial_capacity(50000)
            .weigher(|_key, value: &CacheEntry| -> u32 {
                (value.data.len() as u32 + 64).max(1) // 데이터 크기 + 메타데이터
            })
            .build();

        Self {
            cache: Arc::new(cache),
        }
    }

    pub fn get(&self, domain: &str, record_type: &RecordType) -> Option<Vec<u8>> {
        let key = (domain.to_lowercase(), *record_type);

        if let Some(entry) = self.cache.get(&key) {
            // TTL 확인
            if self.is_entry_valid(&entry) {
                debug!(
                    "Cache HIT for domain: {}, record_type: {:?}",
                    domain, record_type
                );
                return Some(entry.data.clone());
            } else {
                debug!(
                    "Cache entry expired for domain: {}, record_type: {:?}",
                    domain, record_type
                );
                self.cache.remove(&key);
            }
        }

        debug!(
            "Cache MISS for domain: {}, record_type: {:?}",
            domain, record_type
        );
        None
    }

    pub fn get_with_id(
        &self,
        domain: &str,
        record_type: &RecordType,
        query_id: u16,
    ) -> Option<Vec<u8>> {
        if let Some(cached_data) = self.get(domain, record_type) {
            // Parse the cached response and set the correct ID
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
        let key = (domain.to_lowercase(), *record_type);
        let effective_ttl = std::cmp::min(ttl, MAX_TTL);

        let entry = CacheEntry {
            data,
            ttl: effective_ttl,
            created_at: std::time::SystemTime::now(),
        };

        debug!(
            "📦 Storing in cache: domain={}, record_type={:?}, ttl={}s, size={}B",
            domain,
            record_type,
            effective_ttl,
            entry.data.len()
        );

        self.cache.insert(key, entry);
    }

    pub fn remove_domain(&self, domain: &str) -> u64 {
        let domain_lower = domain.to_lowercase();
        let record_types = [
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::MX,
            RecordType::TXT,
            RecordType::NS,
            RecordType::PTR,
            RecordType::SOA,
            RecordType::SRV,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::CAA,
        ];

        let mut removed_count = 0;
        for record_type in record_types {
            let key = (domain_lower.clone(), record_type);
            if self.cache.remove(&key).is_some() {
                removed_count += 1;
                debug!(
                    "Removed from cache: domain={}, record_type={:?}",
                    domain, record_type
                );
            }
        }

        removed_count
    }

    pub fn clear_all(&self) {
        self.cache.invalidate_all();
        info!("🧹 Cleared all cache entries");
    }

    pub fn cache_stats(&self) -> (u64, u64) {
        (self.cache.entry_count(), self.cache.weighted_size())
    }

    pub fn cache_info(&self) -> serde_json::Value {
        let (entry_count, weighted_size) = self.cache_stats();
        serde_json::json!({
            "entries": entry_count,
            "size_bytes": weighted_size,
            "max_capacity": MAX_CACHE_SIZE,
            "max_ttl_seconds": MAX_TTL,
            "idle_timeout_seconds": CACHE_IDLE_TIME,
        })
    }

    fn is_entry_valid(&self, entry: &CacheEntry) -> bool {
        match entry.created_at.elapsed() {
            Ok(elapsed) => elapsed.as_secs() < entry.ttl,
            Err(_) => {
                warn!("System time error while checking cache entry validity");
                false
            }
        }
    }

    // 캐시 정리 작업 (백그라운드에서 실행)
    pub fn start_cleanup_task(&self) {
        let cache = self.cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5분마다 정리
            loop {
                interval.tick().await;
                cache.run_pending_tasks();
                debug!("🧹 Cache cleanup task completed");
            }
        });
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DnsCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (entries, size) = self.cache_stats();
        f.debug_struct("DnsCache")
            .field("entries", &entries)
            .field("size_bytes", &size)
            .field("max_capacity", &MAX_CACHE_SIZE)
            .finish()
    }
}
