use crate::config::*;
use hickory_proto::rr::RecordType;
use moka::sync::Cache;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug)]
pub enum CacheError {
    InvalidMessage,
    SystemTimeError(std::time::SystemTimeError),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::InvalidMessage => write!(f, "Invalid DNS message format"),
            CacheError::SystemTimeError(e) => write!(f, "System time error: {}", e),
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CacheError::SystemTimeError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::time::SystemTimeError> for CacheError {
    fn from(error: std::time::SystemTimeError) -> Self {
        CacheError::SystemTimeError(error)
    }
}

pub type CacheKey = (String, RecordType);

#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<Cache<CacheKey, CacheEntry>>,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    data: Vec<u8>,
    ttl: u64,
    created_at: std::time::SystemTime,
}

impl DnsCache {
    pub fn new() -> Self {
        info!(
            "🗄️ Initializing DNS cache with max_capacity={} and max_ttl={}s",
            MAX_CACHE_SIZE, MAX_TTL
        );

        let cache = Cache::builder()
            .max_capacity(MAX_CACHE_SIZE)
            // TTL을 엔트리별로 동적으로 설정하기 위해 time_to_live 제거
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

    /// 안전한 get_with_id 버전 (에러 처리 포함)
    pub fn get_with_id(
        &self,
        domain: &str,
        record_type: &RecordType,
        query_id: u16,
    ) -> Result<Option<Vec<u8>>, CacheError> {
        if let Some(cached_data) = self.get(domain, record_type) {
            if cached_data.len() < 2 {
                return Err(CacheError::InvalidMessage);
            }

            let mut updated_data = cached_data;
            updated_data[0] = (query_id >> 8) as u8;
            updated_data[1] = (query_id & 0xff) as u8;
            return Ok(Some(updated_data));
        }
        Ok(None)
    }

    pub async fn store(&self, domain: &str, record_type: &RecordType, data: Vec<u8>, ttl: u64) {
        let cache = self.cache.clone();
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

        // 백그라운드에서 캐시 저장
        tokio::spawn(async move {
            cache.insert(key, entry);
        });
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
