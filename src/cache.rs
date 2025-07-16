use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use moka::sync::Cache;
use std::time::Duration;
use tracing::{debug, info};

pub const MAX_CACHE_SIZE: u64 = 10000;
pub const MAX_TTL: u64 = 3000;

pub type CacheKey = (String, RecordType); // (domain, record_type) - upstream 제거

pub struct DnsCache {
    cache: Cache<CacheKey, Vec<u8>>,
}

impl DnsCache {
    pub fn new() -> Self {
        info!(
            "Initializing DNS cache with max_capacity={} and max_ttl={}s",
            MAX_CACHE_SIZE, MAX_TTL
        );
        Self {
            cache: Cache::builder()
                .max_capacity(MAX_CACHE_SIZE)
                .time_to_live(Duration::from_secs(MAX_TTL))
                .build(),
        }
    }

    pub fn get(&self, domain: &str, record_type: &RecordType) -> Option<Vec<u8>> {
        let key = (domain.to_string(), *record_type);
        let result = self.cache.get(&key);
        if result.is_some() {
            debug!(
                "Cache HIT for domain: {}, record_type: {:?}",
                domain, record_type
            );
        } else {
            debug!(
                "Cache MISS for domain: {}, record_type: {:?}",
                domain, record_type
            );
        }
        result
    }

    pub fn get_with_id(
        &self,
        domain: &str,
        record_type: &RecordType,
        query_id: u16,
    ) -> Option<Vec<u8>> {
        let key = (domain.to_string(), *record_type);
        if let Some(cached_data) = self.cache.get(&key) {
            debug!(
                "Cache HIT for domain: {}, record_type: {:?}, updating ID to {}",
                domain, record_type, query_id
            );
            // Parse the cached response and set the correct ID
            if let Ok(mut cached_response) = Message::from_vec(&cached_data) {
                cached_response.set_id(query_id);
                if let Ok(updated_data) = cached_response.to_vec() {
                    return Some(updated_data);
                }
            }
        } else {
            debug!(
                "Cache MISS for domain: {}, record_type: {:?}",
                domain, record_type
            );
        }
        None
    }

    pub fn store(&self, domain: &str, record_type: &RecordType, data: Vec<u8>, ttl: u64) {
        let key = (domain.to_string(), *record_type);
        let effective_ttl = std::cmp::min(ttl, MAX_TTL);
        debug!(
            "Storing in cache: domain={}, record_type={:?}, ttl={}s",
            domain, record_type, effective_ttl
        );
        self.cache.insert(key, data);
    }

    pub fn cache_stats(&self) -> (u64, u64) {
        (self.cache.entry_count(), self.cache.weighted_size())
    }

    pub fn remove_domain(&self, domain: &str) -> u64 {
        let mut removed_count = 0;

        // 모든 레코드 타입에 대해 삭제 시도
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
        ];

        for record_type in record_types {
            let key = (domain.to_string(), record_type);
            if self.cache.remove(&key).is_some() {
                removed_count += 1;
                debug!(
                    "Removed from cache: domain={}, record_type={:?}",
                    domain, record_type
                );
            }
        }

        info!(
            "Removed {} cache entries for domain: {}",
            removed_count, domain
        );
        removed_count
    }

    pub fn clear_all(&self) {
        self.cache.invalidate_all();
        info!("Cleared all cache entries");
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}
