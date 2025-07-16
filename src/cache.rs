use moka::sync::Cache;
use std::time::Duration;
use trust_dns_proto::rr::RecordType;
use trust_dns_proto::op::Message;
use once_cell::sync::Lazy;

pub const MAX_CACHE_SIZE: u64 = 10000;
pub const MAX_TTL: u64 = 3000;

pub type CacheKey = (String, RecordType, String); // (domain, record_type, upstream)

pub static CACHE: Lazy<Cache<CacheKey, Vec<u8>>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(MAX_CACHE_SIZE)
        .time_to_live(Duration::from_secs(MAX_TTL))
        .build()
});

pub fn get_cached_entry(domain: &str, record_type: &RecordType, upstream: &str) -> Option<Vec<u8>> {
    let key = (domain.to_string(), *record_type, upstream.to_string());
    CACHE.get(&key)
}

pub fn get_cached_entry_with_id(domain: &str, record_type: &RecordType, upstream: &str, query_id: u16) -> Option<Vec<u8>> {
    let key = (domain.to_string(), *record_type, upstream.to_string());
    if let Some(cached_data) = CACHE.get(&key) {
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

pub fn store_cached_entry(domain: &str, record_type: &RecordType, upstream: &str, data: Vec<u8>, _ttl: u64) {
    let key = (domain.to_string(), *record_type, upstream.to_string());
    CACHE.insert(key, data);
}
