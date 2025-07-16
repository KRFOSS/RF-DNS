use crate::dns_utils::{fetch_dns, make_answer, patch_response};
use trust_dns_proto::op::Message;
use anyhow::Result;
use crate::cache::{get_cached_entry_with_id, store_cached_entry};

pub async fn get_record(query: &[u8], upstream: Option<String>) -> Result<Vec<u8>> {
    use tracing::{debug, trace, error, warn};
    
    debug!("Received query bytes: {:?}", query);
    debug!("Query length: {}", query.len());
    
    let message = match Message::from_vec(query) {
        Ok(msg) => msg,
        Err(e) => {
            error!("Failed to parse DNS message: {}", e);
            
            // Try to parse as a simpler DNS message without EDNS
            if query.len() >= 12 {
                // Extract basic DNS header information
                let query_id = u16::from_be_bytes([query[0], query[1]]);
                let question_count = u16::from_be_bytes([query[4], query[5]]);
                
                if question_count == 1 {
                    // Try to extract the domain name manually
                    let mut pos = 12; // Skip header
                    let mut domain_parts = Vec::new();
                    
                    while pos < query.len() {
                        let len = query[pos] as usize;
                        if len == 0 {
                            pos += 1;
                            break;
                        }
                        if pos + 1 + len >= query.len() {
                            break;
                        }
                        
                        let part = String::from_utf8_lossy(&query[pos + 1..pos + 1 + len]);
                        domain_parts.push(part.to_string());
                        pos += 1 + len;
                    }
                    
                    if !domain_parts.is_empty() && pos + 4 <= query.len() {
                        let domain = domain_parts.join(".");
                        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
                        
                        warn!("Attempting manual DNS query parsing for domain: {}, qtype: {}", domain, qtype);
                        
                        // Convert qtype to RecordType
                        use trust_dns_proto::rr::RecordType;
                        let record_type = match qtype {
                            1 => RecordType::A,
                            28 => RecordType::AAAA,
                            5 => RecordType::CNAME,
                            65 => RecordType::HTTPS,
                            _ => RecordType::A, // Default to A record
                        };
                        
                        let upstream = upstream.unwrap_or_else(|| crate::dns_utils::DEFAULT_UPSTREAM.to_string());
                        
                        // Check cache first
                        if let Some(cached_answer) = get_cached_entry_with_id(&domain, &record_type, &upstream, query_id) {
                            trace!("Cache hit for domain: {}", domain);
                            return Ok(cached_answer);
                        }
                        
                        // Fetch from upstream
                        let answer = fetch_dns(&domain, &record_type, &upstream).await?;
                        
                        // Create a proper response with the original query ID
                        let mut response = Message::from_vec(&answer)?;
                        response.set_id(query_id);
                        
                        // Store in cache
                        let response_bytes = response.to_vec()?;
                        trace!("Storing response in cache for domain: {}", domain);
                        store_cached_entry(&domain, &record_type, &upstream, response_bytes.clone(), 300);
                        
                        return Ok(response_bytes);
                    }
                }
            }
            
            return Err(e.into());
        }
    };
    
    let question = message.queries().first().ok_or_else(|| {
        error!("No query found in message");
        anyhow::anyhow!("No query found in message")
    })?;
    
    let domain = question.name().to_string().trim_end_matches('.').to_string();
    let upstream = upstream.unwrap_or_else(|| crate::dns_utils::DEFAULT_UPSTREAM.to_string());
    let record_type = question.query_type();

    debug!(domain = %domain, upstream = %upstream, record_type = ?record_type, "get_record called");
    
    // Check cache first
    if let Some(cached_answer) = get_cached_entry_with_id(&domain, &record_type, &upstream, message.id()) {
        trace!("Cache hit for domain: {}", domain);
        return Ok(cached_answer);
    }

    // Fetch from upstream
    trace!("Cache miss, fetching from upstream: {}", upstream);
    let answer = fetch_dns(&domain, &record_type, &upstream).await.map_err(|e| {
        error!("Failed to fetch DNS from upstream: {}", e);
        e
    })?;
    
    let mut response = make_answer(&message, &answer).map_err(|e| {
        error!("Failed to create DNS answer: {}", e);
        e
    })?;
    
    // Apply patches
    trace!("Applying patch_response");
    patch_response(&mut response).await.map_err(|e| {
        error!("Failed to patch response: {}", e);
        e
    })?;
    
    // Store in cache
    let response_bytes = response.to_vec().map_err(|e| {
        error!("Failed to serialize response: {}", e);
        e
    })?;
    
    trace!("Storing response in cache for domain: {}", domain);
    store_cached_entry(&domain, &record_type, &upstream, response_bytes.clone(), 300);
    
    Ok(response_bytes)
}
