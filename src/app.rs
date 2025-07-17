use crate::cache::DnsCache;
use crate::dns_utils::patch_response;
use crate::recursive_dns::RecursiveDnsResolver;
use anyhow::Result;
use hickory_proto::op::Message;
use std::sync::Arc;

#[derive(Clone)]
pub struct DnsState {
    pub cache: Arc<DnsCache>,
    pub recursive_resolver: Arc<RecursiveDnsResolver>,
}

impl DnsState {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DnsCache::new()),
            recursive_resolver: Arc::new(
                RecursiveDnsResolver::new().expect("Failed to create recursive resolver"),
            ),
        }
    }
}

impl Default for DnsState {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn get_record(query: &[u8], state: DnsState) -> Result<Vec<u8>> {
    use tracing::{debug, error, trace, warn};

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

                        warn!(
                            "Attempting manual DNS query parsing for domain: {}, qtype: {}",
                            domain, qtype
                        );

                        // Convert qtype to RecordType
                        use hickory_proto::rr::RecordType;
                        let record_type = match qtype {
                            1 => RecordType::A,
                            28 => RecordType::AAAA,
                            5 => RecordType::CNAME,
                            2 => RecordType::NS,
                            15 => RecordType::MX,
                            16 => RecordType::TXT,
                            12 => RecordType::PTR,
                            33 => RecordType::SRV,
                            6 => RecordType::SOA,
                            65 => RecordType::HTTPS,
                            64 => RecordType::SVCB,
                            13 => RecordType::HINFO,
                            24 => RecordType::SIG,
                            25 => RecordType::KEY,
                            35 => RecordType::NAPTR,
                            41 => RecordType::OPT,
                            43 => RecordType::DS,
                            44 => RecordType::SSHFP,
                            46 => RecordType::RRSIG,
                            47 => RecordType::NSEC,
                            48 => RecordType::DNSKEY,
                            50 => RecordType::NSEC3,
                            51 => RecordType::NSEC3PARAM,
                            52 => RecordType::TLSA,
                            59 => RecordType::CDS,
                            60 => RecordType::CDNSKEY,
                            61 => RecordType::OPENPGPKEY,
                            62 => RecordType::CSYNC,
                            250 => RecordType::TSIG,
                            252 => RecordType::AXFR,
                            255 => RecordType::ANY,
                            257 => RecordType::CAA,
                            _ => RecordType::A, // Default to A record
                        };

                        // Check cache first
                        if let Some(cached_answer) =
                            state.cache.get_with_id(&domain, &record_type, query_id)
                        {
                            trace!("Cache hit for domain: {}", domain);
                            return Ok(cached_answer);
                        }

                        // Fetch using recursive resolver
                        let response = state
                            .recursive_resolver
                            .resolve_domain(&domain, record_type)
                            .await?;
                        let mut response = response;
                        response.set_id(query_id);

                        // Store in cache
                        let response_bytes = response.to_vec()?;
                        trace!("Storing response in cache for domain: {}", domain);
                        let ttl = crate::dns_utils::extract_ttl_from_response(&response);
                        state
                            .cache
                            .store(&domain, &record_type, response_bytes.clone(), ttl);

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

    let domain = question
        .name()
        .to_string()
        .trim_end_matches('.')
        .to_string();
    let record_type = question.query_type();

    debug!(domain = %domain, record_type = ?record_type, "get_record called");

    // Check cache first
    if let Some(cached_answer) = state.cache.get_with_id(&domain, &record_type, message.id()) {
        trace!("Cache hit for domain: {}", domain);
        return Ok(cached_answer);
    }

    // Fetch from upstream
    trace!("Cache miss, fetching using recursive resolver");
    let answer = state
        .recursive_resolver
        .resolve_domain(&domain, record_type)
        .await
        .map_err(|e| {
            error!("Failed to resolve DNS using recursive resolver: {}", e);
            e
        })?;

    let mut response = answer;
    response.set_id(message.id());

    // Apply patches
    trace!("Applying patch_response");
    patch_response(&mut response, &state).await.map_err(|e| {
        error!("Failed to patch response: {}", e);
        e
    })?;

    // Store in cache
    let response_bytes = response.to_vec().map_err(|e| {
        error!("Failed to serialize response: {}", e);
        e
    })?;

    trace!("Storing response in cache for domain: {}", domain);
    let ttl = crate::dns_utils::extract_ttl_from_response(&response);
    state
        .cache
        .store(&domain, &record_type, response_bytes.clone(), ttl);

    Ok(response_bytes)
}
