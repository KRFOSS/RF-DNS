use crate::app::DnsState;
use crate::cloudflare::is_cloudflare_ip;
use anyhow::Result;
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use once_cell::sync::Lazy;
use reqwest::Client;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, trace};

pub const DEFAULT_UPSTREAM: &str = "https://1.1.1.1/dns-query";
pub const USE_RECURSIVE_DNS: bool = true; // 자체 DNS 조회 사용 여부

pub static HTTP_CLIENT: Lazy<Arc<Client>> = Lazy::new(|| Arc::new(Client::new()));

pub static BYPASS_LIST: Lazy<HashSet<String>> = Lazy::new(|| {
    [
        "prod.api.letsencrypt.org",
        "cloudflare.com",
        "speed.cloudflare.com",
        "shops.myshopify.com",
        ".cdn.cloudflare.net",
        ".pacloudflare.com",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
});

pub async fn handle_dns_request(message: Message, state: DnsState) -> Result<Message> {
    let question = match message.queries().first() {
        Some(q) => q,
        None => {
            let mut response = Message::new();
            response.set_id(message.id());
            response.set_message_type(hickory_proto::op::MessageType::Response);
            response.set_recursion_desired(message.recursion_desired());
            response.set_recursion_available(true);
            response.set_authoritative(false);
            response.set_response_code(ResponseCode::FormErr);
            return Ok(response);
        }
    };

    let domain = question
        .name()
        .to_string()
        .trim_end_matches('.')
        .to_string();
    let record_type = question.query_type();
    let upstream = DEFAULT_UPSTREAM.to_string(); // For now, we use the default upstream.

    debug!(domain = %domain, record_type = ?record_type, "handle_dns_request called");

    // Check cache first
    if let Some(cached_answer) = state.cache.get_with_id(&domain, &record_type, message.id()) {
        debug!("Cache hit for domain: {}", domain);
        return Ok(Message::from_vec(&cached_answer)?);
    }

    // Fetch from upstream
    debug!("Cache miss, fetching from upstream for domain: {}", domain);
    let answer = fetch_dns(&domain, &record_type, &upstream, &state).await?;

    let mut response = make_answer(&message, &answer)?;

    // Apply patches
    trace!("Applying patch_response");
    patch_response(&mut response, &state).await?;

    // Store in cache
    let response_bytes = response.to_vec()?;

    debug!("Storing response in cache for domain: {}", domain);
    let ttl = extract_ttl_from_response(&response);
    state
        .cache
        .store(&domain, &record_type, response_bytes, ttl);

    Ok(response)
}

pub fn get_cache(domain: &str, record_type: &RecordType, state: &DnsState) -> Option<Vec<u8>> {
    state.cache.get(domain, record_type)
}

pub fn store_cache(domain: &str, record_type: &RecordType, response: &Message, state: &DnsState) {
    if let Ok(data) = response.to_vec() {
        let ttl = extract_ttl_from_response(response);
        state.cache.store(domain, record_type, data, ttl);
    }
}

pub fn make_answer(original: &Message, answer_data: &[u8]) -> Result<Message> {
    let mut response = Message::from_vec(answer_data)?;
    response.set_id(original.id());

    // Set proper DNS response flags
    response.set_message_type(hickory_proto::op::MessageType::Response);
    response.set_recursion_desired(original.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(false);

    // Don't add queries if they already exist
    if response.queries().is_empty() {
        response.add_queries(original.queries().to_vec());
    }
    Ok(response)
}

pub fn should_bypass(message: &Message) -> bool {
    let query = match message.queries().first() {
        Some(q) => q,
        None => return false,
    };
    let domain = query
        .name()
        .to_string()
        .trim_end_matches('.')
        .to_lowercase();

    for bypass in BYPASS_LIST.iter() {
        if bypass.starts_with('.') {
            if domain.ends_with(&bypass[1..]) {
                return true;
            }
        } else if &domain == bypass {
            return true;
        }
    }

    // Check CNAME and NS records
    for answer in message.answers() {
        if let Some(rdata) = answer.data() {
            if let Some(target) = extract_domain_from_rdata(rdata) {
                let target = target.trim_end_matches('.').to_lowercase();
                for bypass in BYPASS_LIST.iter() {
                    if bypass.starts_with('.') {
                        if target.ends_with(&bypass[1..]) {
                            return true;
                        }
                    } else if &target == bypass {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub async fn patch_response(response: &mut Message, state: &DnsState) -> Result<()> {
    if should_bypass(response) {
        trace!("patch_response: bypassed");
        return Ok(());
    }

    let query = match response.queries().first() {
        Some(q) => q.clone(),
        None => return Ok(()),
    };
    let domain = query.name().clone();
    let record_type = query.query_type();

    // Only check A and AAAA records for Cloudflare IP optimization
    if record_type == RecordType::A || record_type == RecordType::AAAA {
        // Find first IP address in the response
        let first_ip = response
            .answers()
            .iter()
            .find_map(|answer| answer.data().and_then(extract_ip_from_rdata));

        if let Some(ip) = first_ip {
            debug!("patch_response: first_ip found: {}", ip);
            if is_cloudflare_ip(&ip) {
                debug!("patch_response: IP is Cloudflare, patching to kali.download");
                // Replace with kali.download response
                let namu_response_data =
                    fetch_dns("kali.download", &record_type, DEFAULT_UPSTREAM, state).await?;
                let namu_message = Message::from_vec(&namu_response_data)?;

                let mut new_response = Message::new();
                new_response.set_id(response.id());
                new_response.set_message_type(response.message_type());
                new_response.set_op_code(response.op_code());
                new_response.set_authoritative(response.authoritative());
                new_response.set_truncated(response.truncated());
                new_response.set_recursion_desired(response.recursion_desired());
                new_response.set_recursion_available(response.recursion_available());
                new_response.set_response_code(response.response_code());
                new_response.add_queries(response.queries().to_vec());

                let new_answers: Vec<Record> = namu_message
                    .answers()
                    .iter()
                    .map(|answer| {
                        let mut new_record = answer.clone();
                        new_record.set_name(domain.clone());
                        new_record.set_ttl(std::cmp::max(answer.ttl(), 600));
                        new_record
                    })
                    .collect();

                new_response.add_answers(new_answers);
                *response = new_response;
            }
        }
    }

    Ok(())
}

pub async fn fetch_dns(
    domain: &str,
    record_type: &RecordType,
    upstream: &str,
    state: &DnsState,
) -> Result<Vec<u8>> {
    // 자체 DNS 조회 사용 여부 확인
    if USE_RECURSIVE_DNS {
        debug!("Using recursive DNS resolution for domain: {}", domain);

        // 캐시 확인
        if let Some(cached) = get_cache(domain, record_type, state) {
            debug!("Recursive DNS cache hit: domain={}", domain);
            return Ok(cached);
        }

        // 자체 DNS 조회 수행
        let response = state
            .recursive_resolver
            .resolve_domain(domain, *record_type)
            .await?;
        let response_data = response.to_vec()?;

        // 캐시 저장
        store_cache(domain, record_type, &response, state);

        return Ok(response_data);
    }

    // 기존 업스트림 방식 사용
    // Create DNS query with a random ID
    let name = Name::from_str(domain)?;
    let mut message = Message::new();
    message.add_query(Query::query(name, *record_type));
    message.set_recursion_desired(true);

    // Check cache first - use original query ID
    if let Some(cached) = get_cache(domain, record_type, state) {
        debug!(
            "fetch_dns cache hit: domain={}, record_type={:?}",
            domain, record_type
        );
        // Parse cached response and set the query ID
        let mut cached_response = Message::from_vec(&cached)?;
        cached_response.set_id(message.id());
        return Ok(cached_response.to_vec()?);
    }

    let query_data = message.to_vec()?;

    // Ensure upstream has https:// prefix
    let upstream_url = if upstream.starts_with("https://") || upstream.starts_with("http://") {
        upstream.to_string()
    } else {
        format!("https://{}", upstream)
    };

    // Send HTTP request
    let client = HTTP_CLIENT.clone();
    debug!(
        "Sending DNS query to upstream: {} for domain: {}",
        upstream_url, domain
    );
    let response = client
        .post(&upstream_url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query_data)
        .send()
        .await?;

    let response_data = response.bytes().await?.to_vec();

    // Parse and cache response
    if let Ok(mut response_message) = Message::from_vec(&response_data) {
        debug!("Caching DNS response for domain: {}", domain);
        // Set the correct ID before caching
        response_message.set_id(message.id());
        store_cache(domain, record_type, &response_message, state);
        return Ok(response_message.to_vec()?);
    }

    Ok(response_data)
}

pub fn extract_ttl_from_response(response: &Message) -> u64 {
    response
        .answers()
        .iter()
        .map(|answer| answer.ttl() as u64)
        .next()
        .unwrap_or(300)
}

fn extract_ip_from_rdata(rdata: &RData) -> Option<String> {
    match rdata {
        RData::A(addr) => Some(addr.to_string()),
        RData::AAAA(addr) => Some(addr.to_string()),
        // Other record types don't contain IP addresses directly
        _ => None,
    }
}

fn extract_domain_from_rdata(rdata: &RData) -> Option<String> {
    match rdata {
        // Basic record types
        RData::A(_) => None,
        RData::AAAA(_) => None,
        RData::CNAME(name) => Some(name.to_string()),
        RData::NS(name) => Some(name.to_string()),
        RData::MX(mx) => Some(mx.exchange().to_string()),
        RData::PTR(name) => Some(name.to_string()),
        RData::SRV(srv) => Some(srv.target().to_string()),
        RData::TXT(_) => None,
        RData::SOA(soa) => Some(soa.mname().to_string()),
        RData::HTTPS(_) => None,
        RData::SVCB(_) => None,
        RData::ANAME(name) => Some(name.to_string()),
        RData::CAA(_) => None,
        RData::CSYNC(_) => None,
        RData::HINFO(_) => None,
        RData::NAPTR(naptr) => Some(naptr.replacement().to_string()),
        RData::NULL(_) => None,
        RData::OPENPGPKEY(_) => None,
        RData::OPT(_) => None,
        RData::SSHFP(_) => None,
        RData::TLSA(_) => None,
        RData::Unknown { .. } => None,
        _ => None,
    }
}
