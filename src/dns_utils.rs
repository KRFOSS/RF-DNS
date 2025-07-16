use crate::cache::{get_cached_entry, store_cached_entry};
use crate::cloudflare::is_cloudflare_ip;
use anyhow::Result;
use reqwest::Client;
use std::collections::HashSet;
use std::str::FromStr;
use trust_dns_proto::op::{Message, Query};
use trust_dns_proto::rr::{Name, RData, Record, RecordType};
use once_cell::sync::Lazy;
use std::sync::Arc;
use tracing::{debug, trace};

pub const DEFAULT_UPSTREAM: &str = "https://1.1.1.1/dns-query";

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

pub fn get_cache(domain: &str, record_type: &RecordType, upstream: &str) -> Option<Vec<u8>> {
    get_cached_entry(domain, record_type, upstream)
}

pub fn store_cache(domain: &str, record_type: &RecordType, upstream: &str, response: &Message) {
    if let Ok(data) = response.to_vec() {
        let ttl = extract_ttl_from_response(response);
        store_cached_entry(domain, record_type, upstream, data, ttl);
    }
}

pub fn make_answer(original: &Message, answer_data: &[u8]) -> Result<Message> {
    let mut response = Message::from_vec(answer_data)?;
    response.set_id(original.id());
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
    let domain = query.name().to_string().trim_end_matches('.').to_lowercase();

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

pub async fn patch_response(response: &mut Message) -> Result<()> {
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

    // Find first IP address in the response
    let first_ip = response.answers().iter().find_map(|answer| {
        answer.data().and_then(extract_ip_from_rdata)
    });

    if let Some(ip) = first_ip {
        debug!("patch_response: first_ip found: {}", ip);
        if is_cloudflare_ip(&ip) {
            debug!("patch_response: IP is Cloudflare, patching to namu.wiki");
            // Replace with namu.wiki response
            let namu_response_data = fetch_dns("namu.wiki", &record_type, DEFAULT_UPSTREAM).await?;
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

            let new_answers: Vec<Record> = namu_message.answers()
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

    Ok(())
}

pub async fn fetch_dns(domain: &str, record_type: &RecordType, upstream: &str) -> Result<Vec<u8>> {
    // Create DNS query with a random ID
    let name = Name::from_str(domain)?;
    let mut message = Message::new();
    message.add_query(Query::query(name, *record_type));
    message.set_recursion_desired(true);
    
    // Check cache first - use original query ID
    if let Some(cached) = get_cache(domain, record_type, upstream) {
        trace!("fetch_dns cache hit: domain={}, upstream={}", domain, upstream);
        // Parse cached response and set the query ID
        let mut cached_response = Message::from_vec(&cached)?;
        cached_response.set_id(message.id());
        return Ok(cached_response.to_vec()?);
    }

    let query_data = message.to_vec()?;

    // Send HTTP request
    let client = HTTP_CLIENT.clone();
    debug!("Sending DNS query to upstream: {} for domain: {}", upstream, domain);
    let response = client
        .post(upstream)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query_data)
        .send()
        .await?;

    let response_data = response.bytes().await?.to_vec();

    // Parse and cache response
    if let Ok(mut response_message) = Message::from_vec(&response_data) {
        trace!("Caching DNS response for domain: {}", domain);
        // Set the correct ID before caching
        response_message.set_id(message.id());
        store_cache(domain, record_type, upstream, &response_message);
        return Ok(response_message.to_vec()?);
    }

    Ok(response_data)
}

fn extract_ttl_from_response(response: &Message) -> u64 {
    response
        .answers()
        .iter()
        .filter(|answer| matches!(answer.record_type(), RecordType::A | RecordType::AAAA))
        .map(|answer| answer.ttl() as u64)
        .next()
        .unwrap_or(300)
}

fn extract_ip_from_rdata(rdata: &RData) -> Option<String> {
    match rdata {
        RData::A(addr) => Some(addr.to_string()),
        RData::AAAA(addr) => Some(addr.to_string()),
        _ => None,
    }
}

fn extract_domain_from_rdata(rdata: &RData) -> Option<String> {
    match rdata {
        RData::CNAME(name) => Some(name.to_string()),
        RData::NS(name) => Some(name.to_string()),
        _ => None,
    }
}
