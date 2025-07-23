// 공통 모듈: 중복 코드 제거 및 최적화된 유틸리티 함수들
use crate::config::*;
use crate::errors::*;
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::RecordType;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::OnceCell;

// 전역 ID 생성기 (성능 최적화)
static ID_GENERATOR: AtomicU16 = AtomicU16::new(1);

// 소켓 풀 (메모리 최적화)
static SOCKET_POOL: OnceCell<Arc<tokio::sync::Mutex<Vec<UdpSocket>>>> = OnceCell::const_new();

/// 고성능 DNS 쿼리 ID 생성
#[inline]
pub fn generate_query_id() -> u16 {
    ID_GENERATOR.fetch_add(1, Ordering::Relaxed)
}

/// 최적화된 DNS 메시지 생성
pub fn create_dns_query(domain: &str, record_type: RecordType) -> DnsResult<Message> {
    let mut query = Message::new();
    query.set_id(generate_query_id());
    query.set_message_type(MessageType::Query);
    query.set_recursion_desired(true);
    
    let name = domain.parse()
        .map_err(|e| DnsError::ParseError(format!("Invalid domain: {}", e)))?;
    query.add_query(Query::query(name, record_type));
    
    Ok(query)
}

/// 최적화된 에러 응답 생성
pub fn create_error_response(query_id: u16, error_code: ResponseCode) -> Message {
    let mut response = Message::new();
    response.set_id(query_id);
    response.set_message_type(MessageType::Response);
    response.set_response_code(error_code);
    response.set_recursion_available(true);
    response
}

/// 소켓 풀에서 UDP 소켓 가져오기 (최적화)
pub async fn get_pooled_socket() -> DnsResult<UdpSocket> {
    let pool = SOCKET_POOL.get_or_init(|| async {
        Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(SOCKET_POOL_SIZE)))
    }).await;
    
    let mut pool_guard = pool.lock().await;
    if let Some(socket) = pool_guard.pop() {
        drop(pool_guard);
        Ok(socket)
    } else {
        drop(pool_guard);
        UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| DnsError::NetworkError(format!("Failed to create socket: {}", e)))
    }
}

/// 소켓을 풀에 반환 (최적화)
pub async fn return_pooled_socket(socket: UdpSocket) {
    if let Some(pool) = SOCKET_POOL.get() {
        let mut pool_guard = pool.lock().await;
        if pool_guard.len() < SOCKET_POOL_SIZE {
            pool_guard.push(socket);
        }
    }
}

/// DNS 메시지 검증 (보안 강화)
pub fn validate_dns_message(data: &[u8]) -> DnsResult<()> {
    if data.len() < MIN_DNS_MESSAGE_SIZE {
        return Err(DnsError::InvalidQuery("DNS message too small".to_string()));
    }
    if data.len() > MAX_DNS_MESSAGE_SIZE {
        return Err(DnsError::InvalidQuery("DNS message too large".to_string()));
    }
    Ok(())
}

/// 도메인 이름 검증 및 정규화 (보안 + 성능)
pub fn normalize_domain(domain: &str) -> DnsResult<String> {
    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(DnsError::InvalidQuery("Domain name too long".to_string()));
    }
    
    let normalized = domain.to_lowercase();
    if normalized.ends_with('.') {
        Ok(normalized)
    } else {
        Ok(format!("{}.", normalized))
    }
}

/// TCP 길이 프리픽스 처리 (중복 제거)
pub fn encode_tcp_length(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u16;
    let mut result = Vec::with_capacity(data.len() + 2);
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(data);
    result
}

/// TCP 길이 프리픽스 디코딩
pub fn decode_tcp_length(data: &[u8]) -> DnsResult<(usize, &[u8])> {
    if data.len() < 2 {
        return Err(DnsError::InvalidQuery("TCP message too short".to_string()));
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    Ok((len, &data[2..]))
}

/// 빠른 메모리 복사 (성능 최적화)
#[inline]
pub fn fast_copy(dst: &mut [u8], src: &[u8]) -> usize {
    let copy_len = std::cmp::min(dst.len(), src.len());
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), copy_len);
    }
    copy_len
}

/// 서버 주소 최적화 (DNS 서버 로드밸런싱)
pub fn get_optimal_servers(servers: &[SocketAddr]) -> Vec<SocketAddr> {
    // 간단한 라운드 로빈 + 빠른 서버 우선
    let mut optimized = servers.to_vec();
    optimized.rotate_left(generate_query_id() as usize % servers.len());
    optimized
}

/// 메트릭 업데이트용 매크로 (코드 크기 감소)
#[macro_export]
macro_rules! update_metrics {
    ($metrics:expr, cache_hit) => {
        $metrics.record_cache_hit();
    };
    ($metrics:expr, cache_miss) => {
        $metrics.record_cache_miss();
    };
    ($metrics:expr, success) => {
        $metrics.record_success();
    };
    ($metrics:expr, error) => {
        $metrics.record_error();
    };
}

/// 컴팩트한 응답 타이머
pub struct CompactTimer {
    start: std::time::Instant,
}

impl CompactTimer {
    pub fn new() -> Self {
        Self { start: std::time::Instant::now() }
    }
    
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}
