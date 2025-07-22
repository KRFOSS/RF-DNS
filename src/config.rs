// 전역 설정 및 상수 정의
use std::time::Duration;

// 서버 설정
pub const DNS_PORT: u16 = 53;
pub const DOH_PORT: u16 = 443;
pub const DOT_PORT: u16 = 853;
pub const DOQ_PORT: u16 = 8853; // DoQ는 별도 포트 사용

// 캐시 설정
pub const MAX_CACHE_SIZE: u64 = 500000; // 캐시 크기 대폭 증가
pub const MAX_TTL: u64 = 14400; // 4시간 TTL
pub const CACHE_IDLE_TIME: u64 = 7200; // 2시간 유휴 시간

// 네트워크 설정
pub const MAX_CONCURRENT_CONNECTIONS: usize = 2000;
pub const MAX_CONCURRENT_QUERIES: usize = 1000;
pub const QUERY_TIMEOUT: Duration = Duration::from_millis(5000); // 5초로 증가
pub const HTTP_TIMEOUT: Duration = Duration::from_millis(8000); // 8초로 증가

// 서버 워커 설정
pub const UDP_WORKERS: usize = 8;
pub const SOCKET_BUFFER_SIZE: usize = 2048;

// 리졸버 설정
pub const SOCKET_POOL_SIZE: usize = 100;

// 루트 DNS 서버들
pub const ROOT_DNS_SERVERS: &[&str] = &[
    "1.1.1.1",         // Cloudflare Primary
    "1.0.0.1",         // Cloudflare Secondary
    "8.8.8.8",         // Google Primary
    "8.8.4.4",         // Google Secondary
    "9.9.9.9",         // Quad9 Primary
    "149.112.112.112", // Quad9 Secondary
    "208.67.222.222",  // OpenDNS Primary
    "208.67.220.220",  // OpenDNS Secondary
];

// 우회 도메인 목록
pub const BYPASS_DOMAINS: &[&str] = &[
    "prod.api.letsencrypt.org",
    "cloudflare.com",
    "speed.cloudflare.com",
    "shops.myshopify.com",
    ".cdn.cloudflare.net",
    ".pacloudflare.com",
];

// 로깅 설정
pub const LOG_LEVEL: &str = "info";
pub const STATS_INTERVAL: Duration = Duration::from_secs(300); // 5분마다 통계 출력

// 보안 설정
pub const MAX_DOMAIN_LENGTH: usize = 253;
pub const MAX_LABEL_LENGTH: usize = 63;
pub const MAX_DNS_MESSAGE_SIZE: usize = 4096;
pub const MIN_DNS_MESSAGE_SIZE: usize = 12;
pub const MAX_BASE64_QUERY_LENGTH: usize = 8192;
