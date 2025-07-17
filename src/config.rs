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
pub const TCP_WORKERS: usize = 4;
pub const SOCKET_BUFFER_SIZE: usize = 2048;

// 리졸버 설정
pub const SOCKET_POOL_SIZE: usize = 100;
pub const MAX_QUERY_RETRIES: u32 = 5; // 재시도 횟수 증가

// 루트 DNS 서버들
pub const ROOT_DNS_SERVERS: &[&str] = &[
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    "208.67.222.222",
    "149.112.112.112",
    "198.41.0.4",     // A.ROOT-SERVERS.NET
    "170.247.170.2",  // B.ROOT-SERVERS.NET
    "192.33.4.12",    // C.ROOT-SERVERS.NET
    "199.7.91.13",    // D.ROOT-SERVERS.NET
    "192.203.230.10", // E.ROOT-SERVERS.NET
    "192.5.5.241",    // F.ROOT-SERVERS.NET
    "192.112.36.4",   // G.ROOT-SERVERS.NET
    "198.97.190.53",  // H.ROOT-SERVERS.NET
    "192.36.148.17",  // I.ROOT-SERVERS.NET
    "192.58.128.30",  // J.ROOT-SERVERS.NET
    "193.0.14.129",   // K.ROOT-SERVERS.NET
    "199.7.83.42",    // L.ROOT-SERVERS.NET
    "202.12.27.33",   // M.ROOT-SERVERS.NET
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
