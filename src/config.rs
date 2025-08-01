// 전역 설정 및 상수 정의
use std::time::Duration;

// 서버 설정
pub const DNS_PORT: u16 = 53;
pub const DOH_PORT: u16 = 443;
pub const DOT_PORT: u16 = 853;

// 캐시 설정 (성능 최적화)
pub const MAX_CACHE_SIZE: u64 = 100000; // 캐시 크기 최적화 (500K -> 100K)
pub const MAX_TTL: u64 = 3600; // TTL 단축 (4시간 -> 1시간)  
pub const CACHE_IDLE_TIME: u64 = 1800; // 유휴 시간 단축 (2시간 -> 30분)

// 네트워크 설정 (성능 최적화)
pub const MAX_CONCURRENT_CONNECTIONS: usize = 1000; // 연결 수 최적화 (2000 -> 1000)
pub const MAX_CONCURRENT_QUERIES: usize = 500; // 쿼리 수 최적화 (1000 -> 500)
pub const QUERY_TIMEOUT: Duration = Duration::from_millis(3000); // 타임아웃 단축 (5초 -> 3초)
pub const HTTP_TIMEOUT: Duration = Duration::from_millis(5000); // 타임아웃 단축 (8초 -> 5초)

// 서버 워커 설정
pub const UDP_WORKERS: usize = 8;
pub const SOCKET_BUFFER_SIZE: usize = 2048;

// 리졸버 설정 (성능 최적화)
pub const SOCKET_POOL_SIZE: usize = 50; // 소켓 풀 크기 최적화 (100 -> 50)

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

// 업스트림 DNS 프리셋
pub const UPSTREAM_PRESETS: &[(&str, &str)] = &[
    ("cloudflare", "1.1.1.1"),
    ("cf", "1.1.1.1"),
    ("google", "8.8.8.8"),
    ("g", "8.8.8.8"),
    ("quad9", "9.9.9.9"),
    ("q9", "9.9.9.9"),
    ("opendns", "208.67.222.222"),
    ("od", "208.67.222.222"),
    ("adguard", "94.140.14.14"),
    ("ag", "94.140.14.14"),
    ("eliv", "150.230.255.179"),
    ("ei", "150.230.255.179"),
];

// 보안 설정
pub const MAX_DOMAIN_LENGTH: usize = 253;
pub const MAX_LABEL_LENGTH: usize = 63;
pub const MAX_DNS_MESSAGE_SIZE: usize = 4096;
pub const MIN_DNS_MESSAGE_SIZE: usize = 12;
pub const MAX_BASE64_QUERY_LENGTH: usize = 8192;
