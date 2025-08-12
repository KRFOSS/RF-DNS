// 설정 로드: config.toml에서 읽어 전역 설정 제공
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::Duration;

// CLI 기본값 호환을 위해 컴파일 타임 상수 유지 (TOML 미설정 시 기본)
pub const DEFAULT_DNS_PORT: u16 = 53;
pub const DEFAULT_DOH_PORT: u16 = 443;
pub const DEFAULT_DOT_PORT: u16 = 853;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PortsConfig {
    pub dns: u16,
    pub doh: u16,
    pub dot: u16,
    pub tcp: u16,
}

impl Default for PortsConfig {
    fn default() -> Self {
        Self {
            dns: DEFAULT_DNS_PORT,
            doh: DEFAULT_DOH_PORT,
            dot: DEFAULT_DOT_PORT,
            tcp: 5353,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    pub max_size: u64,
    pub max_ttl: u64,
    pub idle_time: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 100_000,
            max_ttl: 3600,
            idle_time: 1800,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub max_concurrent_connections: usize,
    pub max_concurrent_queries: usize,
    pub query_timeout_ms: u64,
    pub http_timeout_ms: u64,
    pub udp_workers: usize,
    pub socket_buffer_size: usize,
    pub socket_pool_size: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_concurrent_connections: 1000,
            max_concurrent_queries: 500,
            query_timeout_ms: 3000,
            http_timeout_ms: 5000,
            udp_workers: 8,
            socket_buffer_size: 2048,
            socket_pool_size: 50,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub stats_interval_sec: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            stats_interval_sec: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub max_domain_length: usize,
    pub max_label_length: usize,
    pub max_dns_message_size: usize,
    pub min_dns_message_size: usize,
    pub max_base64_query_length: usize,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_domain_length: 253,
            max_label_length: 63,
            max_dns_message_size: 4096,
            min_dns_message_size: 12,
            max_base64_query_length: 8192,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamPreset {
    pub name: String,
    pub ip: String,
}

impl Default for UpstreamPreset {
    fn default() -> Self {
        Self {
            name: "cloudflare".into(),
            ip: "1.1.1.1".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub ports: PortsConfig,
    pub cache: CacheConfig,
    pub network: NetworkConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
    pub root_dns_servers: Vec<String>,
    pub bypass_domains: Vec<String>,
    pub upstream_presets: Vec<UpstreamPreset>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            ports: PortsConfig::default(),
            cache: CacheConfig::default(),
            network: NetworkConfig::default(),
            logging: LoggingConfig::default(),
            security: SecurityConfig::default(),
            root_dns_servers: vec![
                "1.1.1.1".into(),
                "1.0.0.1".into(),
                "8.8.8.8".into(),
                "8.8.4.4".into(),
                "9.9.9.9".into(),
                "149.112.112.112".into(),
                "208.67.222.222".into(),
                "208.67.220.220".into(),
            ],
            bypass_domains: vec![
                "prod.api.letsencrypt.org".into(),
                "cloudflare.com".into(),
                "speed.cloudflare.com".into(),
                "shops.myshopify.com".into(),
                ".cdn.cloudflare.net".into(),
                ".pacloudflare.com".into(),
            ],
            upstream_presets: vec![
                UpstreamPreset {
                    name: "cloudflare".into(),
                    ip: "1.1.1.1".into(),
                },
                UpstreamPreset {
                    name: "cf".into(),
                    ip: "1.1.1.1".into(),
                },
                UpstreamPreset {
                    name: "google".into(),
                    ip: "8.8.8.8".into(),
                },
                UpstreamPreset {
                    name: "g".into(),
                    ip: "8.8.8.8".into(),
                },
                UpstreamPreset {
                    name: "quad9".into(),
                    ip: "9.9.9.9".into(),
                },
                UpstreamPreset {
                    name: "q9".into(),
                    ip: "9.9.9.9".into(),
                },
                UpstreamPreset {
                    name: "opendns".into(),
                    ip: "208.67.222.222".into(),
                },
                UpstreamPreset {
                    name: "od".into(),
                    ip: "208.67.222.222".into(),
                },
                UpstreamPreset {
                    name: "adguard".into(),
                    ip: "94.140.14.14".into(),
                },
                UpstreamPreset {
                    name: "ag".into(),
                    ip: "94.140.14.14".into(),
                },
                UpstreamPreset {
                    name: "eliv".into(),
                    ip: "150.230.255.179".into(),
                },
                UpstreamPreset {
                    name: "ei".into(),
                    ip: "150.230.255.179".into(),
                },
            ],
        }
    }
}

// TOML 로더: config.toml 경로는 실행 디렉토리 루트의 "config.toml" 기본
fn load_from_toml() -> AppConfig {
    let path = std::env::var("RFDNS_CONFIG").unwrap_or_else(|_| "config.toml".into());
    let p = Path::new(&path);
    if !p.exists() {
        return AppConfig::default();
    }

    match fs::read_to_string(p) {
        Ok(txt) => match toml::from_str::<AppConfig>(&txt) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "[rfdns] Failed to parse config.toml: {} — using defaults",
                    e
                );
                AppConfig::default()
            }
        },
        Err(e) => {
            eprintln!("[rfdns] Failed to read config.toml: {} — using defaults", e);
            AppConfig::default()
        }
    }
}

// 전역 설정 (Lazy)
pub static CONFIG: Lazy<AppConfig> = Lazy::new(load_from_toml);

// 헬퍼: 설정 접근자
pub fn get() -> &'static AppConfig {
    &CONFIG
}

// 편의 접근자들 (기존 상수 대체)
pub fn stats_interval() -> Duration {
    Duration::from_secs(CONFIG.logging.stats_interval_sec)
}
pub fn query_timeout() -> Duration {
    Duration::from_millis(CONFIG.network.query_timeout_ms)
}
pub fn http_timeout() -> Duration {
    Duration::from_millis(CONFIG.network.http_timeout_ms)
}
