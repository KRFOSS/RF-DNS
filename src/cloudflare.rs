use ipnet::IpNet;
use once_cell::sync::Lazy;
use std::net::IpAddr;
use std::str::FromStr;

// Separate IPv4 and IPv6 networks for faster lookup
pub static CF_IPV4_NETWORKS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    vec![
        IpNet::from_str("103.21.244.0/22").unwrap(),
        IpNet::from_str("103.22.200.0/22").unwrap(),
        IpNet::from_str("103.31.4.0/22").unwrap(),
        IpNet::from_str("104.16.0.0/13").unwrap(),
        IpNet::from_str("104.24.0.0/14").unwrap(),
        IpNet::from_str("108.162.192.0/18").unwrap(),
        IpNet::from_str("131.0.72.0/22").unwrap(),
        IpNet::from_str("141.101.64.0/18").unwrap(),
        IpNet::from_str("162.158.0.0/15").unwrap(),
        IpNet::from_str("172.64.0.0/13").unwrap(),
        IpNet::from_str("173.245.48.0/20").unwrap(),
        IpNet::from_str("188.114.96.0/20").unwrap(),
        IpNet::from_str("190.93.240.0/20").unwrap(),
        IpNet::from_str("197.234.240.0/22").unwrap(),
        IpNet::from_str("198.41.128.0/17").unwrap(),
    ]
});

pub static CF_IPV6_NETWORKS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    vec![
        IpNet::from_str("2400:cb00::/32").unwrap(),
        IpNet::from_str("2606:4700::/32").unwrap(),
        IpNet::from_str("2803:f800::/32").unwrap(),
        IpNet::from_str("2405:b500::/32").unwrap(),
        IpNet::from_str("2405:8100::/32").unwrap(),
        IpNet::from_str("2a06:98c0::/29").unwrap(),
        IpNet::from_str("2c0f:f248::/32").unwrap(),
    ]
});

pub static CF_NETWORKS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    let mut networks = Vec::new();
    networks.extend(CF_IPV4_NETWORKS.clone());
    networks.extend(CF_IPV6_NETWORKS.clone());
    networks
});

pub fn is_cloudflare_ip(ip: &str) -> bool {
    match IpAddr::from_str(ip) {
        Ok(addr) => {
            // Check appropriate network list based on IP version
            match addr {
                IpAddr::V4(_) => CF_IPV4_NETWORKS
                    .iter()
                    .any(|network| network.contains(&addr)),
                IpAddr::V6(_) => CF_IPV6_NETWORKS
                    .iter()
                    .any(|network| network.contains(&addr)),
            }
        }
        Err(_) => false,
    }
}
