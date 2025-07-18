mod cache;
mod config;
mod doh;
mod doq;
mod dot;
mod errors;
mod metrics;
mod resolver;
mod servers;
mod state;
mod utils;

use clap::Parser;
use config::*;
use daemonize::Daemonize;
use doh::run_doh_server;
use doq::run_doq_server;
use dot::run_dot_server;
use errors::DnsResult;
use servers::{run_tcp_server, run_udp_server};
use state::AppState;
use tracing::info;
use utils::setup_logging;

#[derive(Parser)]
#[command(name = "rfdns")]
#[command(about = "A high-performance DNS server with DoH and DoT support")]
struct Args {
    /// Path to TLS certificate file
    #[arg(long, help = "Path to TLS certificate file (.pem or .crt)")]
    cert: Option<String>,

    /// Path to TLS private key file
    #[arg(long, help = "Path to TLS private key file (.pem or .key)")]
    key: Option<String>,

    /// DoH server port
    #[arg(long, default_value_t = DOH_PORT, help = "Port for DNS over HTTPS server")]
    doh_port: u16,

    /// DoT server port
    #[arg(long, default_value_t = DOT_PORT, help = "Port for DNS over TLS server")]
    dot_port: u16,

    /// DoQ server port
    #[arg(long, default_value_t = DOQ_PORT, help = "Port for DNS over QUIC server")]
    doq_port: u16,

    /// Plain DNS server port
    #[arg(long, default_value_t = DNS_PORT, help = "Port for plain DNS server")]
    dns_port: u16,

    /// TCP DNS server port
    #[arg(long, default_value_t = 5353, help = "Port for TCP DNS server")]
    tcp_port: u16,

    /// Enable UDP DNS server
    #[arg(long, help = "Enable UDP DNS server")]
    enable_udp: bool,

    /// Enable TCP DNS server
    #[arg(long, help = "Enable TCP DNS server")]
    enable_tcp: bool,

    /// Enable DoH server
    #[arg(long, help = "Enable DNS over HTTPS server")]
    enable_doh: bool,

    /// Enable DoT server
    #[arg(long, help = "Enable DNS over TLS server")]
    enable_dot: bool,

    /// Enable DoQ server
    #[arg(long, help = "Enable DNS over QUIC server")]
    enable_doq: bool,

    /// Run as daemon
    #[arg(long, help = "Run as daemon in background")]
    daemon: bool,

    /// PID file path (only used with --daemon)
    #[arg(long, help = "Path to PID file when running as daemon")]
    pid_file: Option<String>,
}

#[tokio::main]
async fn main() -> DnsResult<()> {
    let args = Args::parse();

    // 데몬 모드 설정
    if args.daemon {
        let pid_file = args.pid_file.as_deref().unwrap_or("/var/run/rfdns.pid");

        let daemonize = Daemonize::new()
            .pid_file(pid_file)
            .chown_pid_file(true)
            .working_directory("/tmp")
            .user("nobody")
            .group("daemon")
            .umask(0o027);

        match daemonize.start() {
            Ok(_) => {
                // 데몬 모드에서는 로깅을 다시 설정해야 함
                setup_logging();
                info!("🔄 Successfully daemonized with PID file: {}", pid_file);
            }
            Err(e) => {
                eprintln!("❌ Failed to daemonize: {}", e);
                return Err(errors::DnsError::ConfigurationError(format!(
                    "Failed to daemonize: {}",
                    e
                )));
            }
        }
    } else {
        // 로깅 설정
        setup_logging();
    }

    // 기본 크립토 프로바이더 설치
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| {
            errors::DnsError::ConfigurationError(
                "Failed to install default crypto provider".to_string(),
            )
        })?;

    // 애플리케이션 상태 초기화
    let state = AppState::new()?;

    info!("🚀 rfdns v{} starting...", env!("CARGO_PKG_VERSION"));
    info!("🔧 Configuration loaded successfully");

    // 서버 태스크들
    let mut tasks = Vec::new();

    // UDP DNS 서버
    if args.enable_udp {
        let udp_state = state.clone();
        let udp_port = args.dns_port;
        let udp_task = tokio::spawn(async move {
            if let Err(e) = run_udp_server(udp_state, udp_port).await {
                eprintln!("❌ UDP DNS server error: {}", e);
            }
        });
        tasks.push(udp_task);
        info!("📡 UDP DNS server will start on port {}", args.dns_port);
    }

    // TCP DNS 서버
    if args.enable_tcp {
        let tcp_state = state.clone();
        let tcp_port = args.tcp_port;
        let tcp_task = tokio::spawn(async move {
            if let Err(e) = run_tcp_server(tcp_state, tcp_port).await {
                eprintln!("❌ TCP DNS server error: {}", e);
            }
        });
        tasks.push(tcp_task);
        info!("📡 TCP DNS server will start on port {}", args.tcp_port);
    }

    // DoT 서버
    if args.enable_dot {
        let dot_state = state.clone();
        let dot_port = args.dot_port;
        let cert_for_dot = args.cert.clone();
        let key_for_dot = args.key.clone();
        let dot_task = tokio::spawn(async move {
            if let Err(e) = run_dot_server(dot_state, dot_port, cert_for_dot, key_for_dot).await {
                eprintln!("❌ DoT server error: {}", e);
            }
        });
        tasks.push(dot_task);
        info!("🔐 DoT server will start on port {}", args.dot_port);
    }

    // DoQ 서버
    if args.enable_doq {
        let doq_state = state.clone();
        let doq_port = args.doq_port;
        let cert_for_doq = args.cert.clone();
        let key_for_doq = args.key.clone();
        let doq_task = tokio::spawn(async move {
            if let Err(e) = run_doq_server(doq_state, doq_port, cert_for_doq, key_for_doq).await {
                eprintln!("❌ DoQ server error: {}", e);
            }
        });
        tasks.push(doq_task);
        info!("🚀 DoQ server will start on port {}", args.doq_port);
    }

    // DoH 서버
    if args.enable_doh {
        let doh_state = state.clone();
        let doh_port = args.doh_port;
        let cert_for_doh = args.cert.clone();
        let key_for_doh = args.key.clone();
        let doh_task = tokio::spawn(async move {
            if let Err(e) = run_doh_server(doh_state, doh_port, cert_for_doh, key_for_doh).await {
                eprintln!("❌ DoH server error: {}", e);
            }
        });
        tasks.push(doh_task);
        info!("🌐 DoH server will start on port {}", args.doh_port);
    }

    if tasks.is_empty() {
        return Err(errors::DnsError::ConfigurationError(
            "No servers enabled".to_string(),
        ));
    }

    // 시그널 핸들러 설정
    let shutdown_signal = setup_shutdown_signal();

    info!("🚀 All servers starting...");
    info!(
        "📊 Metrics and statistics will be displayed every {} seconds",
        STATS_INTERVAL.as_secs()
    );

    // 서버 시작 완료 메시지
    tokio::select! {
        _ = futures::future::join_all(tasks) => {
            info!("🛑 All servers have stopped");
        }
        _ = shutdown_signal => {
            info!("🛑 Received shutdown signal, stopping servers...");
        }
    }

    info!("👋 rfdns shutdown complete");
    Ok(())
}

async fn setup_shutdown_signal() {
    use tokio::signal;

    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .expect("Failed to install SIGINT handler");
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");

    tokio::select! {
        _ = sigint.recv() => {
            info!("🛑 Received SIGINT");
        }
        _ = sigterm.recv() => {
            info!("🛑 Received SIGTERM");
        }
    }
}
