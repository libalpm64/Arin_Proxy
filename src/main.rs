mod config;
mod state;
mod pow;
mod handlers;
mod blake3;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper::{Request};
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use http_body_util::Full;
use bytes::Bytes;
use parking_lot::RwLock;
use log::{info, error};

use crate::config::{Config, DomainSettings};
use crate::state::{AppState, IPBuckets, N_IP_BUCKETS};
use crate::pow::PowVerifierPool;
 

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging so info!/error! messages are visible without RUST_LOG set
    // Commented out -> Env_logger adds extra overhead.
    //env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
    //    .format_timestamp_secs()
    //    .init();
    info!("Starting Arin Proxy");
    info!("Loading configuration from config.json");
    let config_file = match File::open("config.json") {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to open config.json: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("config.json not found: {}", e)));
        }
    };
    let config: Config = match serde_json::from_reader(BufReader::new(config_file)) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to parse config.json: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid configuration file: {}", e)));
        }
    };

    // Globals
    let domains_config = Arc::new(config.domains);
    let cookie_key: [u8; 32] = *blake3::hash(config.cookie_secret.as_bytes()).as_bytes();
    let pin_pow_threads = config.runtime.pin_pow_threads;
    let pow_pool = PowVerifierPool::new(
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).min(4),
        pin_pow_threads,
    );
    let global_total_requests = Arc::new(AtomicU64::new(0));
    let global_challenged_requests = Arc::new(AtomicU64::new(0));
    let global_allowed_requests = Arc::new(AtomicU64::new(0));
    
    info!("HTTP client config prepared");
    info!("Arin proxy is running on http://127.0.0.1:3000");
    info!("Configured domains:");
    let mut stages_map: HashMap<String, Arc<AtomicU8>> = HashMap::new();
    for (domain, settings) in domains_config.iter() {
        let initial_stage = settings.stage.unwrap_or(0);
        stages_map.insert(domain.clone(), Arc::new(AtomicU8::new(initial_stage)));
        info!(
            "  {} -> {} (Cloudflare mode: {}, Initial stage: {})", 
            domain, settings.backend, settings.cloudflare_mode, initial_stage
        );
    }
    let stages_global = Arc::new(stages_map);
    info!("Starting HTTP server");
    let mut domains_map: HashMap<String, DomainSettings> = HashMap::new();
    for (k, v) in domains_config.iter() {
        let mut s = v.clone();
        s.current_stage = s.stage.unwrap_or(0);
        s.last_reset = Some(Instant::now());
        s.stage_ptr = stages_global.get(k).cloned();
        if config.runtime.resolve_dns_startup {
            if let Some((host, port_str)) = s.backend.split_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    use std::net::{ToSocketAddrs, SocketAddr};
                    let addrs = (host, port).to_socket_addrs();
                    if let Ok(mut iter) = addrs {
                        if let Some(sa) = iter.find(|a| matches!(a, SocketAddr::V4(_) | SocketAddr::V6(_))) {
                            s.backend = format!("{}:{}", sa.ip(), port);
                        }
                    }
                }
            }
        }
        if !s.backend.is_empty() {
            let mut base = String::with_capacity(8 + s.backend.len());
            if s.use_https { base.push_str("https://"); } else { base.push_str("http://"); }
            base.push_str(&s.backend);
            s.backend_base = base;
        } else {
            s.backend_base = String::new();
        }
        domains_map.insert(k.clone(), s);
    }
    let init_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let http_client: HyperClient<HttpConnector, Full<Bytes>> = HyperClient::builder(TokioExecutor::new()).build_http();
    let app_state = Arc::new(AppState {
        domains: RwLock::new(domains_map),
        ip_buckets: IPBuckets::new(N_IP_BUCKETS, init_secs),
        stages: stages_global.clone(),
        pow_pool: pow_pool.clone(),
        cookie_key,
        local_ip_acc: parking_lot::Mutex::new(vec![0u64; N_IP_BUCKETS]),
        global_total_requests: global_total_requests.clone(),
        global_challenged_requests: global_challenged_requests.clone(),
        global_allowed_requests: global_allowed_requests.clone(),
        http_client,
    });
    let cleanup_state = app_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_state.cleanup_old_requests();
        }
    });
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;
    info!("Starting proxy server on 127.0.0.1:3000");
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = app_state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let remote_ip = peer.ip().to_string();
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req: Request<hyper::body::Incoming>| handlers::route(req, state.clone(), remote_ip.clone())))
                .await
            {
                error!("Error serving connection: {}", err);
            }
        });
    }
}