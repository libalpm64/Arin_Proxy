mod config;
mod state;
mod pow;
mod handlers;
mod blake3;

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper::{Request};
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioTimer;
use tokio::sync::Semaphore;
use socket2::{SockRef, TcpKeepalive};
use http_body_util::combinators::BoxBody;
use bytes::Bytes;
use log::{info, error};

use crate::config::Config;
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
    for (domain, settings) in domains_config.iter() {
        let initial_stage = settings.stage.unwrap_or(0);
        info!(
            "  {} -> {} (Cloudflare mode: {}, Initial stage: {})", 
            domain, settings.backend, settings.cloudflare_mode, initial_stage
        );
    }
    info!("Starting HTTP server");
    let init_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut domains_map: HashMap<String, Arc<crate::state::DomainRuntime>> = HashMap::new();
    for (k, v) in domains_config.iter() {
        let mut s = v.clone();
        let stage_arc = Arc::new(AtomicU8::new(s.stage.unwrap_or(0)));
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
            let runtime = crate::state::DomainRuntime {
                backend_base: base,
                cloudflare_mode: s.cloudflare_mode,
                total_requests: AtomicU64::new(0),
                bypassed_requests: AtomicU64::new(0),
                blocked_requests: AtomicU64::new(0),
                last_reset_secs: AtomicU64::new(init_secs),
                last_pow_success: AtomicU64::new(0),
                stage: stage_arc.clone(),
            };
            domains_map.insert(k.clone(), Arc::new(runtime));
        } else {
            let runtime = crate::state::DomainRuntime {
                backend_base: String::new(),
                cloudflare_mode: s.cloudflare_mode,
                total_requests: AtomicU64::new(0),
                bypassed_requests: AtomicU64::new(0),
                blocked_requests: AtomicU64::new(0),
                last_reset_secs: AtomicU64::new(init_secs),
                last_pow_success: AtomicU64::new(0),
                stage: stage_arc.clone(),
            };
            domains_map.insert(k.clone(), Arc::new(runtime));
        }
    }
    let mut connector = HttpConnector::new();
    let connect_timeout_ms = config.runtime.client_connect_timeout_ms.unwrap_or(3000);
    connector.set_connect_timeout(Some(Duration::from_millis(connect_timeout_ms)));
    let keep_alive_secs = config.runtime.client_keep_alive_secs.unwrap_or(30);
    connector.set_keepalive(Some(Duration::from_secs(keep_alive_secs)));
    connector.set_nodelay(true);
    let mut client_builder = HyperClient::builder(TokioExecutor::new());
    let pool_limit = config.runtime.client_pool_limit.unwrap_or(128);
    client_builder.pool_max_idle_per_host(pool_limit);
    let pool_idle_secs = config.runtime.client_lifetime_secs.unwrap_or(15);
    client_builder.pool_timer(TokioTimer::new()).pool_idle_timeout(Duration::from_secs(pool_idle_secs));
    if config.runtime.client_http2_only { client_builder.http2_only(true); }
    let http_client: HyperClient<HttpConnector, BoxBody<Bytes, hyper::Error>> = client_builder.build(connector);
    let max_conc = config.runtime.client_max_concurrency.unwrap_or(512);
    let app_state = Arc::new(AppState {
        domains: Arc::new(domains_map),
        ip_buckets: IPBuckets::new(N_IP_BUCKETS, init_secs),
        pow_pool: pow_pool.clone(),
        cookie_key,
        local_ip_acc: {
            let mut v: Vec<std::sync::atomic::AtomicU64> = Vec::with_capacity(N_IP_BUCKETS);
            for _ in 0..N_IP_BUCKETS { v.push(std::sync::atomic::AtomicU64::new(0)); }
            v.into_boxed_slice()
        },
        global_total_requests: global_total_requests.clone(),
        global_challenged_requests: global_challenged_requests.clone(),
        global_allowed_requests: global_allowed_requests.clone(),
        http_client,
        backend_sem: Arc::new(Semaphore::new(max_conc)),
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
    let conn_sem = Arc::new(Semaphore::new(4096));
    info!("Starting proxy server on 127.0.0.1:3000");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!("Accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };

        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(10));
        let sockref = SockRef::from(&stream);
        if let Err(e) = sockref.set_tcp_keepalive(&keepalive) {
            log::warn!("Failed to set TCP keepalive: {}", e);
        }

        let state = app_state.clone();
        let permit = conn_sem.clone().acquire_owned().await.unwrap();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let remote_addr = peer;
            let jitter = ((peer.port() as u64) & 3) + 1;
            let header_timeout = Duration::from_secs(8 + jitter);
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .preserve_header_case(true)
                .title_case_headers(true)
                .keep_alive(true)
                .header_read_timeout(header_timeout)
                .serve_connection(io, service_fn(move |req: Request<hyper::body::Incoming>| handlers::route(req, state.clone(), remote_addr)))
                .await
            {
                log::debug!("Error serving connection: {}", err);
            }
            drop(permit);
        });
    }
}
use std::collections::HashMap;