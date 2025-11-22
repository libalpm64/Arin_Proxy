mod config;
mod state;
mod pow;
mod handlers;
mod blake3;

use std::collections::HashMap;
use std::cell::RefCell;
use std::fs::File;
use std::io::BufReader;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use actix_web::{web, App, HttpServer};
use dashmap::DashMap;
use actix_web::rt::time::interval;
use mimalloc::MiMalloc;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
use log::{info, error};

use crate::config::{Config, DomainSettings};
use crate::state::{AppState, IPBuckets, N_IP_BUCKETS};
use crate::pow::PowVerifierPool;
use crate::handlers::{validate_pow, handle_request, get_proxy_stats};
use awc::Client as AwcClient;
use awc::Connector as AwcConnector;

#[actix_web::main]
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

    /*
    It can be unsound to call std::env::set_var or std::env::remove_var
    in a multithreaded program due to safety limitations of the way the process
    environment is handled on some platforms. It is important to ensure that
    these functions are not called when any other thread might be running.

    It is safe in this context because we only call set_var at startup
    before spawning any threads.
    */
    unsafe {
        if config.allocator.large_os_pages {
            env::set_var("MIMALLOC_LARGE_OS_PAGES", "1");
        }
        if config.allocator.eager_commit {
            env::set_var("MIMALLOC_EAGER_COMMIT", "1");
        }
        if config.allocator.verbose {
            env::set_var("MIMALLOC_VERBOSE", "1");
        }
    }

    // Globals
    let domains_config = Arc::new(config.domains);
    let cookie_key: [u8; 32] = *blake3::hash(config.cookie_secret.as_bytes()).as_bytes();
    let stages_global: Arc<DashMap<String, Arc<AtomicU8>>> = Arc::new(DashMap::new());
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
        stages_global.insert(domain.clone(), Arc::new(AtomicU8::new(initial_stage)));
        info!(
            "  {} -> {} (Cloudflare mode: {}, Initial stage: {})", 
            domain, settings.backend, settings.cloudflare_mode, initial_stage
        );
    }
    info!("Starting HTTP server");
    
    let domains_config = domains_config.clone();
    let stages_global_inner = stages_global.clone();
    let pin_workers = config.runtime.pin_workers;
    let worker_affinity_counter = Arc::new(AtomicUsize::new(0));
    let server = HttpServer::new(move || {
        /*
          Pin worker to a CPU core on Windows.
          Note: In this case it's only on the OS target windows. Linux doesn't have such limitation.
          It's core API handles concurrency without needing to pin cores to workers. 
        */ 
        #[cfg(target_os = "windows")]
        {
            if pin_workers {
                let n_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
                let idx = worker_affinity_counter.fetch_add(1, Ordering::Relaxed) % n_cpus;
                unsafe { let _ = SetThreadAffinityMask(GetCurrentThread(), (1usize << idx) as usize); }
            }
        }
        // Per-Worker Appstate functions
        let domains_map: DashMap<String, DomainSettings> = DashMap::new();
        for (k, v) in domains_config.iter() {
            let mut s = v.clone();
            s.current_stage = s.stage.unwrap_or(0);
            s.last_reset = Some(Instant::now());
            // AtomicU64 fields are already initialized to 0 by Default
            // Cache global stage pointer for fast reads/writes
            s.stage_ptr = stages_global_inner.get(k).map(|e| e.value().clone());
            // Resolve backend DNS at startup to avoid runtime resolution
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
            // Avoid per-request allocation/concat for domains.
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
        let pool_limit = config.runtime.client_pool_limit.unwrap_or(256);
        let conn_timeout = Duration::from_millis(config.runtime.client_connect_timeout_ms.unwrap_or(5000));
        let keep_alive = Duration::from_secs(config.runtime.client_keep_alive_secs.unwrap_or(60));
        let lifetime = Duration::from_secs(config.runtime.client_lifetime_secs.unwrap_or(300));
        let connector = AwcConnector::new()
            .limit(pool_limit)
            .conn_keep_alive(keep_alive)
            .conn_lifetime(lifetime)
            .timeout(conn_timeout);
        let http_client = AwcClient::builder()
            .connector(connector)
            .timeout(Duration::from_secs(30))
            .finish();
        let app_state = Arc::new(AppState {
            domains: domains_map,
            ip_buckets: IPBuckets::new(N_IP_BUCKETS, init_secs),
            stages: stages_global_inner.clone(),
            pow_pool: pow_pool.clone(),
            cookie_key,
            local_ip_acc: RefCell::new(vec![0u64; N_IP_BUCKETS]),
            global_total_requests: global_total_requests.clone(),
            global_challenged_requests: global_challenged_requests.clone(),
            global_allowed_requests: global_allowed_requests.clone(),
            http_client,
        });

        // Request Cleanup 
        let cleanup_state = app_state.clone();
        actix_web::rt::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_state.cleanup_old_requests();
            }
        });

        App::new()
            .app_data(web::Data::new(app_state))
            .route("/proxy/stats", web::get().to(get_proxy_stats))
            .route("/pow/validate", web::post().to(validate_pow))
            .default_service(web::to(handle_request))
    })
    .bind("127.0.0.1:3000")?
    .backlog(2048)
    .workers(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
    .keep_alive(Duration::from_secs(30))
    .client_request_timeout(Duration::from_secs(30))
    .shutdown_timeout(5)
    .run();

    info!("Starting proxy server on 127.0.0.1:3000");
    server.await
}