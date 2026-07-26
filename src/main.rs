mod config;
mod state;
mod pow;
mod vdf;
mod handlers;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::task::LocalSet;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use socket2::{SockRef, TcpKeepalive};
use http_body_util::combinators::BoxBody;
use bytes::Bytes;
use crossbeam_channel::{self, bounded};

use crate::config::Config;
use crate::state::{init_core_state, cleanup_old_requests, get_stats_snapshot, N_IP_BUCKETS, DomainConfig, DomainCoreStats, PerCoreIPLimiter};
use crate::pow::PowVerifierPool;

fn bind_reuseport(addr: std::net::SocketAddr, _core_id: usize) -> std::io::Result<tokio::net::TcpListener> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    
    #[cfg(unix)]
    {
        let _ = socket.set_reuse_port(true);
    }
    
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    
    TcpListener::from_std(std_listener)
}

fn build_core_state(config: &Config, cookie_key: [u8; 32]) -> (
    HashMap<String, DomainConfig>,
    HashMap<String, DomainCoreStats>,
    PowVerifierPool,
    [u8; 32],
    HyperClient<HttpConnector, BoxBody<Bytes, hyper::Error>>,
    tokio::sync::Semaphore,
    PerCoreIPLimiter,
) {
    let pow_pool = PowVerifierPool::new(1, false);
    
    let init_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let mut domains_config = std::collections::HashMap::new();
    let mut domains_stats = std::collections::HashMap::new();
    
    for (k, v) in &config.domains {
        let mut s = v.clone();
        
        if config.runtime.resolve_dns_startup {
            if let Some((host, port_str)) = s.backend.split_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    use std::net::{ToSocketAddrs, SocketAddr};
                    if let Ok(mut iter) = (host, port).to_socket_addrs() {
                        if let Some(sa) = iter.find(|a| matches!(a, SocketAddr::V4(_) | SocketAddr::V6(_))) {
                            s.backend = format!("{}:{}", sa.ip(), port);
                        }
                    }
                }
            }
        }
        
        let backend_base = if !s.backend.is_empty() {
            let mut base = String::with_capacity(8 + s.backend.len());
            base.push_str(if s.use_https { "https://" } else { "http://" });
            base.push_str(&s.backend);
            base
        } else {
            String::new()
        };
        
        domains_config.insert(k.clone(), DomainConfig {
            backend_base: backend_base.clone(),
            cloudflare_mode: s.cloudflare_mode,
        });
        
        domains_stats.insert(k.clone(), DomainCoreStats::new(s.stage.unwrap_or(0)));
    }
    
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_millis(
        config.runtime.client_connect_timeout_ms.unwrap_or(3000)
    )));
    connector.set_nodelay(true);
    
    let mut client_builder = HyperClient::builder(TokioExecutor::new());
    client_builder.pool_max_idle_per_host(16);
    client_builder.pool_idle_timeout(Duration::from_secs(5));
    
    let http_client = client_builder.build(connector);
    
    let max_conc = config.runtime.client_max_concurrency.unwrap_or(512);
    let backend_sem = tokio::sync::Semaphore::new(max_conc);
    
    let ip_limiter = PerCoreIPLimiter::new(N_IP_BUCKETS, init_secs);
    
    (domains_config, domains_stats, pow_pool, cookie_key, http_client, backend_sem, ip_limiter)
}

async fn core_loop(
    core_id: usize,
    config: Arc<Config>,
    cookie_key: [u8; 32],
    stats_tx: crossbeam_channel::Sender<(u64, u64, u64)>,
) {
    let (domains_config, domains_stats, pow_pool, cookie_key, http_client, backend_sem, ip_limiter) = 
        build_core_state(&config, cookie_key);
    
    init_core_state(domains_config, domains_stats, pow_pool, cookie_key, http_client, backend_sem, ip_limiter);
    
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = match bind_reuseport(addr, core_id) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Core {} failed to bind: {}", core_id, e);
            return;
        }
    };
    
    eprintln!("Core {} listening on {}", core_id, addr);
    
    let listener = std::sync::Arc::new(listener);
    let conn_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1024));
    let stats_tx = std::sync::Arc::new(stats_tx);
    
    let local_set = LocalSet::new();
    
    local_set.spawn_local(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_old_requests();
        }
    });
    
    local_set.spawn_local(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let stats_tx = stats_tx.clone();
        loop {
            interval.tick().await;
            let snapshot = get_stats_snapshot();
            let _ = stats_tx.try_send(snapshot);
        }
    });
    
    local_set.run_until(async move {
        let conn_sem = conn_sem.clone();
        let listener = listener.clone();
        
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Core {} accept error: {}", core_id, e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            
            let keepalive = TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(10));
            
            let sockref = SockRef::from(&stream);
            let _ = sockref.set_tcp_keepalive(&keepalive);
            
            let permit = conn_sem.clone().acquire_owned().await.unwrap();
            
            tokio::task::spawn_local(async move {
                let io = TokioIo::new(stream);
                let remote_addr = peer;
                
                let _ = http1::Builder::new()
                    .timer(TokioTimer::new())
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .keep_alive(true)
                    .header_read_timeout(Duration::from_secs(10))
                    .serve_connection(io, service_fn(move |req| {
                        handlers::handle_request(req, remote_addr)
                    }))
                    .await;
                
                drop(permit);
            });
        }
    }).await;
}

fn main() -> std::io::Result<()> {
    let config_file = File::open("config.json")?;
    let config: Config = serde_json::from_reader(BufReader::new(config_file))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    
    let config = Arc::new(config);
    let cookie_key: [u8; 32] = *blake3::hash(config.cookie_secret.as_bytes()).as_bytes();
    crate::vdf::init();
    
    let (stats_tx, stats_rx) = bounded(64);
    
    std::thread::spawn(move || {
        loop {
            match stats_rx.recv() {
                Ok((t, c, a)) => {
                    crate::state::GLOBAL_TOTAL.fetch_add(t, std::sync::atomic::Ordering::Relaxed);
                    crate::state::GLOBAL_CHALLENGED.fetch_add(c, std::sync::atomic::Ordering::Relaxed);
                    crate::state::GLOBAL_ALLOWED.fetch_add(a, std::sync::atomic::Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
    });
    
    let cores = num_cpus::get();
    eprintln!("Starting Arin Proxy with {} cores", cores);
    
    let mut handles = Vec::new();
    
    for core_id in 0..cores {
        let config_clone = config.clone();
        let cookie_key_clone = cookie_key;
        let stats_tx_clone = stats_tx.clone();
        
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            
            rt.block_on(core_loop(core_id, config_clone, cookie_key_clone, stats_tx_clone));
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.join();
    }
    
    Ok(())
}
