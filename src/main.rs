mod config;
mod state;
mod pow;
mod handlers;

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioTimer;
use tokio::sync::Semaphore;
use socket2::{SockRef, TcpKeepalive};
use http_body_util::combinators::BoxBody;
use bytes::Bytes;

use crate::config::Config;
use crate::state::{AppState, IPBuckets, N_IP_BUCKETS, DomainRuntime};
use crate::pow::PowVerifierPool;

fn main() -> std::io::Result<()> {
    let config_file = File::open("config.json")?;
    let config: Config = serde_json::from_reader(BufReader::new(config_file))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let domains_config = Arc::new(config.domains);
    let cookie_key: [u8; 32] = *blake3::hash(config.cookie_secret.as_bytes()).as_bytes();
    let pin_pow_threads = config.runtime.pin_pow_threads;
    
    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .min(4);
    
    let pow_pool = PowVerifierPool::new(num_workers, pin_pow_threads);
    let global_total_requests = Arc::new(AtomicU64::new(0));
    let global_challenged_requests = Arc::new(AtomicU64::new(0));
    let global_allowed_requests = Arc::new(AtomicU64::new(0));
    
    let init_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut domains_map: std::collections::HashMap<String, Arc<DomainRuntime>> = 
        std::collections::HashMap::with_capacity(domains_config.len());
    
    for (k, v) in domains_config.iter() {
        let mut s = v.clone();
        let stage_arc = Arc::new(AtomicU8::new(s.stage.unwrap_or(0)));
        
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
        
        let runtime = DomainRuntime {
            backend_base,
            cloudflare_mode: s.cloudflare_mode,
            total_requests: AtomicU64::new(0),
            bypassed_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            last_reset_secs: AtomicU64::new(init_secs),
            last_pow_success: AtomicU64::new(0),
            stage: stage_arc,
        };
        domains_map.insert(k.clone(), Arc::new(runtime));
    }

    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_millis(
        config.runtime.client_connect_timeout_ms.unwrap_or(3000)
    )));
    connector.set_nodelay(true);
    
    let mut client_builder = HyperClient::builder(TokioExecutor::new());
    client_builder.pool_max_idle_per_host(16);
    client_builder.pool_idle_timeout(Duration::from_secs(5));
    
    let http_client: HyperClient<HttpConnector, BoxBody<Bytes, hyper::Error>> = 
        client_builder.build(connector);
    
    let max_conc = config.runtime.client_max_concurrency.unwrap_or(512);
    
    let local_ip_acc: Box<[AtomicU64]> = (0..N_IP_BUCKETS)
        .map(|_| AtomicU64::new(0))
        .collect();
    
    let app_state = Arc::new(AppState {
        domains: Arc::new(domains_map),
        ip_buckets: IPBuckets::new(N_IP_BUCKETS, init_secs),
        pow_pool,
        cookie_key,
        local_ip_acc,
        global_total_requests,
        global_challenged_requests,
        global_allowed_requests,
        http_client,
        backend_sem: Arc::new(Semaphore::new(max_conc)),
    });

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
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
            let conn_sem = Arc::new(Semaphore::new(1024));
            
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };

                let keepalive = TcpKeepalive::new()
                    .with_time(Duration::from_secs(60))
                    .with_interval(Duration::from_secs(10));
                
                let sockref = SockRef::from(&stream);
                let _ = sockref.set_tcp_keepalive(&keepalive);

                let state = app_state.clone();
                let permit = conn_sem.clone().acquire_owned().await.unwrap();
                
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let remote_addr = peer;
                    
                    let _ = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .keep_alive(true)
                        .header_read_timeout(Duration::from_secs(10))
                        .serve_connection(io, service_fn(move |req| {
                            handlers::route(req, state.clone(), remote_addr)
                        }))
                        .await;
                    
                    drop(permit);
                });
            }
        })
}
