use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};

pub const N_IP_BUCKETS: usize = 64 * 1024;

thread_local! {
    pub static IP_BUCKET_STATE: RefCell<PerCoreIPLimiter> = RefCell::new(PerCoreIPLimiter::new(N_IP_BUCKETS, 0));
    pub static DOMAIN_CONFIG: RefCell<HashMap<String, DomainConfig>> = RefCell::new(HashMap::new());
    pub static DOMAIN_STATS: RefCell<HashMap<String, DomainCoreStats>> = RefCell::new(HashMap::new());
    pub static POW_POOL: RefCell<crate::pow::PowVerifierPool> = RefCell::new(crate::pow::PowVerifierPool::new(1, false));
    pub static COOKIE_KEY: RefCell<[u8; 32]> = RefCell::new([0u8; 32]);
    pub static HTTP_CLIENT: RefCell<Option<Client<HttpConnector, BoxBody<Bytes, hyper::Error>>>> = RefCell::new(None);
    pub static BACKEND_SEM: RefCell<Arc<tokio::sync::Semaphore>> = RefCell::new(Arc::new(tokio::sync::Semaphore::new(512)));
    pub static LOCAL_TOTAL: std::cell::Cell<u64> = std::cell::Cell::new(0);
    pub static LOCAL_CHALLENGED: std::cell::Cell<u64> = std::cell::Cell::new(0);
    pub static LOCAL_ALLOWED: std::cell::Cell<u64> = std::cell::Cell::new(0);
}

pub static GLOBAL_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_CHALLENGED: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_ALLOWED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct DomainConfig {
    pub backend_base: String,
    pub cloudflare_mode: bool,
}

pub struct DomainCoreStats {
    pub total_requests: u64,
    pub bypassed_requests: u64,
    pub last_reset_secs: u64,
    pub last_pow_success: u64,
    pub stage: u8,
}

impl DomainCoreStats {
    pub fn new(stage: u8) -> Self {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            total_requests: 0,
            bypassed_requests: 0,
            last_reset_secs: now_secs,
            last_pow_success: 0,
            stage,
        }
    }
}

pub struct PerCoreIPLimiter {
    counts: Vec<u64>,
    last_reset: Vec<u64>,
    local_batch: Vec<u64>,
}

impl PerCoreIPLimiter {
    pub fn new(size: usize, init_secs: u64) -> Self {
        let mut counts = Vec::with_capacity(size);
        let mut last_reset = Vec::with_capacity(size);
        let mut local_batch = Vec::with_capacity(size);
        
        for _ in 0..size {
            counts.push(0);
            last_reset.push(init_secs);
            local_batch.push(0);
        }
        
        Self { counts, last_reset, local_batch }
    }

    #[inline]
    pub fn index(&self, ip: IpAddr) -> usize {
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        let mut h = FNV_OFFSET;
        match ip {
            IpAddr::V4(addr) => {
                for &b in &addr.octets() {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
            }
            IpAddr::V6(addr) => {
                for &b in addr.octets().iter() {
                    h ^= b as u64;
                    h = h.wrapping_mul(FNV_PRIME);
                }
            }
        }
        (h as usize) & (N_IP_BUCKETS - 1)
    }

    pub fn update_and_get(&mut self, ip: IpAddr, now_secs: u64, stale_secs: u64) -> u64 {
        let idx = self.index(ip);
        
        if now_secs.saturating_sub(self.last_reset[idx]) > stale_secs {
            self.counts[idx] = 1;
            self.last_reset[idx] = now_secs;
            self.local_batch[idx] = 0;
            return 1;
        }
        
        self.local_batch[idx] += 1;
        let entry = self.local_batch[idx];
        
        if entry >= 16 {
            self.counts[idx] += entry;
            self.local_batch[idx] = 0;
            self.counts[idx]
        } else {
            self.counts[idx] + entry
        }
    }

    pub fn update_local_batch(&mut self, ip: IpAddr, now_secs: u64, stale_secs: u64) {
        let idx = self.index(ip);
        
        if now_secs.saturating_sub(self.last_reset[idx]) > stale_secs {
            self.counts[idx] = 1;
            self.last_reset[idx] = now_secs;
            self.local_batch[idx] = 0;
            return;
        }
        
        self.local_batch[idx] += 1;
        if self.local_batch[idx] >= 32 {
            self.counts[idx] += self.local_batch[idx];
            self.local_batch[idx] = 0;
        }
    }

    pub fn cleanup_older_than(&mut self, now_secs: u64, max_age_secs: u64) {
        for i in 0..self.counts.len() {
            if now_secs.saturating_sub(self.last_reset[i]) > max_age_secs {
                self.counts[i] = 0;
            }
        }
    }
}

pub fn init_core_state(
    domains_config: HashMap<String, DomainConfig>,
    domains_stats: HashMap<String, DomainCoreStats>,
    pow_pool: crate::pow::PowVerifierPool,
    cookie_key: [u8; 32],
    http_client: Client<HttpConnector, BoxBody<Bytes, hyper::Error>>,
    backend_sem: tokio::sync::Semaphore,
    ip_limiter: PerCoreIPLimiter,
) {
    IP_BUCKET_STATE.with(|state| *state.borrow_mut() = ip_limiter);
    DOMAIN_CONFIG.with(|state| *state.borrow_mut() = domains_config);
    DOMAIN_STATS.with(|state| *state.borrow_mut() = domains_stats);
    POW_POOL.with(|state| *state.borrow_mut() = pow_pool);
    COOKIE_KEY.with(|state| *state.borrow_mut() = cookie_key);
    HTTP_CLIENT.with(|state| *state.borrow_mut() = Some(http_client));
    BACKEND_SEM.with(|state| *state.borrow_mut() = Arc::new(backend_sem));
}

pub fn cleanup_old_requests() {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    IP_BUCKET_STATE.with(|state| {
        state.borrow_mut().cleanup_older_than(now_secs, 3600);
    });
}

pub fn get_stats_snapshot() -> (u64, u64, u64) {
    let total = LOCAL_TOTAL.with(|c| c.replace(0));
    let challenged = LOCAL_CHALLENGED.with(|c| c.replace(0));
    let allowed = LOCAL_ALLOWED.with(|c| c.replace(0));
    (total, challenged, allowed)
}
