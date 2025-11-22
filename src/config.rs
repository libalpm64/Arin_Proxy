use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

#[derive(Serialize, Deserialize)]
pub struct DomainSettings {
    pub backend: String,
    pub cloudflare_mode: bool,
    #[serde(default)]
    pub use_https: bool,
    #[serde(default)]
    pub stage: Option<u8>,
    #[serde(skip)]
    pub backend_base: String,
    #[serde(skip)]
    pub total_requests: AtomicU64,
    #[serde(skip)]
    pub bypassed_requests: AtomicU64,
    #[serde(skip)]
    pub blocked_requests: AtomicU64,
    #[serde(skip)]
    pub last_reset: Option<Instant>,
    #[serde(skip)]
    pub current_stage: u8,
    #[serde(skip)]
    pub last_pow_success: Option<u64>,
    #[serde(skip)]
    pub stage_ptr: Option<Arc<AtomicU8>>,
}

impl Default for DomainSettings {
    fn default() -> Self {
        Self {
            backend: String::new(),
            cloudflare_mode: false,
            use_https: false,
            stage: None,
            backend_base: String::new(),
            total_requests: AtomicU64::new(0),
            bypassed_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            last_reset: None,
            current_stage: 0,
            last_pow_success: None,
            stage_ptr: None,
        }
    }
}

impl Clone for DomainSettings {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            cloudflare_mode: self.cloudflare_mode,
            use_https: self.use_https,
            stage: self.stage,
            backend_base: self.backend_base.clone(),
            total_requests: AtomicU64::new(self.total_requests.load(Ordering::Relaxed)),
            bypassed_requests: AtomicU64::new(self.bypassed_requests.load(Ordering::Relaxed)),
            blocked_requests: AtomicU64::new(self.blocked_requests.load(Ordering::Relaxed)),
            last_reset: self.last_reset,
            current_stage: self.current_stage,
            last_pow_success: self.last_pow_success,
            stage_ptr: self.stage_ptr.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct AllocatorOpts {
    #[serde(default)]
    pub large_os_pages: bool,
    #[serde(default)]
    pub eager_commit: bool,
    #[serde(default)]
    pub verbose: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub struct RuntimeOpts {
    #[serde(default)]
    pub pin_workers: bool,
    #[serde(default)]
    pub pin_pow_threads: bool,
    #[serde(default)]
    pub client_pool_limit: Option<usize>,
    #[serde(default)]
    pub client_connect_timeout_ms: Option<u64>,
    #[serde(default)]
    pub client_keep_alive_secs: Option<u64>,
    #[serde(default)]
    pub client_lifetime_secs: Option<u64>,
    #[serde(default)]
    pub resolve_dns_startup: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub domains: HashMap<String, DomainSettings>,
    pub cookie_secret: String,
    #[serde(default)]
    pub allocator: AllocatorOpts,
    #[serde(default)]
    pub runtime: RuntimeOpts,
}