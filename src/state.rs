use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;

pub const N_IP_BUCKETS: usize = 64 * 1024;

pub struct IPBuckets {
    pub counts: Box<[AtomicU64]>,
    pub last_reset_secs: Box<[AtomicU64]>,
}

impl IPBuckets {
    pub fn new(size: usize, init_secs: u64) -> Self {
        let counts: Box<[AtomicU64]> = (0..size).map(|_| AtomicU64::new(0)).collect();
        let last_reset_secs: Box<[AtomicU64]> =
            (0..size).map(|_| AtomicU64::new(init_secs)).collect();

        Self {
            counts,
            last_reset_secs,
        }
    }

    #[inline]
    pub fn index(&self, ip: IpAddr) -> usize {
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        let mut h = FNV_OFFSET;
        match ip {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                h ^= octets[0] as u64;
                h = h.wrapping_mul(FNV_PRIME);
                h ^= octets[1] as u64;
                h = h.wrapping_mul(FNV_PRIME);
                h ^= octets[2] as u64;
                h = h.wrapping_mul(FNV_PRIME);
                h ^= octets[3] as u64;
                h = h.wrapping_mul(FNV_PRIME);
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

    pub fn cleanup_older_than(&self, now_secs: u64, max_age_secs: u64) {
        for i in 0..self.counts.len() {
            let last = self.last_reset_secs[i].load(Ordering::Relaxed);
            if now_secs.saturating_sub(last) > max_age_secs {
                self.counts[i].store(0, Ordering::Relaxed);
            }
        }
    }
}

pub struct DomainRuntime {
    pub backend_base: String,
    pub cloudflare_mode: bool,
    pub total_requests: AtomicU64,
    pub bypassed_requests: AtomicU64,
    #[allow(dead_code)]
    pub blocked_requests: AtomicU64,
    pub last_reset_secs: AtomicU64,
    pub last_pow_success: AtomicU64,
    pub stage: Arc<AtomicU8>,
}

pub struct AppState {
    pub domains: Arc<std::collections::HashMap<String, Arc<DomainRuntime>>>,
    pub ip_buckets: IPBuckets,
    pub pow_pool: Arc<crate::pow::PowVerifierPool>,
    pub cookie_key: [u8; 32],
    pub local_ip_acc: Box<[AtomicU64]>,
    pub global_total_requests: Arc<AtomicU64>,
    pub global_challenged_requests: Arc<AtomicU64>,
    pub global_allowed_requests: Arc<AtomicU64>,
    pub http_client: Client<HttpConnector, BoxBody<Bytes, hyper::Error>>,
    pub backend_sem: Arc<Semaphore>,
}

impl AppState {
    pub fn cleanup_old_requests(&self) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.ip_buckets.cleanup_older_than(now_secs, 3600);
    }

    #[inline]
    pub fn ip_update_and_get_batched(&self, ip: IpAddr, now_secs: u64, stale_secs: u64) -> u64 {
        let idx = self.ip_buckets.index(ip);
        let last = self.ip_buckets.last_reset_secs[idx].load(Ordering::Relaxed);

        if now_secs.saturating_sub(last) > stale_secs {
            self.ip_buckets.counts[idx].store(1, Ordering::Relaxed);
            self.ip_buckets.last_reset_secs[idx].store(now_secs, Ordering::Relaxed);
            self.local_ip_acc[idx].store(0, Ordering::Relaxed);
            1
        } else {
            let entry = self.local_ip_acc[idx].fetch_add(1, Ordering::Relaxed) + 1;
            if entry >= 16 {
                let prev = self.ip_buckets.counts[idx].load(Ordering::Relaxed);
                let total = prev.saturating_add(entry);
                self.ip_buckets.counts[idx].store(total, Ordering::Relaxed);
                self.local_ip_acc[idx].store(0, Ordering::Relaxed);
                total
            } else {
                self.ip_buckets.counts[idx]
                    .load(Ordering::Relaxed)
                    .saturating_add(entry)
            }
        }
    }

    #[inline]
    pub fn ip_update_local_batch(&self, ip: IpAddr, now_secs: u64, stale_secs: u64) {
        let idx = self.ip_buckets.index(ip);
        let last = self.ip_buckets.last_reset_secs[idx].load(Ordering::Relaxed);

        if now_secs.saturating_sub(last) > stale_secs {
            self.ip_buckets.counts[idx].store(1, Ordering::Relaxed);
            self.ip_buckets.last_reset_secs[idx].store(now_secs, Ordering::Relaxed);
            self.local_ip_acc[idx].store(0, Ordering::Relaxed);
        } else {
            let entry = self.local_ip_acc[idx].fetch_add(1, Ordering::Relaxed) + 1;
            if entry >= 32 {
                let prev = self.ip_buckets.counts[idx].load(Ordering::Relaxed);
                let total = prev.saturating_add(entry);
                self.ip_buckets.counts[idx].store(total, Ordering::Relaxed);
                self.local_ip_acc[idx].store(0, Ordering::Relaxed);
            }
        }
    }
}
