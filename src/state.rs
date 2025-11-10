use crate::config::DomainSettings;
use awc::Client;
use dashmap::DashMap;
use log::debug;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/*
Use 64K buckets to ensure predictable memory usage and good cache locality.
This size balances distribution and cache efficiency which is faster in memory.
*/
pub const N_IP_BUCKETS: usize = 64 * 1024;

pub struct IPBuckets {
    pub counts: Box<[AtomicU64]>,
    pub last_reset_secs: Box<[AtomicU64]>,
}

impl IPBuckets {
    pub fn new(size: usize, init_secs: u64) -> Self {
        let mut counts_vec: Vec<AtomicU64> = Vec::with_capacity(size);
        let mut reset_vec: Vec<AtomicU64> = Vec::with_capacity(size);
        for _ in 0..size {
            counts_vec.push(AtomicU64::new(0));
            reset_vec.push(AtomicU64::new(init_secs));
        }
        Self {
            counts: counts_vec.into_boxed_slice(),
            last_reset_secs: reset_vec.into_boxed_slice(),
        }
    }

    #[inline]
    // FNV-1a hash for speed and locality.
    pub fn index(&self, ip: &str) -> usize {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in ip.as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        (h as usize) & (self.counts.len() - 1)
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

pub struct AppState {
    pub domains: DashMap<String, DomainSettings>,
    pub ip_buckets: IPBuckets,
    pub stages: Arc<DashMap<String, Arc<AtomicU8>>>,
    pub pow_pool: Arc<crate::pow::PowVerifierPool>,
    pub cookie_key: [u8; 32],
    pub local_ip_acc: RefCell<Vec<u64>>, 
    pub global_total_requests: Arc<AtomicU64>,
    pub global_challenged_requests: Arc<AtomicU64>,
    pub global_allowed_requests: Arc<AtomicU64>,
    pub http_client: Client,
}

impl AppState {
    pub fn cleanup_old_requests(&self) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.ip_buckets.cleanup_older_than(now_secs, 3600);
        debug!("Cleaned up old request records");
    }

    #[inline]
    pub fn ip_update_and_get_batched(&self, ip: &str, now_secs: u64, stale_secs: u64) -> u64 {
        let idx = self.ip_buckets.index(ip);
        let last = self.ip_buckets.last_reset_secs[idx].load(Ordering::Relaxed);
        let mut acc = self.local_ip_acc.borrow_mut();
        let entry = &mut acc[idx];
        if now_secs.saturating_sub(last) > stale_secs {
            // stale: reset global and local
            self.ip_buckets.counts[idx].store(1, Ordering::Relaxed);
            self.ip_buckets.last_reset_secs[idx].store(now_secs, Ordering::Relaxed);
            *entry = 0;
            1
        } else {
            *entry = entry.saturating_add(1);
            let prev = self.ip_buckets.counts[idx].load(Ordering::Relaxed);
            let total = prev.saturating_add(*entry);
            // flush when batch reaches threshold to keep global counters reasonably fresh
            if *entry >= 16 {
                self.ip_buckets.counts[idx].store(total, Ordering::Relaxed);
                *entry = 0;
            }
            total
        }
    }

    #[inline]
    pub fn ip_update_local_batch(&self, ip: &str, now_secs: u64, stale_secs: u64) {
        let idx = self.ip_buckets.index(ip);
        let last = self.ip_buckets.last_reset_secs[idx].load(Ordering::Relaxed);
        let mut acc = self.local_ip_acc.borrow_mut();
        let entry = &mut acc[idx];
        if now_secs.saturating_sub(last) > stale_secs {
            self.ip_buckets.counts[idx].store(1, Ordering::Relaxed);
            self.ip_buckets.last_reset_secs[idx].store(now_secs, Ordering::Relaxed);
            *entry = 0;
        } else {
            *entry = entry.saturating_add(1);
            if *entry >= 32 {
                let prev = self.ip_buckets.counts[idx].load(Ordering::Relaxed);
                let total = prev.saturating_add(*entry);
                self.ip_buckets.counts[idx].store(total, Ordering::Relaxed);
                *entry = 0;
            }
        }
    }
}