use crate::blake3;
use crossbeam_channel::{unbounded, Sender};
use std::sync::Arc;
use tokio::sync::oneshot;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask};

pub const POW_DIFFICULTY: u32 = 18;
pub const POW_CHALLENGE_LENGTH: usize = 32;
static NEXT_SEED: AtomicU64 = AtomicU64::new(1);

struct PowJob {
    nonce: String,
    challenge_secret: String,
    difficulty_bits: usize,
    tx: oneshot::Sender<bool>,
}

pub struct PowVerifierPool {
    tx: Sender<PowJob>,
}

impl PowVerifierPool {
    pub fn new(num_threads: usize, pin_threads: bool) -> Arc<Self> {
        let (tx, rx) = unbounded::<PowJob>();
        let n_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        for i in 0..num_threads.max(1) {
            let rx_cl = rx.clone();
            let idx = i % n_cpus;
            std::thread::spawn(move || {
                #[cfg(target_os = "windows")]
                {
                    if pin_threads {
                        unsafe {
                            let _ = SetThreadAffinityMask(GetCurrentThread(), (1usize << idx) as usize);
                        }
                    }
                }
                loop {
                    match rx_cl.recv() {
                        Ok(job) => {
                            let mut hasher = blake3::Hasher::new();
                            hasher.update(job.nonce.as_bytes());
                            hasher.update(job.challenge_secret.as_bytes());
                            let hash_bytes = hasher.finalize().as_bytes().to_owned();
                            let mut bits_to_check = job.difficulty_bits;
                            let mut ok = true;
                            for &b in hash_bytes.iter() {
                                if bits_to_check >= 8 {
                                    if b != 0 { ok = false; break; }
                                    bits_to_check -= 8;
                                } else {
                                    if bits_to_check == 0 { break; }
                                    let mask: u8 = 0xFF << (8 - bits_to_check);
                                    if b & mask != 0 { ok = false; }
                                    break;
                                }
                            }
                            let _ = job.tx.send(ok);
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        Arc::new(Self { tx })
    }

    pub fn submit(&self, nonce: String, challenge_secret: String, difficulty_bits: usize) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(PowJob { nonce, challenge_secret, difficulty_bits, tx });
        rx
    }
}

// Generate a secret used for the PoW challenge
pub fn generate_challenge_secret() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seed = NEXT_SEED.fetch_add(1, Ordering::Relaxed);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&now_nanos.to_be_bytes());
    hasher.update(&seed.to_be_bytes());
    let bytes = hasher.finalize();
    let raw = bytes.as_bytes();
    let mut out = String::with_capacity(POW_CHALLENGE_LENGTH);
    for i in 0..POW_CHALLENGE_LENGTH {
        let idx = raw[i % raw.len()] as usize % CHARSET.len();
        out.push(CHARSET[idx] as char);
    }
    out
}

pub fn generate_pow_html(challenge_secret: &str, difficulty: u32) -> Result<String, Box<dyn std::error::Error>> {
    let html = include_str!("pow_challenge.html");
    Ok(html.replace("{challenge_secret}", challenge_secret)
        .replace("{difficulty}", &difficulty.to_string()))
}