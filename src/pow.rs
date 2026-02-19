use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;

pub const POW_DIFFICULTY: u32 = 18;
pub const POW_CHALLENGE_LENGTH: usize = 32;
static NEXT_SEED: AtomicU64 = AtomicU64::new(1);

pub struct PowVerifierPool {
    _threads: usize,
}

impl PowVerifierPool {
    pub fn new(num_threads: usize, _pin_threads: bool) -> Arc<Self> {
        Arc::new(Self {
            _threads: num_threads.max(1),
        })
    }

    pub fn submit(
        &self,
        nonce: String,
        challenge_secret: String,
        difficulty_bits: usize,
    ) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let mut hasher = blake3::Hasher::new();
            hasher.update(nonce.as_bytes());
            hasher.update(challenge_secret.as_bytes());
            let hash_bytes = *hasher.finalize().as_bytes();

            let mut bits_to_check = difficulty_bits;
            let mut ok = true;
            for &b in hash_bytes.iter() {
                if bits_to_check >= 8 {
                    if b != 0 {
                        ok = false;
                        break;
                    }
                    bits_to_check -= 8;
                } else {
                    if bits_to_check == 0 {
                        break;
                    }
                    let mask: u8 = 0xFF << (8 - bits_to_check);
                    if b & mask != 0 {
                        ok = false;
                    }
                    break;
                }
            }
            let _ = tx.send(ok);
        });
        rx
    }
}

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

pub fn generate_pow_html(
    challenge_secret: &str,
    difficulty: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    let html = include_str!("pow_challenge.html");
    Ok(html
        .replace("{challenge_secret}", challenge_secret)
        .replace("{difficulty}", &difficulty.to_string()))
}
