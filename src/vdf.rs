use rand::{RngCore, rngs::OsRng};
use rsa::{BigUint, RsaPrivateKey, traits::{PrivateKeyParts, PublicKeyParts}};
use std::{collections::VecDeque, net::IpAddr, sync::{Mutex, OnceLock}, time::{Duration, Instant}};
use tokio::sync::oneshot;

pub const VDF_DIFFICULTY: u64 = 300_000;
const WIDTH: usize = 256;
const MAX_PENDING: usize = 32_768;

pub struct BrowserChallenge {
    pub modulus: String,
    pub base: String,
    pub difficulty: u64,
}

struct Params {
    modulus: BigUint,
    exponent: BigUint,
}

struct Pending {
    answer: [u8; WIDTH],
    ip: IpAddr,
    domain: String,
    expires: Instant,
}

static PARAMS: OnceLock<Params> = OnceLock::new();
static PENDING: OnceLock<Mutex<VecDeque<Pending>>> = OnceLock::new();

fn params() -> &'static Params {
    PARAMS.get_or_init(|| Params::generate(2048, VDF_DIFFICULTY))
}

fn pending() -> &'static Mutex<VecDeque<Pending>> {
    PENDING.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_PENDING)))
}

pub fn init() {
    let _ = params();
}

impl Params {
    fn generate(bits: usize, difficulty: u64) -> Self {
        let key = RsaPrivateKey::new(&mut OsRng, bits).expect("RSA key generation failed");
        let one = BigUint::from(1u8);
        let phi = (key.primes()[0].clone() - &one) * (key.primes()[1].clone() - &one);
        let exponent = BigUint::from(2u8).modpow(&BigUint::from(difficulty), &phi);
        Self { modulus: key.n().clone(), exponent }
    }

    fn issue(&self, difficulty: u64) -> (BrowserChallenge, [u8; WIDTH]) {
        let base = loop {
            let mut bytes = [0u8; WIDTH];
            OsRng.fill_bytes(&mut bytes);
            let value = BigUint::from_bytes_be(&bytes) % (&self.modulus - BigUint::from(3u8)) + BigUint::from(2u8);
            if gcd(value.clone(), self.modulus.clone()) == BigUint::from(1u8) { break value; }
        };
        let answer = fixed(&base.modpow(&self.exponent, &self.modulus).to_bytes_be());
        (BrowserChallenge {
            modulus: encode(&fixed(&self.modulus.to_bytes_be())),
            base: encode(&fixed(&base.to_bytes_be())),
            difficulty,
        }, answer)
    }
}

fn gcd(mut left: BigUint, mut right: BigUint) -> BigUint {
    while right != BigUint::from(0u8) {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    left
}

fn fixed(bytes: &[u8]) -> [u8; WIDTH] {
    let mut out = [0u8; WIDTH];
    out[WIDTH - bytes.len()..].copy_from_slice(bytes);
    out
}

fn encode(bytes: &[u8; WIDTH]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(WIDTH * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

fn decode(value: &str) -> Option<[u8; WIDTH]> {
    if value.len() != WIDTH * 2 { return None; }
    let mut out = [0u8; WIDTH];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

fn digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub fn issue(ip: IpAddr, domain: String) -> BrowserChallenge {
    let (challenge, answer) = params().issue(VDF_DIFFICULTY);
    let mut queue = pending().lock().unwrap_or_else(|error| error.into_inner());
    let now = Instant::now();
    while queue.front().is_some_and(|item| item.expires <= now) { queue.pop_front(); }
    if queue.len() == MAX_PENDING { queue.pop_front(); }
    queue.push_back(Pending {
        answer,
        ip,
        domain,
        expires: now + Duration::from_secs(300),
    });
    challenge
}

pub fn submit(answer: String, ip: IpAddr, domain: String) -> oneshot::Receiver<bool> {
    let (sender, receiver) = oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let verified = decode(&answer).is_some_and(|answer| {
            let mut queue = pending().lock().unwrap_or_else(|error| error.into_inner());
            let now = Instant::now();
            queue.retain(|item| item.expires > now);
            queue.iter().position(|item| {
                item.answer == answer && item.ip == ip && item.domain == domain
            }).is_some_and(|index| queue.remove(index).is_some())
        });
        let _ = sender.send(verified);
    });
    receiver
}

pub fn generate_vdf_html(challenge: &BrowserChallenge) -> Result<String, Box<dyn std::error::Error>> {
    let html = include_str!("vdf_challenge.html")
        .replace("{modulus}", &challenge.modulus)
        .replace("{base}", &challenge.base)
        .replace("{difficulty}", &challenge.difficulty.to_string());
    if html.len() > 2048 { return Err("challenge exceeds 2 KB".into()); }
    Ok(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_matches_sequential_solution() {
        let difficulty = 32;
        let params = Params::generate(1024, difficulty);
        let (challenge, expected) = params.issue(difficulty);
        let modulus = BigUint::parse_bytes(challenge.modulus.as_bytes(), 16).unwrap();
        let mut answer = BigUint::parse_bytes(challenge.base.as_bytes(), 16).unwrap();
        for _ in 0..difficulty { answer = (&answer * &answer) % &modulus; }
        assert_eq!(fixed(&answer.to_bytes_be()), expected);
    }

    #[test]
    fn challenge_html_stays_under_two_kilobytes() {
        let challenge = BrowserChallenge {
            modulus: "f".repeat(WIDTH * 2),
            base: "e".repeat(WIDTH * 2),
            difficulty: VDF_DIFFICULTY,
        };
        assert!(generate_vdf_html(&challenge).unwrap().len() <= 2048);
    }

    #[tokio::test]
    async fn answer_is_bound_and_single_use() {
        let answer = [173u8; WIDTH];
        let encoded = encode(&answer);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        pending().lock().unwrap().push_back(Pending {
            answer,
            ip,
            domain: "example.com".to_owned(),
            expires: Instant::now() + Duration::from_secs(30),
        });
        assert!(!submit(encoded.clone(), "192.0.2.2".parse().unwrap(), "example.com".to_owned()).await.unwrap());
        assert!(!submit(encoded.clone(), ip, "other.example".to_owned()).await.unwrap());
        assert!(submit(encoded.clone(), ip, "example.com".to_owned()).await.unwrap());
        assert!(!submit(encoded, ip, "example.com".to_owned()).await.unwrap());
    }
}
