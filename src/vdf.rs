use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use rand::{RngCore, rngs::OsRng};
use rsa::{BigUint, RsaPrivateKey, traits::{PrivateKeyParts, PublicKeyParts}};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, sync_channel},
    },
    time::Duration,
};

pub const VDF_DIFFICULTY: u64 = 1 << 22;
const WIDTH: usize = 256;
const SEED_WIDTH: usize = 32;
const ID_WIDTH: usize = 16;
const NODE_WIDTH: usize = 8;
const NONCE_WIDTH: usize = 24;
const TAG_WIDTH: usize = 16;
const META_WIDTH: usize = 1 + NODE_WIDTH + ID_WIDTH + SEED_WIDTH + 8 + 8 + 32 + 32;
const TICKET_WIDTH: usize = META_WIDTH + NONCE_WIDTH + WIDTH + TAG_WIDTH;
const POOL_CAPACITY: usize = 10_000;
const POOL_PREWARM: usize = 1_024;
const MAX_ACTIVE: usize = 65_536;
const MAX_GRANTS: usize = 65_536;
const TICKET_TTL_SECS: u64 = 30;
const GRANT_TTL_SECS: u64 = 10;

pub struct BrowserChallenge {
    pub modulus: String,
    pub seed: String,
    pub difficulty: u64,
    pub ticket: String,
}

struct Params {
    modulus: BigUint,
    p: BigUint,
    q: BigUint,
    exponent_p: BigUint,
    exponent_q: BigUint,
    q_inverse: BigUint,
    seal_key: [u8; 32],
    node_id: [u8; NODE_WIDTH],
}

struct Capsule {
    id: [u8; ID_WIDTH],
    seed: [u8; SEED_WIDTH],
    endpoint: [u8; WIDTH],
}

struct CapsulePool {
    receiver: Mutex<Receiver<Capsule>>,
}

struct Grant {
    ip: IpAddr,
    request_digest: [u8; 32],
    expires: u64,
}

static PARAMS: OnceLock<Params> = OnceLock::new();
static POOL: OnceLock<CapsulePool> = OnceLock::new();
static ACTIVE: OnceLock<Mutex<HashMap<[u8; ID_WIDTH], u64>>> = OnceLock::new();
static GRANTS: OnceLock<Mutex<HashMap<[u8; ID_WIDTH], Grant>>> = OnceLock::new();

fn params() -> &'static Params {
    PARAMS.get().expect("VDF is not initialized")
}

fn active() -> &'static Mutex<HashMap<[u8; ID_WIDTH], u64>> {
    ACTIVE.get_or_init(|| Mutex::new(HashMap::with_capacity(MAX_ACTIVE)))
}

fn grants() -> &'static Mutex<HashMap<[u8; ID_WIDTH], Grant>> {
    GRANTS.get_or_init(|| Mutex::new(HashMap::with_capacity(MAX_GRANTS)))
}

pub fn init() {
    let initialized = PARAMS.get_or_init(|| Params::generate(2048, VDF_DIFFICULTY));
    let _ = active();
    let _ = grants();
    POOL.get_or_init(|| {
        let (sender, receiver) = sync_channel(POOL_CAPACITY);
        let generated = Arc::new(AtomicUsize::new(0));
        let workers = num_cpus::get().clamp(1, 8);
        for _ in 0..workers {
            let sender = sender.clone();
            let generated = generated.clone();
            std::thread::spawn(move || {
                loop {
                    if sender.send(params().capsule()).is_err() {
                        break;
                    }
                    generated.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
        drop(sender);
        while generated.load(Ordering::Relaxed) < POOL_PREWARM {
            std::thread::sleep(Duration::from_millis(1));
        }
        let _ = initialized;
        CapsulePool { receiver: Mutex::new(receiver) }
    });
}

impl Params {
    fn generate(bits: usize, difficulty: u64) -> Self {
        let key = RsaPrivateKey::new(&mut OsRng, bits).expect("RSA key generation failed");
        let one = BigUint::from(1u8);
        let p = key.primes()[0].clone();
        let q = key.primes()[1].clone();
        let p_order = &p - &one;
        let q_order = &q - &one;
        let lambda = (&p_order / gcd(p_order.clone(), q_order.clone())) * &q_order;
        let exponent = BigUint::from(2u8).modpow(&BigUint::from(difficulty), &lambda);
        let exponent_p = &exponent % &p_order;
        let exponent_q = &exponent % &q_order;
        let q_inverse = key.crt_coefficient().expect("RSA CRT coefficient failed");
        let mut seal_key = [0u8; 32];
        let mut node_id = [0u8; NODE_WIDTH];
        OsRng.fill_bytes(&mut seal_key);
        OsRng.fill_bytes(&mut node_id);
        Self {
            modulus: key.n().clone(),
            p,
            q,
            exponent_p,
            exponent_q,
            q_inverse,
            seal_key,
            node_id,
        }
    }

    fn capsule(&self) -> Capsule {
        loop {
            let mut id = [0u8; ID_WIDTH];
            let mut seed = [0u8; SEED_WIDTH];
            OsRng.fill_bytes(&mut id);
            OsRng.fill_bytes(&mut seed);
            let hash = BigUint::from_bytes_be(blake3::hash(&seed).as_bytes());
            if hash != BigUint::from(0u8)
                && gcd(hash.clone(), self.modulus.clone()) == BigUint::from(1u8)
            {
                let x = (&hash * &hash) % &self.modulus;
                let endpoint_p = x.modpow(&self.exponent_p, &self.p);
                let endpoint_q = x.modpow(&self.exponent_q, &self.q);
                let endpoint_q_p = &endpoint_q % &self.p;
                let delta = (&endpoint_p + &self.p - endpoint_q_p) % &self.p;
                let coefficient = (delta * &self.q_inverse) % &self.p;
                let endpoint = fixed(&(endpoint_q + &self.q * coefficient).to_bytes_be());
                return Capsule { id, seed, endpoint };
            }
        }
    }

    fn ticket(
        &self,
        capsule: &Capsule,
        request_digest: [u8; 32],
        session_binding: [u8; 32],
        now_secs: u64,
    ) -> String {
        let mut metadata = Vec::with_capacity(META_WIDTH);
        metadata.push(1);
        metadata.extend_from_slice(&self.node_id);
        metadata.extend_from_slice(&capsule.id);
        metadata.extend_from_slice(&capsule.seed);
        metadata.extend_from_slice(&VDF_DIFFICULTY.to_be_bytes());
        metadata.extend_from_slice(&(now_secs + TICKET_TTL_SECS).to_be_bytes());
        metadata.extend_from_slice(&request_digest);
        metadata.extend_from_slice(&session_binding);
        let mut nonce = [0u8; NONCE_WIDTH];
        OsRng.fill_bytes(&mut nonce);
        let mut sealed = capsule.endpoint.to_vec();
        XChaCha20Poly1305::new((&self.seal_key).into())
            .encrypt_in_place(XNonce::from_slice(&nonce), &metadata, &mut sealed)
            .expect("VDF sealing failed");
        let mut ticket = Vec::with_capacity(TICKET_WIDTH);
        ticket.extend_from_slice(&metadata);
        ticket.extend_from_slice(&nonce);
        ticket.extend_from_slice(&sealed);
        encode64(&ticket)
    }

    fn open(
        &self,
        ticket: &str,
        answer: &str,
        session_binding: [u8; 32],
        now_secs: u64,
    ) -> Option<([u8; ID_WIDTH], [u8; 32], u64)> {
        let ticket = decode64(ticket)?;
        let answer = decode64(answer)?;
        if ticket.len() != TICKET_WIDTH || answer.len() != WIDTH {
            return None;
        }
        let metadata = &ticket[..META_WIDTH];
        if metadata[0] != 1 || !constant_eq(&metadata[1..1 + NODE_WIDTH], &self.node_id) {
            return None;
        }
        let mut id = [0u8; ID_WIDTH];
        id.copy_from_slice(&metadata[1 + NODE_WIDTH..1 + NODE_WIDTH + ID_WIDTH]);
        let difficulty_offset = 1 + NODE_WIDTH + ID_WIDTH + SEED_WIDTH;
        let difficulty = u64::from_be_bytes(metadata[difficulty_offset..difficulty_offset + 8].try_into().ok()?);
        let expiry = u64::from_be_bytes(metadata[difficulty_offset + 8..difficulty_offset + 16].try_into().ok()?);
        if difficulty != VDF_DIFFICULTY || expiry < now_secs {
            return None;
        }
        let request_offset = difficulty_offset + 16;
        let mut request_digest = [0u8; 32];
        request_digest.copy_from_slice(&metadata[request_offset..request_offset + 32]);
        if !constant_eq(&metadata[request_offset + 32..request_offset + 64], &session_binding) {
            return None;
        }
        let nonce = &ticket[META_WIDTH..META_WIDTH + NONCE_WIDTH];
        let mut endpoint = ticket[META_WIDTH + NONCE_WIDTH..].to_vec();
        XChaCha20Poly1305::new((&self.seal_key).into())
            .decrypt_in_place(XNonce::from_slice(nonce), metadata, &mut endpoint)
            .ok()?;
        if endpoint.len() != WIDTH
            || BigUint::from_bytes_be(&answer) >= self.modulus
            || !constant_eq(&endpoint, &answer)
        {
            return None;
        }
        Some((id, request_digest, expiry))
    }
}

fn next_capsule() -> Capsule {
    POOL.get()
        .and_then(|pool| pool.receiver.lock().unwrap_or_else(|error| error.into_inner()).try_recv().ok())
        .unwrap_or_else(|| params().capsule())
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

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

fn encode64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let value = (bytes[index] as u32) << 16
            | (bytes[index + 1] as u32) << 8
            | bytes[index + 2] as u32;
        out.push(TABLE[(value >> 18) as usize] as char);
        out.push(TABLE[((value >> 12) & 63) as usize] as char);
        out.push(TABLE[((value >> 6) & 63) as usize] as char);
        out.push(TABLE[(value & 63) as usize] as char);
        index += 3;
    }
    if bytes.len() - index == 1 {
        let value = (bytes[index] as u32) << 16;
        out.push(TABLE[(value >> 18) as usize] as char);
        out.push(TABLE[((value >> 12) & 63) as usize] as char);
    } else if bytes.len() - index == 2 {
        let value = (bytes[index] as u32) << 16 | (bytes[index + 1] as u32) << 8;
        out.push(TABLE[(value >> 18) as usize] as char);
        out.push(TABLE[((value >> 12) & 63) as usize] as char);
        out.push(TABLE[((value >> 6) & 63) as usize] as char);
    }
    out
}

fn decode64(value: &str) -> Option<Vec<u8>> {
    if value.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = accumulator << 6 | digit as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1u32 << bits).wrapping_sub(1);
        }
    }
    if accumulator != 0 || encode64(&out) != value {
        return None;
    }
    Some(out)
}

fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for index in 0..left.len() {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

pub fn request_digest(method: &str, host: &str, path: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(method.as_bytes());
    hasher.update(&[0]);
    hasher.update(host.as_bytes());
    hasher.update(&[0]);
    hasher.update(path.as_bytes());
    hasher.update(&[0]);
    hasher.update(blake3::hash(&[]).as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn session_binding(ip: IpAddr, cookie: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    match ip {
        IpAddr::V4(address) => hasher.update(&address.octets()),
        IpAddr::V6(address) => hasher.update(&address.octets()),
    };
    hasher.update(&[0]);
    hasher.update(cookie.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn issue(
    request_digest: [u8; 32],
    session_binding: [u8; 32],
    now_secs: u64,
) -> Option<BrowserChallenge> {
    let capsule = next_capsule();
    let mut active = active().lock().unwrap_or_else(|error| error.into_inner());
    active.retain(|_, expiry| *expiry >= now_secs);
    if active.len() >= MAX_ACTIVE || active.insert(capsule.id, now_secs + TICKET_TTL_SECS).is_some() {
        return None;
    }
    drop(active);
    let ticket = params().ticket(&capsule, request_digest, session_binding, now_secs);
    Some(BrowserChallenge {
        modulus: encode_hex(&fixed(&params().modulus.to_bytes_be())),
        seed: encode_hex(&capsule.seed),
        difficulty: VDF_DIFFICULTY,
        ticket,
    })
}

pub fn submit(
    ticket: &str,
    answer: &str,
    ip: IpAddr,
    session_binding: [u8; 32],
    backend_available: bool,
    now_secs: u64,
) -> Option<String> {
    let (id, request_digest, expiry) = params().open(ticket, answer, session_binding, now_secs)?;
    let mut active = active().lock().unwrap_or_else(|error| error.into_inner());
    active.retain(|_, item_expiry| *item_expiry >= now_secs);
    active.remove(&id)?;
    drop(active);
    if !backend_available {
        return None;
    }
    let mut token = [0u8; ID_WIDTH];
    OsRng.fill_bytes(&mut token);
    let mut grants = grants().lock().unwrap_or_else(|error| error.into_inner());
    grants.retain(|_, grant| grant.expires >= now_secs);
    if grants.len() >= MAX_GRANTS {
        return None;
    }
    grants.insert(token, Grant {
        ip,
        request_digest,
        expires: expiry.min(now_secs + GRANT_TTL_SECS),
    });
    Some(encode64(&token))
}

pub fn consume_grant(
    token: &str,
    ip: IpAddr,
    request_digest: [u8; 32],
    now_secs: u64,
) -> bool {
    let Some(bytes) = decode64(token) else { return false };
    let Ok(token) = <[u8; ID_WIDTH]>::try_from(bytes.as_slice()) else { return false };
    let mut grants = grants().lock().unwrap_or_else(|error| error.into_inner());
    grants.retain(|_, grant| grant.expires >= now_secs);
    grants.remove(&token).is_some_and(|grant| {
        grant.ip == ip
            && grant.expires >= now_secs
            && constant_eq(&grant.request_digest, &request_digest)
    })
}

pub fn generate_vdf_html(challenge: &BrowserChallenge) -> Result<String, Box<dyn std::error::Error>> {
    let html = include_str!("vdf_challenge.html")
        .replace("{modulus}", &challenge.modulus)
        .replace("{seed}", &challenge.seed)
        .replace("{difficulty}", &challenge.difficulty.to_string())
        .replace("{ticket}", &challenge.ticket);
    if html.len() > 2048 {
        return Err("challenge exceeds 2 KB".into());
    }
    Ok(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_matches_sequential_solution() {
        let difficulty = 32;
        let params = Params::generate(1024, difficulty);
        let capsule = params.capsule();
        let hash = BigUint::from_bytes_be(blake3::hash(&capsule.seed).as_bytes());
        let mut answer = (&hash * &hash) % &params.modulus;
        for _ in 0..difficulty {
            answer = (&answer * &answer) % &params.modulus;
        }
        assert_eq!(fixed(&answer.to_bytes_be()), capsule.endpoint);
    }

    #[test]
    fn sealed_ticket_is_bound_and_canonical() {
        let params = Params::generate(1024, 32);
        let capsule = params.capsule();
        let request = [17u8; 32];
        let session = [29u8; 32];
        let ticket = params.ticket(&capsule, request, session, 100);
        let answer = encode64(&capsule.endpoint);
        let opened = params.open(&ticket, &answer, session, 100).unwrap();
        assert_eq!(opened.0, capsule.id);
        assert_eq!(opened.1, request);
        assert!(params.open(&ticket, &answer, [30u8; 32], 100).is_none());
        assert!(params.open(&ticket, &answer, session, 131).is_none());
        assert!(params.open(&ticket, &format!("A{}", answer), session, 100).is_none());
    }

    #[test]
    fn challenge_html_stays_under_two_kilobytes() {
        let challenge = BrowserChallenge {
            modulus: "f".repeat(WIDTH * 2),
            seed: "e".repeat(SEED_WIDTH * 2),
            difficulty: VDF_DIFFICULTY,
            ticket: "a".repeat((TICKET_WIDTH * 4 + 2) / 3),
        };
        assert!(generate_vdf_html(&challenge).unwrap().len() <= 2048);
    }

    #[test]
    #[ignore]
    fn benchmark_private_verifier() {
        let params = Params::generate(2048, VDF_DIFFICULTY);
        let start = std::time::Instant::now();
        let capsules: Vec<_> = (0..1000).map(|_| params.capsule()).collect();
        let generation = start.elapsed();
        let session = [31u8; 32];
        let tickets: Vec<_> = capsules.iter().enumerate().map(|(index, capsule)| {
            let request = blake3::hash(&index.to_be_bytes());
            let ticket = params.ticket(capsule, *request.as_bytes(), session, 100);
            (ticket, encode64(&capsule.endpoint))
        }).collect();
        let start = std::time::Instant::now();
        for (ticket, answer) in &tickets {
            assert!(params.open(ticket, answer, session, 100).is_some());
        }
        let verification = start.elapsed();
        eprintln!(
            "capsules={} generation_ns_each={} verification_ns_each={}",
            capsules.len(),
            generation.as_nanos() / capsules.len() as u128,
            verification.as_nanos() / capsules.len() as u128,
        );
    }

    #[test]
    #[ignore]
    fn benchmark_native_solver() {
        let params = Params::generate(2048, VDF_DIFFICULTY);
        let capsule = params.capsule();
        let hash = BigUint::from_bytes_be(blake3::hash(&capsule.seed).as_bytes());
        let mut answer = (&hash * &hash) % &params.modulus;
        let start = std::time::Instant::now();
        for _ in 0..VDF_DIFFICULTY {
            answer = (&answer * &answer) % &params.modulus;
        }
        let elapsed = start.elapsed();
        assert_eq!(fixed(&answer.to_bytes_be()), capsule.endpoint);
        eprintln!(
            "squarings={} elapsed_ms={} squarings_per_second={}",
            VDF_DIFFICULTY,
            elapsed.as_millis(),
            VDF_DIFFICULTY as u128 * 1000 / elapsed.as_millis().max(1),
        );
    }
}
