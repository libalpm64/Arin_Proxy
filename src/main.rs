mod config;
mod state;
mod pow;
mod blake3;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use may_minihttp::{HttpServer, HttpService, Request, Response};
use std::net::TcpStream;
use simd_json;

use log::{info, error};

use crate::config::{Config, DomainSettings};
use crate::state::{AppState, IPBuckets, N_IP_BUCKETS};
use crate::pow::{PowVerifierPool, generate_challenge_secret, POW_DIFFICULTY};

fn main() -> std::io::Result<()> {
    // Initialize logging so info!/error! messages are visible without RUST_LOG set
    // Commented out -> Env_logger adds extra overhead.
    //env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
    //    .format_timestamp_secs()
    //    .init();
    info!("Starting Arin Proxy");
    info!("Loading configuration from config.json");
    let mut cfg_bytes = match std::fs::read("config.json") {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to open config.json: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("config.json not found: {}", e)));
        }
    };
    let config: Config = match simd_json::serde::from_slice(&mut cfg_bytes) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to parse config.json: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid configuration file: {}", e)));
        }
    };

    // Globals
    let domains_config = Arc::new(config.domains);
    let cookie_key: [u8; 32] = *blake3::hash(config.cookie_secret.as_bytes()).as_bytes();
    let stages_global: Arc<RwLock<HashMap<String, Arc<AtomicU8>>>> = Arc::new(RwLock::new(HashMap::new()));
    let pin_pow_threads = config.runtime.pin_pow_threads;
    let pow_pool = PowVerifierPool::new(
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).min(4),
        pin_pow_threads,
    );
    let global_total_requests = Arc::new(AtomicU64::new(0));
    let global_challenged_requests = Arc::new(AtomicU64::new(0));
    let global_allowed_requests = Arc::new(AtomicU64::new(0));
    
    info!("HTTP client config prepared");
    info!("Arin proxy is running on http://127.0.0.1:3000");
    info!("Configured domains:");
    for (domain, settings) in domains_config.iter() {
        let initial_stage = settings.stage.unwrap_or(0);
        stages_global.write().unwrap().insert(domain.clone(), Arc::new(AtomicU8::new(initial_stage)));
        info!(
            "  {} -> {} (Cloudflare mode: {}, Initial stage: {})", 
            domain, settings.backend, settings.cloudflare_mode, initial_stage
        );
    }
    info!("Starting HTTP server");

    let stages_global_inner = stages_global.clone();
    let domains_map: RwLock<HashMap<String, DomainSettings>> = RwLock::new(HashMap::new());
    for (k, v) in domains_config.iter() {
        let mut s = v.clone();
        s.current_stage = s.stage.unwrap_or(0);
        s.last_reset = Some(Instant::now());
        s.stage_ptr = stages_global_inner.read().unwrap().get(k).cloned();
        if config.runtime.resolve_dns_startup {
            if let Some((host, port_str)) = s.backend.split_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    use std::net::{ToSocketAddrs, SocketAddr};
                    let addrs = (host, port).to_socket_addrs();
                    if let Ok(mut iter) = addrs {
                        if let Some(sa) = iter.find(|a| matches!(a, SocketAddr::V4(_) | SocketAddr::V6(_))) {
                            s.backend = format!("{}:{}", sa.ip(), port);
                        }
                    }
                }
            }
        }
        if !s.backend.is_empty() {
            let mut base = String::with_capacity(8 + s.backend.len());
            if s.use_https { base.push_str("https://"); } else { base.push_str("http://"); }
            base.push_str(&s.backend);
            s.backend_base = base;
        } else {
            s.backend_base = String::new();
        }
        domains_map.write().unwrap().insert(k.clone(), s);
    }
    let init_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let app_state = Arc::new(AppState {
        domains: domains_map,
        ip_buckets: IPBuckets::new(N_IP_BUCKETS, init_secs),
        stages: stages_global_inner.clone(),
        pow_pool: pow_pool.clone(),
        cookie_key,
        local_ip_acc: std::sync::Mutex::new(vec![0u64; N_IP_BUCKETS]),
        global_total_requests: global_total_requests.clone(),
        global_challenged_requests: global_challenged_requests.clone(),
        global_allowed_requests: global_allowed_requests.clone(),
    });

    let cleanup_state = app_state.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(60));
            cleanup_state.cleanup_old_requests();
        }
    });

    #[derive(Clone)]
    struct ArinService { state: Arc<AppState> }
    impl HttpService for ArinService { fn call(&mut self, req: Request, rsp: &mut Response) -> std::io::Result<()> { handle_request_may(req, rsp, &self.state) } }

    let jh = HttpServer(ArinService { state: app_state.clone() }).start("127.0.0.1:3000")?;
    info!("Starting proxy server on 127.0.0.1:3000");
    jh.join().unwrap();
    Ok(())
}

const STAGE_THRESHOLD: u64 = 500;
const IP_ENTRY_STALE_DURATION: u64 = 60;
const SOFT_RL_LIMIT: u64 = 800;
const HARD_RL_LIMIT: u64 = 1000;
const MAX_BACKOFF_MS: u64 = 200;

fn handle_request_may(mut req: Request, rsp: &mut Response, state: &Arc<AppState>) -> std::io::Result<()> {
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let method = req.method().to_owned();
    let path = req.path().to_owned();
    state.global_total_requests.fetch_add(1, Ordering::Relaxed);

    if method.eq_ignore_ascii_case("GET") && path == "/proxy/stats" { return get_proxy_stats_may(rsp, state); }
    if method.eq_ignore_ascii_case("POST") && path == "/pow/validate" {
        let mut host = String::new();
        for h in req.headers() { if h.name.eq_ignore_ascii_case("host") { host = std::str::from_utf8(h.value).unwrap_or("").to_owned(); break; } }
        {
            let mut body = Vec::new();
            req.body_ref().read_to_end(&mut body)?;
            return validate_pow_may(&body, rsp, state, &host, &req);
        }
    }

    let mut host = "";
    for h in req.headers() { if h.name.eq_ignore_ascii_case("host") { host = std::str::from_utf8(h.value).unwrap_or(""); break; } }
    if host.is_empty() { rsp.status_code(400, "Bad Request").body("Invalid domain"); return Ok(()); }

    let ip = derive_ip_may(&req, host, state).unwrap_or(String::new());
    if ip.is_empty() { rsp.status_code(400, "Bad Request").body("Cannot determine client IP"); return Ok(()); }

    let request_count = state.ip_update_and_get_batched(&ip, now_secs, IP_ENTRY_STALE_DURATION);
    if request_count >= SOFT_RL_LIMIT { let backoff_ms = ((request_count - SOFT_RL_LIMIT) * MAX_BACKOFF_MS) / (HARD_RL_LIMIT - SOFT_RL_LIMIT); if backoff_ms > 0 { std::thread::sleep(Duration::from_millis(backoff_ms)); } }
    if request_count > HARD_RL_LIMIT { rsp.status_code(429, "Too Many Requests"); rsp.body("Too many requests"); return Ok(()); }

    let mut cookie_str = ""; for h in req.headers() { if h.name.eq_ignore_ascii_case("cookie") { cookie_str = std::str::from_utf8(h.value).unwrap_or(""); break; } }
    let cookie_valid = verify_challenge_cookie(cookie_str, &ip, now_secs, &state.cookie_key);

    if !cookie_valid && is_media_request_may(&req) { let cookie_value = create_challenge_cookie_value(&ip, now_secs, &state.cookie_key); rsp.status_code(302, "Found"); rsp.header(&format!("Set-Cookie: Arin={}; Path=/; SameSite=None; Secure", cookie_value)); rsp.header(&format!("Location: {}", path)); rsp.header("Cache-Control: no-store, no-cache, must-revalidate"); rsp.header("Pragma: no-cache"); state.global_challenged_requests.fetch_add(1, Ordering::Relaxed); rsp.body(""); return Ok(()); }

    let (current_stage, backend_base, request_allowed) = {
        let mut dmap = state.domains.write().unwrap();
        if let Some(domain_settings) = dmap.get_mut(host) {
            domain_settings.total_requests.fetch_add(1, Ordering::Relaxed);
            if domain_settings.last_reset.map_or(true, |last| last.elapsed() >= Duration::from_secs(1)) {
                if domain_settings.bypassed_requests.load(Ordering::Relaxed) >= STAGE_THRESHOLD {
                    if let Some(stage_arc) = domain_settings.stage_ptr.as_ref() { let cur = stage_arc.load(Ordering::Relaxed); let new = (cur + 1).min(3); stage_arc.store(new, Ordering::Relaxed); domain_settings.current_stage = new; } else if let Some(entry) = state.stages.read().unwrap().get(host) { let cur = entry.load(Ordering::Relaxed); let new = (cur + 1).min(3); entry.store(new, Ordering::Relaxed); domain_settings.current_stage = new; }
                }
                domain_settings.bypassed_requests.store(0, Ordering::Relaxed);
                domain_settings.last_reset = Some(Instant::now());
            }
            let stage = if let Some(stage_arc) = domain_settings.stage_ptr.as_ref() { stage_arc.load(Ordering::Relaxed) } else { state.stages.read().unwrap().get(host).map(|e| e.load(Ordering::Relaxed)).unwrap_or(domain_settings.current_stage) };
            let allowed = match stage { 0 => true, 1 | 2 | 3 => cookie_valid, _ => false };
            if !cookie_valid && (1..=3).contains(&stage) { } else if allowed { domain_settings.bypassed_requests.fetch_add(1, Ordering::Relaxed); }
            (stage, domain_settings.backend_base.clone(), allowed)
        } else { rsp.status_code(404, "Not Found").body("Domain not configured"); return Ok(()); }
    };

    if !cookie_valid {
        match current_stage {
            0 => {}
            1 => { let cookie_value = create_challenge_cookie_value(&ip, now_secs, &state.cookie_key); rsp.header(&format!("Set-Cookie: Arin={}; Path=/; SameSite=None; Secure", cookie_value)); state.global_challenged_requests.fetch_add(1, Ordering::Relaxed); rsp.body("<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0\"></head><body></body></html>"); return Ok(()); }
            2 => { let cookie_value = create_challenge_cookie_value(&ip, now_secs, &state.cookie_key); let mut js = String::with_capacity(160 + cookie_value.len()); js.push_str("<!DOCTYPE html><html><head><script>document.cookie='Arin="); js.push_str(&cookie_value); js.push_str("; Path=/; SameSite=None; Secure';window.location.reload();</script></head><body></body></html>"); state.global_challenged_requests.fetch_add(1, Ordering::Relaxed); rsp.body_vec(js.into_bytes()); return Ok(()); }
            3 => { let challenge_secret = generate_challenge_secret(); let html = crate::pow::generate_pow_html(&challenge_secret, POW_DIFFICULTY).map_err(|e| std::io::Error::other(e.to_string()))?; state.global_challenged_requests.fetch_add(1, Ordering::Relaxed); rsp.body_vec(html.into_bytes()); return Ok(()); }
            _ => { rsp.status_code(403, "Forbidden").body("Request blocked"); return Ok(()); }
        }
    }

    if !request_allowed { rsp.status_code(403, "Forbidden").body("Request blocked"); return Ok(()); }
    state.global_allowed_requests.fetch_add(1, Ordering::Relaxed);
    proxy_request_may(&req, rsp, &backend_base, host)
}

fn get_proxy_stats_may(rsp: &mut Response, state: &Arc<AppState>) -> std::io::Result<()> {
    #[derive(serde::Serialize)]
    struct Stats { total_requests: u64, challenged_requests: u64, allowed_requests: u64 }
    let stats = Stats { total_requests: state.global_total_requests.load(Ordering::Relaxed), challenged_requests: state.global_challenged_requests.load(Ordering::Relaxed), allowed_requests: state.global_allowed_requests.load(Ordering::Relaxed) };
    let body = simd_json::to_vec(&stats).map_err(|e| std::io::Error::other(e.to_string()))?;
    rsp.header("Content-Type: application/json"); rsp.body_vec(body); Ok(())
}

#[derive(serde::Deserialize)] struct PowValidationRequest { nonce: String, challenge_secret: String }
#[derive(serde::Serialize)] struct PowValidationResponse { verified: bool }

fn validate_pow_may(body: &[u8], rsp: &mut Response, state: &Arc<AppState>, host: &str, req: &Request) -> std::io::Result<()> {
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut owned = body.to_vec();
    let pow_request: PowValidationRequest = simd_json::serde::from_slice(&mut owned).map_err(|e| std::io::Error::other(e.to_string()))?;
    let rx = state.pow_pool.submit(pow_request.nonce, pow_request.challenge_secret, POW_DIFFICULTY as usize);
    let verified = rx.recv().unwrap_or(false);
    if verified {
        let ip = derive_ip_may(req, host, state).unwrap_or(String::new()); if ip.is_empty() { rsp.status_code(400, "Bad Request").body("Cannot determine client IP"); return Ok(()); }
        let cookie_value = create_challenge_cookie_value(&ip, now_secs, &state.cookie_key);
        if let Some(domain_settings) = state.domains.write().unwrap().get_mut(host) { domain_settings.bypassed_requests.fetch_add(1, Ordering::Relaxed); domain_settings.last_pow_success = Some(now_secs); }
        rsp.header(&format!("Set-Cookie: Arin={}; Path=/; SameSite=Lax", cookie_value));
        let body = simd_json::to_vec(&PowValidationResponse{verified:true}).map_err(|e| std::io::Error::other(e.to_string()))?; rsp.header("Content-Type: application/json"); rsp.body_vec(body);
    } else { let body = simd_json::to_vec(&PowValidationResponse{verified:false}).map_err(|e| std::io::Error::other(e.to_string()))?; rsp.header("Content-Type: application/json"); rsp.body_vec(body); }
    Ok(())
}

fn proxy_request_may(req: &Request, rsp: &mut Response, backend_base: &str, orig_host: &str) -> std::io::Result<()> {
    if backend_base.is_empty() { rsp.status_code(500, "Internal Server Error").body("Backend not configured"); return Ok(()); }
    if backend_base.starts_with("https://") { rsp.status_code(502, "Bad Gateway").body("HTTPS backend not supported"); return Ok(()); }
    let addr = &backend_base["http://".len()..]; let (backend_host, port) = match addr.split_once(':') { Some((h,p)) => (h, p.parse::<u16>().unwrap_or(80)), None => (addr, 80) };
    let method_owned = req.method().to_owned();
    let path_q_owned = req.path().to_owned();
    let mut stream = TcpStream::connect((backend_host, port))?;
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(method_owned.as_bytes()); out.extend_from_slice(b" "); out.extend_from_slice(path_q_owned.as_bytes()); out.extend_from_slice(b" HTTP/1.1\r\n");
    out.extend_from_slice(b"Host: "); out.extend_from_slice(orig_host.as_bytes()); out.extend_from_slice(b"\r\n");
    for h in req.headers() { let name = h.name; if is_hop_req_header(name) { continue; } if name.eq_ignore_ascii_case("host") { continue; } out.extend_from_slice(name.as_bytes()); out.extend_from_slice(b": "); out.extend_from_slice(h.value); out.extend_from_slice(b"\r\n"); }
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"\r\n\r\n");
    stream.write_all(&out)?;
    let mut read_buf = Vec::with_capacity(4096); let mut header_end = None; loop { let mut tmp = [0u8; 1024]; let n = stream.read(&mut tmp)?; if n == 0 { break; } read_buf.extend_from_slice(&tmp[..n]); if let Some(pos) = find_headers_end(&read_buf) { header_end = Some(pos); break; } if read_buf.len() > 1024*128 { break; } }
    let header_end = header_end.unwrap_or(read_buf.len()); let (head_bytes, rest) = read_buf.split_at(header_end);
    let (code, content_len) = parse_response_meta(head_bytes)?;
    let mut body_vec = Vec::new(); body_vec.extend_from_slice(rest); if let Some(cl) = content_len { while body_vec.len() < cl { let mut tmp = [0u8; 2048]; let n = stream.read(&mut tmp)?; if n == 0 { break; } body_vec.extend_from_slice(&tmp[..n]); } }
    rsp.status_code(code, code_to_msg(code)); rsp.body_vec(body_vec); Ok(())
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 { return None; }
    for i in 0..=buf.len()-4 {
        if buf[i] == b'\r' && buf[i+1] == b'\n' && buf[i+2] == b'\r' && buf[i+3] == b'\n' { return Some(i+4); }
    }
    None
}

fn parse_response_meta(head: &[u8]) -> std::io::Result<(usize, Option<usize>)> {
    let mut lines = head.split(|&b| b == b'\n');
    let status_line = lines.next().ok_or_else(|| std::io::Error::other("empty response"))?;
    let status_line = if status_line.ends_with(b"\r") { &status_line[..status_line.len()-1] } else { status_line };
    let mut parts = status_line.split(|&b| b == b' ');
    let _http = parts.next().ok_or_else(|| std::io::Error::other("bad status line"))?;
    let code_bytes = parts.next().ok_or_else(|| std::io::Error::other("bad status code"))?;
    let code_str = std::str::from_utf8(code_bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
    let code = code_str.parse::<usize>().unwrap_or(502);

    let mut content_len: Option<usize> = None;
    for line in lines {
        if line == b"\r" || line.is_empty() { break; }
        let line = if line.ends_with(b"\r") { &line[..line.len()-1] } else { line };
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let (name, value) = line.split_at(colon);
            let name_str = std::str::from_utf8(name).map_err(|e| std::io::Error::other(e.to_string()))?;
            if name_str.eq_ignore_ascii_case("content-length") {
                let val = &value[1..]; // skip ':'
                let val_str = std::str::from_utf8(val).map_err(|e| std::io::Error::other(e.to_string()))?.trim();
                if let Ok(n) = val_str.parse::<usize>() { content_len = Some(n); }
            }
        }
    }
    Ok((code, content_len))
}
fn code_to_msg(code: usize) -> &'static str { match code { 200 => "Ok", 201 => "Created", 301 => "Moved Permanently", 302 => "Found", 400 => "Bad Request", 403 => "Forbidden", 404 => "Not Found", 429 => "Too Many Requests", 500 => "Internal Server Error", 502 => "Bad Gateway", _ => "" } }

fn create_challenge_cookie_value(ip: &str, timestamp: u64, key: &[u8; 32]) -> String { hash_ip_with_timestamp(ip, timestamp, key) }
fn verify_challenge_cookie(cookie_str: &str, ip: &str, current_time: u64, key: &[u8; 32]) -> bool { let provided_opt = cookie_str.split(';').find_map(|s| { let t = s.trim(); t.strip_prefix("Arin=").map(|v| v.trim().trim_matches('"')) }); if let Some(provided) = provided_opt { for dt in 0..=60 { let t = current_time.saturating_sub(dt); let expected = hash_ip_with_timestamp(ip, t, key); if ct_eq(provided.as_bytes(), expected.as_bytes()) { return true; } } } false }
fn ct_eq(a: &[u8], b: &[u8]) -> bool { if a.len() != b.len() { return false; } let mut diff: u8 = 0; for (x,y) in a.iter().zip(b.iter()) { diff |= x ^ y; } diff == 0 }
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
fn hex_encode(bytes: &[u8]) -> String { let mut s = String::with_capacity(bytes.len()*2); for &b in bytes { s.push(HEX_CHARS[(b>>4) as usize] as char); s.push(HEX_CHARS[(b & 0x0F) as usize] as char);} s }
fn hash_ip_with_timestamp(ip: &str, timestamp: u64, key: &[u8; 32]) -> String { let mut hasher = blake3::Hasher::new_keyed(key); hasher.update(ip.as_bytes()); hasher.update(&timestamp.to_be_bytes()); let bytes = hasher.finalize(); hex_encode(bytes.as_bytes()) }
fn derive_ip_may(req: &Request, domain: &str, state: &AppState) -> Option<String> {
    let cf_mode = state.domains.read().unwrap().get(domain).map(|d| d.cloudflare_mode).unwrap_or(false);
    if cf_mode {
        for h in req.headers() { if h.name.eq_ignore_ascii_case("CF-Connecting-IP") { return std::str::from_utf8(h.value).ok().map(|s| s.to_string()); } }
        for h in req.headers() { if h.name.eq_ignore_ascii_case("X-Forwarded-For") { return std::str::from_utf8(h.value).ok().map(|s| s.split(',').next().unwrap_or("").trim().to_string()); } }
        None
    } else { None }
}
fn is_hop_req_header(name: &str) -> bool { const H: [&str; 10] = ["connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailers","transfer-encoding","upgrade","host","accept-encoding"]; for h in &H { if name.eq_ignore_ascii_case(h) { return true; } } false }
fn ends_with_ignore_ascii_case(hay: &str, suffix: &str) -> bool { let hl = hay.len(); let sl = suffix.len(); if sl > hl { return false; } hay[hl - sl..].eq_ignore_ascii_case(suffix) }
fn is_media_request_may(req: &Request) -> bool { for h in req.headers() { if h.name.eq_ignore_ascii_case("Range") { return true; } } for h in req.headers() { if h.name.eq_ignore_ascii_case("Sec-Fetch-Dest") { if let Ok(dest) = std::str::from_utf8(h.value) { if dest.eq_ignore_ascii_case("audio") || dest.eq_ignore_ascii_case("video") || dest.eq_ignore_ascii_case("track") || dest.eq_ignore_ascii_case("media") { return true; } } } } for h in req.headers() { if h.name.eq_ignore_ascii_case("Accept") { if let Ok(a) = std::str::from_utf8(h.value) { let a = a.to_ascii_lowercase(); if a.contains("audio/") || a.contains("video/") || a.contains("application/vnd.apple.mpegurl") || a.contains("application/x-mpegurl") { return true; } } } } let path = req.path(); ends_with_ignore_ascii_case(path, ".mp3") || ends_with_ignore_ascii_case(path, ".mp4") || ends_with_ignore_ascii_case(path, ".m4a") || ends_with_ignore_ascii_case(path, ".wav") || ends_with_ignore_ascii_case(path, ".ogg") || ends_with_ignore_ascii_case(path, ".webm") }