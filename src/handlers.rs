use hyper::{Request, Response, StatusCode};
use hyper::header;
use hyper::body::Incoming;
use http_body_util::{Full, BodyExt, combinators::BoxBody};
use bytes::Bytes;
use tokio::time::sleep;
use crate::blake3;
use log::{info, warn, error, debug};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::atomic::Ordering;
use std::net::{IpAddr, SocketAddr};

use crate::state::AppState;
use crate::pow::{POW_DIFFICULTY, generate_challenge_secret, generate_pow_html};

pub const STAGE_THRESHOLD: u64 = 500;
pub const IP_ENTRY_STALE_DURATION: u64 = 60;
pub const SOFT_RL_LIMIT: u64 = 800;
pub const HARD_RL_LIMIT: u64 = 1000;
pub const MAX_BACKOFF_MS: u64 = 200;
pub const CHALLENGE_TTL_SECS: u64 = 300;

#[derive(Deserialize)]
pub struct PowValidationRequest {
    pub nonce: String,
    pub challenge_secret: String,
}

#[derive(Serialize)]
pub struct PowValidationResponse {
    pub verified: bool,
}

#[derive(Serialize)]
pub struct ProxyStats {
    pub total_requests: u64,
    pub challenged_requests: u64,
    pub allowed_requests: u64,
}

pub async fn handle_request(
    req: Request<Incoming>,
    state: std::sync::Arc<AppState>,
    remote_addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    state.global_total_requests.fetch_add(1, Ordering::Relaxed);
    let domain = match req.headers().get(header::HOST).and_then(|h| h.to_str().ok()) {
        Some(domain) => domain,
        None => {
            let resp = Response::builder().status(StatusCode::BAD_REQUEST);
            return Ok(resp.body(full_body(Bytes::from_static(b"Invalid domain"))).unwrap());
        }
    };
    
    if req.method() == hyper::Method::POST && req.uri().path() == "/pow/validate" {
        return validate_pow(req, state).await;
    }

    let ip = match derive_ip(&req, domain, &state, &remote_addr) {
        Some(ip) => ip,
        None => {
            warn!("Could not determine client IP for domain: {}", domain);
            let resp = Response::builder().status(StatusCode::BAD_REQUEST);
            return Ok(resp.body(full_body(Bytes::from_static(b"Cannot determine client IP"))).unwrap());
        }
    };

    let request_count = state
        .ip_update_and_get_batched(ip, now_secs, IP_ENTRY_STALE_DURATION);

    if request_count >= SOFT_RL_LIMIT {
        let backoff_ms = ((request_count - SOFT_RL_LIMIT) * MAX_BACKOFF_MS)
            / (HARD_RL_LIMIT - SOFT_RL_LIMIT);
        if backoff_ms > 0 {
            sleep(Duration::from_millis(backoff_ms)).await;
        }
    }

    if request_count > HARD_RL_LIMIT {
        let retry_secs: u64 = 1 + ((request_count - HARD_RL_LIMIT) / 100).min(10);
        let mut resp = Response::builder().status(StatusCode::TOO_MANY_REQUESTS);
        resp = resp.header(header::RETRY_AFTER, retry_secs.to_string());
        resp = resp.header("X-Backoff-ms", MAX_BACKOFF_MS.to_string());
        return Ok(resp.body(full_body(Bytes::from_static(b"Too many requests"))).unwrap());
    }

    if ip != remote_addr.ip() {
        state.ip_update_local_batch(remote_addr.ip(), now_secs, IP_ENTRY_STALE_DURATION);
    }

    let cookie_str = req
        .headers()
        .get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .unwrap_or("");

    debug!("Cookie string received: {}", cookie_str);
    let cookie_valid = verify_challenge_cookie(cookie_str, ip, now_secs, &state.cookie_key);
    debug!("Cookie validation result: {} (IP: {}, Time: {})", cookie_valid, ip, now_secs);

    // Media request check
    if !cookie_valid && is_media_request(&req) {
        let cookie_value = create_challenge_cookie_value(ip, now_secs, &state.cookie_key);
        let mut resp = Response::builder().status(StatusCode::FOUND);
        let set_cookie = format!("Arin={}; Path=/; HttpOnly; SameSite=None; Secure", cookie_value);
        resp = resp.header(header::SET_COOKIE, set_cookie);
        resp = resp.header(header::LOCATION, req.uri().to_string());
        resp = resp.header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate");
        resp = resp.header(header::PRAGMA, "no-cache");
        state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
        return Ok(resp.body(empty_body()).unwrap());
    }

    let (current_stage, backend_base, request_allowed) = {
        if let Some(d) = state.domains.get(domain) {
            d.total_requests.fetch_add(1, Ordering::Relaxed);
            let now = now_secs;
            let last = d.last_reset_secs.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= 1 {
                if d.bypassed_requests.load(Ordering::Relaxed) >= STAGE_THRESHOLD {
                    let cur = d.stage.load(Ordering::Relaxed);
                    let new = (cur + 1).min(3);
                    d.stage.store(new, Ordering::Relaxed);
                    debug!("Domain {} advanced to stage {}", domain, new);
                }
                d.bypassed_requests.store(0, Ordering::Relaxed);
                d.last_reset_secs.store(now, Ordering::Relaxed);
            }
            let stage = d.stage.load(Ordering::Relaxed);
            let allowed = match stage {
                0 => true,
                1 | 2 | 3 => cookie_valid,
                _ => false,
            };
            if !cookie_valid && (1..=3).contains(&stage) {
            } else if allowed {
                d.bypassed_requests.fetch_add(1, Ordering::Relaxed);
            }
            (stage, d.backend_base.clone(), allowed)
        } else {
            warn!("Request for unconfigured domain: {}", domain);
            let resp = Response::builder().status(StatusCode::NOT_FOUND);
            return Ok(resp.body(full_body(Bytes::from_static(b"Domain not configured"))).unwrap());
        }
    };

    if !cookie_valid {
        match current_stage {
            0 => {}
            1 => {
                let cookie_value = create_challenge_cookie_value(ip, now_secs, &state.cookie_key);
                let forwarded_proto = req
                    .headers()
                    .get("X-Forwarded-Proto")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| "http".to_owned());
                let is_https = forwarded_proto.eq_ignore_ascii_case("https");
                let mut resp = Response::builder().status(StatusCode::OK);
                let cookie_suffix = if is_https { "; SameSite=None; Secure" } else { "; SameSite=Lax" };
                let set_cookie = format!("Arin={}; Path=/; HttpOnly{}", cookie_value, cookie_suffix);
                resp = resp.header(header::SET_COOKIE, set_cookie);
                let html = "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0\"></head><body></body></html>";
                state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
                return Ok(resp.header(header::CONTENT_TYPE, "text/html").body(full_body(Bytes::from_static(html.as_bytes()))).unwrap());
            }
            2 => {
                let cookie_value = create_challenge_cookie_value(ip, now_secs, &state.cookie_key);
                let forwarded_proto = req
                    .headers()
                    .get("X-Forwarded-Proto")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| "http".to_owned());
                let cookie_suffix = if forwarded_proto.eq_ignore_ascii_case("https") { "; SameSite=None; Secure" } else { "; SameSite=Lax" };
                let mut js_challenge = String::with_capacity(160 + cookie_value.len());
                js_challenge.push_str("<!DOCTYPE html><html><head><script>document.cookie = 'Arin=");
                js_challenge.push_str(&cookie_value);
                js_challenge.push_str("; Path=/");
                js_challenge.push_str(cookie_suffix);
                js_challenge.push_str("';window.location.reload();</script></head><body></body></html>");
                state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
                let resp = Response::builder().status(StatusCode::OK);
                return Ok(resp.header(header::CONTENT_TYPE, "text/html").body(full_body(Bytes::from(js_challenge))).unwrap());
            }
            3 => {
                let challenge_secret = generate_challenge_secret();
                let pow_html = match generate_pow_html(&challenge_secret, POW_DIFFICULTY) {
                    Ok(html) => html,
                    Err(e) => {
                        error!("Failed to generate PoW HTML: {}", e);
                        let resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR);
                        return Ok(resp.body(full_body(Bytes::from_static(b"Failed to generate challenge"))).unwrap());
                    }
                };
                state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
                let resp = Response::builder().status(StatusCode::OK);
                return Ok(resp.header(header::CONTENT_TYPE, "text/html").body(full_body(Bytes::from(pow_html))).unwrap());
            }
            _ => {
                warn!("Invalid stage {} for domain {}", current_stage, domain);
                let resp = Response::builder().status(StatusCode::FORBIDDEN);
                return Ok(resp.body(full_body(Bytes::from_static(b"Request blocked"))).unwrap());
            }
        }
    }

    if !request_allowed {
        let resp = Response::builder().status(StatusCode::FORBIDDEN);
        return Ok(resp.body(full_body(Bytes::from_static(b"Request blocked"))).unwrap());
    }
    state.global_allowed_requests.fetch_add(1, Ordering::Relaxed);
    proxy_request(req, &backend_base, &state).await
}

pub async fn validate_pow(
    req: Request<Incoming>,
    state: std::sync::Arc<AppState>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (parts, body) = req.into_parts();
    let whole_body = body.collect().await?.to_bytes();
    let pow_request: PowValidationRequest = match serde_json::from_slice(&whole_body) {
        Ok(request) => request,
        Err(e) => {
            warn!("Invalid PoW validation request: {}", e);
            let resp = Response::builder().status(StatusCode::BAD_REQUEST);
            return Ok(resp.body(full_body(Bytes::from_static(b"Invalid POW validation request"))).unwrap());
        }
    };

    let nonce = pow_request.nonce;
    let challenge_secret = pow_request.challenge_secret;
    let difficulty_bits = POW_DIFFICULTY as usize;
    let verified_rx = state.pow_pool.submit(nonce, challenge_secret, difficulty_bits);
    let verified = verified_rx.await.unwrap_or(false);

    if verified {
        let domain = parts
            .headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let ip = match parts.headers.get("CF-Connecting-IP").and_then(|h| h.to_str().ok()).and_then(|s| s.parse::<IpAddr>().ok()) {
            Some(ip) => ip,
            None => {
                warn!("Could not determine IP for PoW validation");
                let resp = Response::builder().status(StatusCode::BAD_REQUEST);
                return Ok(resp.body(full_body(Bytes::from_static(b"Cannot determine client IP"))).unwrap());
            }
        };
        
        let cookie_value = create_challenge_cookie_value(ip, now_secs, &state.cookie_key);
        
        info!("PoW validation successful for IP: {}", ip);
        
        if let Some(d) = state.domains.get(domain) {
            d.bypassed_requests.fetch_add(1, Ordering::Relaxed);
            d.last_pow_success.store(now_secs, Ordering::Relaxed);
            debug!("PoW completion counted for domain {}: {} bypassed, last success: {}",
                  domain, d.bypassed_requests.load(Ordering::Relaxed), now_secs);
        }
        let json = serde_json::to_vec(&PowValidationResponse { verified: true }).unwrap_or_default();
        let mut resp = Response::builder().status(StatusCode::OK);
        let set_cookie = format!("Arin={}; Path=/; HttpOnly; SameSite=Lax", cookie_value);
        resp = resp.header(header::SET_COOKIE, set_cookie);
        resp = resp.header(header::CONTENT_TYPE, "application/json");
        Ok(resp.body(full_body(Bytes::from(json))).unwrap())
    } else {
        warn!("PoW validation failed");
        let json = serde_json::to_vec(&PowValidationResponse { verified: false }).unwrap_or_default();
        let mut resp = Response::builder().status(StatusCode::OK);
        resp = resp.header(header::CONTENT_TYPE, "application/json");
        Ok(resp.body(full_body(Bytes::from(json))).unwrap())
    }
}

async fn proxy_request(
    req: Request<Incoming>,
    backend_base: &str,
    state: &std::sync::Arc<AppState>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    /* 
     Request cleanup, Cull them after 30 seconds we might want to change this later.
     Some clients have slow request loading or slow Android devices.
    */ 
    if backend_base.is_empty() {
        error!("Empty backend URL");
        let resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR);
        return Ok(resp.body(full_body(Bytes::from_static(b"Backend not configured"))).unwrap());
    }

    let original_host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let path_q = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("");
    let mut backend_url = String::with_capacity(backend_base.len() + path_q.len());
    backend_url.push_str(backend_base);
    backend_url.push_str(path_q);

    let uri = backend_url.parse::<hyper::Uri>().unwrap();
    let mut out_req = hyper::Request::builder()
        .method(req.method())
        .uri(uri);

    /* 
     Manually parse headers to avoid hop-by-hop headers and other compressors
     This saves CPU resources from having to read the entire HTTP Header.
     Which will allow for more requests to be processed 
    */ 
    for (name, value) in req.headers().iter() {
        let s = name.as_str();
        if is_hop_req_header(s) { continue; }
        out_req = out_req.header(name.as_str(), value);
    }
    out_req = out_req.header(header::HOST, original_host);

    // Disable automatic compression in the request builder. Saves CPU utilization by using Zero-Copy Costs.
    // Stream body to backend to avoid buffering
    let incoming = req.into_body();
    let out_req = out_req.body(incoming.boxed()).unwrap();
    let _permit = state.backend_sem.clone().acquire_owned().await.unwrap();
    let backend_response = match state.http_client.request(out_req).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to send request to backend: {}", e);
            let resp = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body(Bytes::from_static(b"Backend request failed or timed out")))
                .unwrap();
            return Ok(resp);
        }
    };
    let status = backend_response.status();
    let mut resp_builder = Response::builder().status(status);
    
    /* 
     Manually parse headers to avoid hop-by-hop headers and other compressors
     This saves CPU resources from having to read the entire HTTP Header.
     Which will allow for more requests to be processed.
    */
    for (name, value) in backend_response.headers().iter() {
        let s = name.as_str();
        if is_hop_resp_header(s) { continue; }
        resp_builder = resp_builder.header(name.as_str(), value);
    }
    let body = backend_response.into_body().boxed();
    Ok(resp_builder.body(body).unwrap())
}

#[inline]
fn create_challenge_cookie_value(ip: IpAddr, timestamp: u64, key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    match ip {
        IpAddr::V4(addr) => hasher.update(&addr.octets()),
        IpAddr::V6(addr) => hasher.update(&addr.octets()),
    }
    hasher.update(&timestamp.to_be_bytes());
    let bytes = hasher.finalize();
    let raw = bytes.as_bytes();
    let ts_str = timestamp.to_string();
    let mut out = String::with_capacity(ts_str.len() + 1 + raw.len() * 2);
    out.push_str(&ts_str);
    out.push(':');
    for &b in raw {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0F) as usize] as char);
    }
    out
}

#[inline]
fn verify_challenge_cookie(cookie_str: &str, ip: IpAddr, current_time: u64, key: &[u8; 32]) -> bool {
    let provided_opt = cookie_str
        .split(';')
        .find_map(|s| {
            let trimmed = s.trim();
            trimmed.strip_prefix("Arin=").map(|v| v.trim().trim_matches('"'))
        });

    if let Some(provided) = provided_opt {
        if let Some((ts_part, hex_part)) = provided.split_once(':') {
            if let Ok(ts) = ts_part.parse::<u64>() {
                if ts <= current_time {
                    let delta = current_time - ts;
                    if delta <= CHALLENGE_TTL_SECS {
                        let expected = hash_ip_with_timestamp(ip, ts, key);
                        if ct_eq(hex_part.as_bytes(), expected.as_bytes()) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

#[inline]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

#[inline]
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0F) as usize] as char);
    }
    s
}

#[inline]
fn hash_ip_with_timestamp(ip: IpAddr, timestamp: u64, key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    match ip {
        IpAddr::V4(addr) => hasher.update(&addr.octets()),
        IpAddr::V6(addr) => hasher.update(&addr.octets()),
    }
    hasher.update(&timestamp.to_be_bytes());
    let bytes = hasher.finalize();
    hex_encode(bytes.as_bytes())
}

pub async fn get_proxy_stats(
    state: std::sync::Arc<AppState>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let total = state.global_total_requests.load(Ordering::Relaxed);
    let challenged = state.global_challenged_requests.load(Ordering::Relaxed);
    let allowed = state.global_allowed_requests.load(Ordering::Relaxed);
    let stats = ProxyStats {
        total_requests: total,
        challenged_requests: challenged,
        allowed_requests: allowed,
    };

    let body = serde_json::to_vec(&stats).unwrap_or_default();
    let mut resp = Response::builder().status(StatusCode::OK);
    resp = resp.header(header::CONTENT_TYPE, "application/json");
    Ok(resp.body(full_body(Bytes::from(body))).unwrap())
}
#[inline]
fn derive_ip<B>(req: &Request<B>, domain: &str, state: &AppState, fallback: &std::net::SocketAddr) -> Option<IpAddr> {
    if let Some(d) = state.domains.get(domain) {
        if d.cloudflare_mode {
            return req.headers().get("CF-Connecting-IP").and_then(|h| h.to_str().ok()).and_then(|s| s.parse::<IpAddr>().ok());
        }
    }
    Some(fallback.ip())
}
#[inline]
fn is_hop_req_header(name: &str) -> bool {
    match name {
        n if n.eq_ignore_ascii_case("connection") => true,
        n if n.eq_ignore_ascii_case("keep-alive") => true,
        n if n.eq_ignore_ascii_case("proxy-authenticate") => true,
        n if n.eq_ignore_ascii_case("proxy-authorization") => true,
        n if n.eq_ignore_ascii_case("te") => true,
        n if n.eq_ignore_ascii_case("trailers") => true,
        n if n.eq_ignore_ascii_case("transfer-encoding") => true,
        n if n.eq_ignore_ascii_case("upgrade") => true,
        n if n.eq_ignore_ascii_case("host") => true,
        n if n.eq_ignore_ascii_case("accept-encoding") => true,
        _ => false,
    }
}

#[inline]
fn is_hop_resp_header(name: &str) -> bool {
    match name {
        n if n.eq_ignore_ascii_case("content-length") => true,
        n if n.eq_ignore_ascii_case("transfer-encoding") => true,
        n if n.eq_ignore_ascii_case("connection") => true,
        n if n.eq_ignore_ascii_case("keep-alive") => true,
        n if n.eq_ignore_ascii_case("proxy-authenticate") => true,
        n if n.eq_ignore_ascii_case("proxy-authorization") => true,
        n if n.eq_ignore_ascii_case("te") => true,
        n if n.eq_ignore_ascii_case("trailers") => true,
        n if n.eq_ignore_ascii_case("upgrade") => true,
        _ => false,
    }
}

#[inline]
fn ends_with_ignore_ascii_case(hay: &str, suffix: &str) -> bool {
    let hl = hay.len();
    let sl = suffix.len();
    if sl > hl { return false; }
    hay[hl - sl..].eq_ignore_ascii_case(suffix)
}

#[inline]
fn is_media_request<B>(req: &Request<B>) -> bool {
    let headers = req.headers();

    if headers.contains_key(header::RANGE) {
        return true;
    }
    
    if let Some(dest) = headers.get("Sec-Fetch-Dest").and_then(|v| v.to_str().ok()) {
        if dest.eq_ignore_ascii_case("audio")
            || dest.eq_ignore_ascii_case("video")
            || dest.eq_ignore_ascii_case("track")
            || dest.eq_ignore_ascii_case("media")
        {
            return true;
        }
    }

    if let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        // Optimized: avoid to_ascii_lowercase allocation
        if accept.split(',').any(|part| {
            let p = part.trim();
            p.eq_ignore_ascii_case("audio/") || p.starts_with("audio/") ||
            p.eq_ignore_ascii_case("video/") || p.starts_with("video/") ||
            p.eq_ignore_ascii_case("application/vnd.apple.mpegurl") ||
            p.eq_ignore_ascii_case("application/x-mpegurl")
        }) {
            return true;
        }
    }
    let path = req.uri().path();
    ends_with_ignore_ascii_case(path, ".mp3")
        || ends_with_ignore_ascii_case(path, ".mp4")
        || ends_with_ignore_ascii_case(path, ".m4a")
        || ends_with_ignore_ascii_case(path, ".wav")
        || ends_with_ignore_ascii_case(path, ".ogg")
        || ends_with_ignore_ascii_case(path, ".webm")
}

pub async fn route(
    req: Request<Incoming>,
    state: std::sync::Arc<AppState>,
    remote_addr: std::net::SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/proxy/stats") => get_proxy_stats(state).await,
        (&hyper::Method::POST, "/pow/validate") => validate_pow(req, state).await,
        _ => handle_request(req, state, remote_addr).await,
    }
}

#[inline]
fn full_body(data: impl Into<Bytes>) -> BoxBody<Bytes, hyper::Error> {
    Full::new(data.into()).map_err(|_| unreachable!()).boxed()
}

#[inline]
fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Empty::<Bytes>::new().map_err(|_| unreachable!()).boxed()
}