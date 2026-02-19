use hyper::{Request, Response, StatusCode, header};
use hyper::body::Incoming;
use http_body_util::{Full, BodyExt, combinators::BoxBody};
use bytes::Bytes;
use tokio::time::sleep;
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

static BAD_REQUEST_BODY: &[u8] = b"Invalid domain";
static IP_ERROR_BODY: &[u8] = b"Cannot determine client IP";
static TOO_MANY_BODY: &[u8] = b"Too many requests";
static NOT_FOUND_BODY: &[u8] = b"Domain not configured";
static CHALLENGE_ERROR_BODY: &[u8] = b"Failed to generate challenge";
static BLOCKED_BODY: &[u8] = b"Request blocked";
static INVALID_POW_BODY: &[u8] = b"Invalid POW validation request";

static STAGE1_HTML: &[u8] = b"<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0\"></head><body></body></html>";

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

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
#[allow(dead_code)]
pub struct ProxyStats {
    pub total_requests: u64,
    pub challenged_requests: u64,
    pub allowed_requests: u64,
}

#[inline]
fn full_body(bytes: Bytes) -> BoxBody<Bytes, hyper::Error> {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

#[inline]
fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::new()).map_err(|never| match never {}).boxed()
}

#[inline]
fn static_body(data: &'static [u8]) -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::from_static(data)).map_err(|never| match never {}).boxed()
}

pub async fn handle_request(
    req: Request<Incoming>,
    state: std::sync::Arc<AppState>,
    remote_addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    state.global_total_requests.fetch_add(1, Ordering::Relaxed);
    
    let domain = match req.headers().get(header::HOST).and_then(|h| h.to_str().ok()) {
        Some(h) => h.split(':').next().unwrap_or(h),
        None => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(static_body(BAD_REQUEST_BODY))
            .unwrap()),
    };
    
    if req.method() == hyper::Method::POST && req.uri().path() == "/pow/validate" {
        return validate_pow(req, state).await;
    }
    
    if req.method() == hyper::Method::GET && req.uri().path() == "/proxy/stats" {
        return get_proxy_stats(state).await;
    }

    let ip = match derive_ip(&req, domain, &state, &remote_addr) {
        Some(ip) => ip,
        None => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(static_body(IP_ERROR_BODY))
            .unwrap()),
    };

    let request_count = state.ip_update_and_get_batched(ip, now_secs, IP_ENTRY_STALE_DURATION);

    if request_count >= SOFT_RL_LIMIT {
        let backoff_ms = ((request_count - SOFT_RL_LIMIT) * MAX_BACKOFF_MS)
            / (HARD_RL_LIMIT - SOFT_RL_LIMIT);
        if backoff_ms > 0 {
            sleep(Duration::from_millis(backoff_ms)).await;
        }
    }

    if request_count > HARD_RL_LIMIT {
        let retry_secs: u64 = 1 + ((request_count - HARD_RL_LIMIT) / 100).min(10);
        return Ok(Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(header::RETRY_AFTER, retry_secs)
            .header("X-Backoff-ms", MAX_BACKOFF_MS)
            .body(static_body(TOO_MANY_BODY))
            .unwrap());
    }

    if ip != remote_addr.ip() {
        state.ip_update_local_batch(remote_addr.ip(), now_secs, IP_ENTRY_STALE_DURATION);
    }

    let cookie_str = req.headers().get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .unwrap_or("");

    let cookie_valid = verify_challenge_cookie(cookie_str, ip, now_secs, &state.cookie_key);

    if !cookie_valid && is_media_request(&req) {
        let cookie_value = create_challenge_cookie_value(ip, now_secs, &state.cookie_key);
        let set_cookie = format!("Arin={}; Path=/; HttpOnly; SameSite=None; Secure", cookie_value);
        state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
        return Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(header::SET_COOKIE, set_cookie)
            .header(header::LOCATION, req.uri().to_string())
            .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")
            .header(header::PRAGMA, "no-cache")
            .body(empty_body())
            .unwrap());
    }

    let (current_stage, backend_base, request_allowed) = {
        let Some(d) = state.domains.get(domain) else {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(static_body(NOT_FOUND_BODY))
                .unwrap());
        };
        
        d.total_requests.fetch_add(1, Ordering::Relaxed);
        
        let last = d.last_reset_secs.load(Ordering::Relaxed);
        if now_secs.saturating_sub(last) >= 1 {
            if d.bypassed_requests.load(Ordering::Relaxed) >= STAGE_THRESHOLD {
                let cur = d.stage.load(Ordering::Relaxed);
                let new = cur.saturating_add(1).min(3);
                d.stage.store(new, Ordering::Relaxed);
            }
            d.bypassed_requests.store(0, Ordering::Relaxed);
            d.last_reset_secs.store(now_secs, Ordering::Relaxed);
        }
        
        let stage = d.stage.load(Ordering::Relaxed);
        let allowed = stage == 0 || cookie_valid;
        
        if allowed {
            d.bypassed_requests.fetch_add(1, Ordering::Relaxed);
        }
        
        (stage, d.backend_base.clone(), allowed)
    };

    if !cookie_valid {
        match current_stage {
            0 => {}
            1 => {
                let cookie_value = create_challenge_cookie_value(ip, now_secs, &state.cookie_key);
                let forwarded_proto = req.headers()
                    .get("X-Forwarded-Proto")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("http");
                
                let is_https = forwarded_proto.eq_ignore_ascii_case("https");
                let cookie_suffix = if is_https { "; SameSite=None; Secure" } else { "; SameSite=Lax" };
                let set_cookie = format!("Arin={}; Path=/; HttpOnly{}", cookie_value, cookie_suffix);
                
                state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::SET_COOKIE, set_cookie)
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(static_body(STAGE1_HTML))
                    .unwrap());
            }
            2 => {
                let cookie_value = create_challenge_cookie_value(ip, now_secs, &state.cookie_key);
                let forwarded_proto = req.headers()
                    .get("X-Forwarded-Proto")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("http");
                
                let cookie_suffix = if forwarded_proto.eq_ignore_ascii_case("https") { 
                    "; SameSite=None; Secure" 
                } else { 
                    "; SameSite=Lax" 
                };
                
                let mut js_challenge = String::with_capacity(200);
                js_challenge.push_str("<!DOCTYPE html><html><head><script>document.cookie='Arin=");
                js_challenge.push_str(&cookie_value);
                js_challenge.push_str("; Path=/");
                js_challenge.push_str(cookie_suffix);
                js_challenge.push_str("';window.location.reload();</script></head><body></body></html>");
                
                state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(full_body(Bytes::from(js_challenge)))
                    .unwrap());
            }
            3 => {
                let challenge_secret = generate_challenge_secret();
                let pow_html = match generate_pow_html(&challenge_secret, POW_DIFFICULTY) {
                    Ok(html) => html,
                    Err(_) => return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(static_body(CHALLENGE_ERROR_BODY))
                        .unwrap()),
                };
                
                state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(full_body(Bytes::from(pow_html)))
                    .unwrap());
            }
            _ => return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(static_body(BLOCKED_BODY))
                .unwrap()),
        }
    }

    if !request_allowed {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(static_body(BLOCKED_BODY))
            .unwrap());
    }
    
    state.global_allowed_requests.fetch_add(1, Ordering::Relaxed);
    proxy_request(req, &backend_base, &state).await
}

pub async fn validate_pow(
    req: Request<Incoming>,
    state: std::sync::Arc<AppState>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = req.into_parts();
    let whole_body = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    
    let pow_request: PowValidationRequest = match serde_json::from_slice(&whole_body) {
        Ok(request) => request,
        Err(_) => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(static_body(INVALID_POW_BODY))
            .unwrap()),
    };

    let difficulty_bits = POW_DIFFICULTY as usize;
    let verified_rx = state.pow_pool.submit(pow_request.nonce, pow_request.challenge_secret, difficulty_bits);
    let verified = verified_rx.await.unwrap_or(false);

    if verified {
        let domain = parts.headers.get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let ip = parts.headers.get("CF-Connecting-IP")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<IpAddr>().ok())
            .or_else(|| parts.headers.get("X-Real-IP")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<IpAddr>().ok()))
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        
        let cookie_value = create_challenge_cookie_value(ip, now_secs, &state.cookie_key);
        let forwarded_proto = parts.headers.get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("http");
        
        let cookie_suffix = if forwarded_proto.eq_ignore_ascii_case("https") {
            "; SameSite=None; Secure"
        } else {
            "; SameSite=Lax"
        };
        
        let set_cookie = format!("Arin={}; Path=/; HttpOnly{}", cookie_value, cookie_suffix);
        
        if let Some(d) = state.domains.get(domain) {
            d.last_pow_success.store(now_secs, Ordering::Relaxed);
        }
        
        let resp_body = PowValidationResponse { verified: true };
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::SET_COOKIE, set_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full_body(Bytes::from(serde_json::to_string(&resp_body).unwrap_or_default())))
            .unwrap());
    }

    let resp_body = PowValidationResponse { verified: false };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(serde_json::to_string(&resp_body).unwrap_or_default())))
        .unwrap())
}

#[inline]
fn derive_ip(req: &Request<Incoming>, domain: &str, state: &AppState, remote_addr: &SocketAddr) -> Option<IpAddr> {
    let cf_mode = state.domains.get(domain)
        .map(|d| d.cloudflare_mode)
        .unwrap_or(false);
    
    if cf_mode {
        req.headers().get("CF-Connecting-IP")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<IpAddr>().ok())
            .or_else(|| req.headers().get("X-Real-IP")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<IpAddr>().ok()))
    } else {
        Some(remote_addr.ip())
    }
}

#[inline]
fn is_media_request(req: &Request<Incoming>) -> bool {
    let path = req.uri().path();
    let ext = path.rsplit('.').next().unwrap_or("");
    matches!(ext, "css" | "js" | "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" | "woff" | "woff2" | "ttf" | "eot" | "webp" | "mp4" | "webm" | "mp3" | "ogg")
}

#[inline]
fn verify_challenge_cookie(cookie_str: &str, ip: IpAddr, now_secs: u64, key: &[u8; 32]) -> bool {
    let arin_value = cookie_str.split(';')
        .map(|s| s.trim())
        .find_map(|s| s.strip_prefix("Arin="));
    
    let Some(value) = arin_value else { return false };
    
    let (ts_str, hash_hex) = match value.split_once(':') {
        Some(parts) => parts,
        None => return false,
    };
    
    let Ok(ts) = ts_str.parse::<u64>() else { return false };
    
    if now_secs.saturating_sub(ts) > CHALLENGE_TTL_SECS {
        return false;
    }
    
    let expected = hash_ip_with_timestamp(ip, ts, key);
    hash_hex.eq_ignore_ascii_case(&expected)
}

#[inline]
fn create_challenge_cookie_value(ip: IpAddr, timestamp: u64, key: &[u8; 32]) -> String {
    let hash = hash_ip_with_timestamp(ip, timestamp, key);
    let ts_str = timestamp.to_string();
    let mut out = String::with_capacity(ts_str.len() + 1 + hash.len());
    out.push_str(&ts_str);
    out.push(':');
    out.push_str(&hash);
    out
}

#[inline]
fn hash_ip_with_timestamp(ip: IpAddr, timestamp: u64, key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    match ip {
        IpAddr::V4(addr) => { hasher.update(&addr.octets()); }
        IpAddr::V6(addr) => { hasher.update(&addr.octets()); }
    }
    hasher.update(&timestamp.to_be_bytes());
    let bytes = hasher.finalize();
    hex_encode(bytes.as_bytes())
}

#[inline]
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0F) as usize] as char);
    }
    s
}

pub async fn proxy_request(
    req: Request<Incoming>,
    backend_base: &str,
    state: &AppState,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    let _permit = state.backend_sem.acquire().await.map_err(|e| e.to_string())?;
    
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    
    let path_query = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let uri_str = format!("{}{}", backend_base, path_query);
    let uri: hyper::Uri = uri_str.parse().map_err(|e: hyper::http::uri::InvalidUri| e.to_string())?;
    
    let original_host = parts.headers.get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    let mut builder = hyper::Request::builder()
        .method(parts.method.clone())
        .uri(uri);
    
    builder = builder.header(header::HOST, original_host);
    
    for (name, value) in parts.headers.iter() {
        if name != header::HOST {
            builder = builder.header(name, value);
        }
    }
    
    let proxied_req = builder.body(full_body(body_bytes)).map_err(|e| e.to_string())?;
    
    let response = state.http_client.request(proxied_req).await.map_err(|e| e.to_string())?;
    let (parts, body) = response.into_parts();
    let body_bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    
    let mut builder = Response::builder().status(parts.status);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    
    Ok(builder.body(full_body(body_bytes)).map_err(|e| e.to_string())?)
}

pub async fn get_proxy_stats(
    state: std::sync::Arc<AppState>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    let stats = ProxyStats {
        total_requests: state.global_total_requests.load(Ordering::Relaxed),
        challenged_requests: state.global_challenged_requests.load(Ordering::Relaxed),
        allowed_requests: state.global_allowed_requests.load(Ordering::Relaxed),
    };
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(serde_json::to_string(&stats).unwrap_or_default())))
        .unwrap())
}

pub async fn route(
    req: Request<Incoming>,
    state: std::sync::Arc<AppState>,
    remote_addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    handle_request(req, state, remote_addr).await
}
