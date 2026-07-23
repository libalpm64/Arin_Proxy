use hyper::{Request, Response, StatusCode, header};
use hyper::body::Incoming;
use http_body_util::{Full, BodyExt, combinators::BoxBody};
use bytes::Bytes;
use tokio::time::sleep;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::{IpAddr, SocketAddr};

use crate::pow::{POW_DIFFICULTY, generate_challenge_secret, generate_pow_html};

pub const STAGE_THRESHOLD: u64 = 500;
pub const IP_ENTRY_STALE_DURATION: u64 = 60;
pub const SOFT_RL_LIMIT: u64 = 800;
pub const HARD_RL_LIMIT: u64 = 1000;
pub const MAX_BACKOFF_MS: u64 = 200;
pub const CHALLENGE_TTL_SECS: u64 = 300;
pub const JS_CHALLENGE_TTL_SECS: u64 = 30;

static BAD_REQUEST_BODY: &[u8] = b"Invalid domain";
static IP_ERROR_BODY: &[u8] = b"Cannot determine client IP";
static TOO_MANY_BODY: &[u8] = b"Too many requests";
static NOT_FOUND_BODY: &[u8] = b"Domain not configured";
static CHALLENGE_ERROR_BODY: &[u8] = b"Failed to generate challenge";
static BLOCKED_BODY: &[u8] = b"Request blocked";
static INVALID_POW_BODY: &[u8] = b"Invalid POW validation request";
static INVALID_JS_BODY: &[u8] = b"Invalid JS validation request";

static STAGE1_HTML: &[u8] = b"<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0\"></head><body></body></html>";

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

#[derive(Deserialize)]
pub struct PowValidationRequest {
    pub nonce: String,
    pub challenge_secret: String,
}

#[derive(Deserialize)]
pub struct JsValidationRequest {
    pub token: String,
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
    remote_addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    crate::state::LOCAL_TOTAL.with(|c| c.set(c.get() + 1));

    let domain = match req.headers().get(header::HOST).and_then(|h| h.to_str().ok()) {
        Some(h) => h.split(':').next().unwrap_or(h),
        None => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(static_body(BAD_REQUEST_BODY))
            .unwrap()),
    };
    
    if req.method() == hyper::Method::POST && req.uri().path() == "/pow/validate" {
        return validate_pow(req).await;
    }

    if req.method() == hyper::Method::POST && req.uri().path() == "/js/validate" {
        let ip = match derive_ip(&req, domain, &remote_addr) {
            Some(ip) => ip,
            None => return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(static_body(IP_ERROR_BODY))
                .unwrap()),
        };
        return validate_js(req, ip).await;
    }
    
    if req.method() == hyper::Method::GET && req.uri().path() == "/proxy/stats" {
        return get_proxy_stats().await;
    }

    let ip = match derive_ip(&req, domain, &remote_addr) {
        Some(ip) => ip,
        None => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(static_body(IP_ERROR_BODY))
            .unwrap()),
    };

    let request_count = crate::state::IP_BUCKET_STATE.with(|state| {
        let mut state = state.borrow_mut();
        (*state).update_and_get(ip, now_secs, IP_ENTRY_STALE_DURATION)
    });

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
        crate::state::IP_BUCKET_STATE.with(|state| {
            let mut state = state.borrow_mut();
            (*state).update_local_batch(remote_addr.ip(), now_secs, IP_ENTRY_STALE_DURATION);
        });
    }

    let cookie_str = req.headers().get(header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .unwrap_or("");

    let cookie_valid = verify_challenge_cookie(cookie_str, ip, now_secs);

    if !cookie_valid && is_media_request(&req) {
        let cookie_value = create_challenge_cookie_value(ip, now_secs);
        let set_cookie = format!("Arin={}; Path=/; HttpOnly; SameSite=None; Secure", cookie_value);
        
        crate::state::LOCAL_CHALLENGED.with(|c| c.set(c.get() + 1));
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
        let domain_config = crate::state::DOMAIN_CONFIG.with(|configs| {
            configs.borrow().get(domain).cloned()
        });
        
        let Some(config) = domain_config else {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(static_body(NOT_FOUND_BODY))
                .unwrap());
        };
        
        crate::state::DOMAIN_STATS.with(|stats| {
            let mut stats = stats.borrow_mut();
            let d = stats.get_mut(domain).unwrap();
            
            d.total_requests += 1;
            
            if now_secs.saturating_sub(d.last_reset_secs) >= 1 {
                if d.bypassed_requests >= STAGE_THRESHOLD {
                    let new = d.stage.saturating_add(1).min(3);
                    d.stage = new;
                }
                d.bypassed_requests = 0;
                d.last_reset_secs = now_secs;
            }
            
            let allowed = d.stage == 0 || cookie_valid;
            
            if allowed {
                d.bypassed_requests += 1;
            }
            
            (d.stage, config.backend_base.clone(), allowed)
        })
    };

    if !cookie_valid {
        match current_stage {
            0 => {}
            1 => {
                let cookie_value = create_challenge_cookie_value(ip, now_secs);
                let forwarded_proto = req.headers()
                    .get("X-Forwarded-Proto")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("http");
                
                let is_https = forwarded_proto.eq_ignore_ascii_case("https");
                let cookie_suffix = if is_https { "; SameSite=None; Secure" } else { "; SameSite=Lax" };
                let set_cookie = format!("Arin={}; Path=/; HttpOnly{}", cookie_value, cookie_suffix);
                
                crate::state::LOCAL_CHALLENGED.with(|c| c.set(c.get() + 1));
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::SET_COOKIE, set_cookie)
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(static_body(STAGE1_HTML))
                    .unwrap());
            }
            2 => {
                let token = create_js_challenge_token(ip, now_secs);
                let mut js_challenge = String::with_capacity(300);
                js_challenge.push_str("<!doctype html><html style=background:#121212><script type=module>import{run}from'https://cdn.jsdelivr.net/gh/libalpm64/Blake3-JS@4fdbc61b1ae09d6313af3c0805fca49754ff0884/arin-browser.js';run('");
                js_challenge.push_str(&token);
                js_challenge.push_str("')</script>");
                
                crate::state::LOCAL_CHALLENGED.with(|c| c.set(c.get() + 1));
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
                
                crate::state::LOCAL_CHALLENGED.with(|c| c.set(c.get() + 1));
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
    
    crate::state::LOCAL_ALLOWED.with(|c| c.set(c.get() + 1));
    proxy_request(req, &backend_base).await
}

pub async fn validate_js(
    req: Request<Incoming>,
    ip: IpAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = req.into_parts();
    let whole_body = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    let js_request: JsValidationRequest = match serde_json::from_slice(&whole_body) {
        Ok(request) => request,
        Err(_) => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(static_body(INVALID_JS_BODY))
            .unwrap()),
    };
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let verified = verify_js_challenge_token(&js_request.token, ip, now_secs);
    let resp_body = PowValidationResponse { verified };
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store");
    if verified {
        let cookie_value = create_challenge_cookie_value(ip, now_secs);
        let forwarded_proto = parts.headers.get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("http");
        let cookie_suffix = if forwarded_proto.eq_ignore_ascii_case("https") {
            "; SameSite=None; Secure"
        } else {
            "; SameSite=Lax"
        };
        let set_cookie = format!("Arin={}; Path=/; HttpOnly{}", cookie_value, cookie_suffix);
        response = response.header(header::SET_COOKIE, set_cookie);
    }
    Ok(response
        .body(full_body(Bytes::from(serde_json::to_string(&resp_body).unwrap_or_default())))
        .unwrap())
}

pub async fn validate_pow(
    req: Request<Incoming>,
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
    
    let verified_rx = crate::state::POW_POOL.with(|pool| {
        pool.borrow().submit(pow_request.nonce, pow_request.challenge_secret, difficulty_bits)
    });
    
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
        
        let cookie_value = create_challenge_cookie_value(ip, now_secs);
        let forwarded_proto = parts.headers.get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("http");
        
        let cookie_suffix = if forwarded_proto.eq_ignore_ascii_case("https") {
            "; SameSite=None; Secure"
        } else {
            "; SameSite=Lax"
        };
        
        let set_cookie = format!("Arin={}; Path=/; HttpOnly{}", cookie_value, cookie_suffix);
        
        crate::state::DOMAIN_STATS.with(|stats| {
            let mut stats = stats.borrow_mut();
            if let Some(d) = stats.get_mut(domain) {
                d.last_pow_success = now_secs;
            }
        });
        
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
fn derive_ip(req: &Request<Incoming>, domain: &str, remote_addr: &SocketAddr) -> Option<IpAddr> {
    let cf_mode = crate::state::DOMAIN_CONFIG.with(|configs| {
        configs.borrow().get(domain).map(|d| d.cloudflare_mode).unwrap_or(false)
    });
    
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
fn verify_challenge_cookie(cookie_str: &str, ip: IpAddr, now_secs: u64) -> bool {
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
    
    let expected = hash_ip_with_timestamp(ip, ts);
    hash_hex.eq_ignore_ascii_case(&expected)
}

#[inline]
fn create_challenge_cookie_value(ip: IpAddr, timestamp: u64) -> String {
    let hash = hash_ip_with_timestamp(ip, timestamp);
    let ts_str = timestamp.to_string();
    let mut out = String::with_capacity(ts_str.len() + 1 + hash.len());
    out.push_str(&ts_str);
    out.push(':');
    out.push_str(&hash);
    out
}

#[inline]
fn create_js_challenge_token(ip: IpAddr, timestamp: u64) -> String {
    let hash = hash_js_challenge(ip, timestamp);
    let ts_str = timestamp.to_string();
    let mut out = String::with_capacity(ts_str.len() + 1 + hash.len());
    out.push_str(&ts_str);
    out.push(':');
    out.push_str(&hash);
    out
}

#[inline]
fn verify_js_challenge_token(token: &str, ip: IpAddr, now_secs: u64) -> bool {
    let Some((ts_str, hash_hex)) = token.split_once(':') else { return false };
    let Ok(timestamp) = ts_str.parse::<u64>() else { return false };
    if timestamp > now_secs || now_secs.saturating_sub(timestamp) > JS_CHALLENGE_TTL_SECS {
        return false;
    }
    hash_hex.eq_ignore_ascii_case(&hash_js_challenge(ip, timestamp))
}

#[inline]
fn hash_js_challenge(ip: IpAddr, timestamp: u64) -> String {
    let key = crate::state::COOKIE_KEY.with(|k| *k.borrow());
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(b"arin-browser-stage-2");
    match ip {
        IpAddr::V4(addr) => { hasher.update(&addr.octets()); }
        IpAddr::V6(addr) => { hasher.update(&addr.octets()); }
    }
    hasher.update(&timestamp.to_be_bytes());
    let bytes = hasher.finalize();
    hex_encode(bytes.as_bytes())
}

#[inline]
fn hash_ip_with_timestamp(ip: IpAddr, timestamp: u64) -> String {
    let key = crate::state::COOKIE_KEY.with(|k| *k.borrow());
    let mut hasher = blake3::Hasher::new_keyed(&key);
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
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    let sem = crate::state::BACKEND_SEM.with(|sem| (*sem.borrow()).clone());
    let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
    
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
    
    let response = crate::state::HTTP_CLIENT.with(|client| {
        let client = (*client.borrow()).clone().unwrap();
        client.request(proxied_req)
    }).await.map_err(|e| e.to_string())?;
    
    let (parts, body) = response.into_parts();
    let body_bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    
    let mut builder = Response::builder().status(parts.status);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    
    Ok(builder.body(full_body(body_bytes)).map_err(|e| e.to_string())?)
}

pub async fn get_proxy_stats(
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    let stats = ProxyStats {
        total_requests: crate::state::GLOBAL_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
        challenged_requests: crate::state::GLOBAL_CHALLENGED.load(std::sync::atomic::Ordering::Relaxed),
        allowed_requests: crate::state::GLOBAL_ALLOWED.load(std::sync::atomic::Ordering::Relaxed),
    };
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(serde_json::to_string(&stats).unwrap_or_default())))
        .unwrap())
}
