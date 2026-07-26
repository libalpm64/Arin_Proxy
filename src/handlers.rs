use hyper::{Request, Response, StatusCode, header};
use hyper::body::Incoming;
use http_body_util::{Full, BodyExt, Limited, combinators::BoxBody};
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
pub const POW_CHALLENGE_TTL_SECS: u64 = 60;
pub const MAX_JS_BODY: usize = 512;
pub const MAX_POW_BODY: usize = 1024;

static BAD_REQUEST_BODY: &[u8] = b"Invalid domain";
static IP_ERROR_BODY: &[u8] = b"Cannot determine client IP";
static TOO_MANY_BODY: &[u8] = b"Too many requests";
static NOT_FOUND_BODY: &[u8] = b"Domain not configured";
static CHALLENGE_ERROR_BODY: &[u8] = b"Failed to generate challenge";
static BLOCKED_BODY: &[u8] = b"Request blocked";
static INVALID_POW_BODY: &[u8] = b"Invalid POW validation request";
static INVALID_JS_BODY: &[u8] = b"Invalid JS validation request";
static PAYLOAD_TOO_LARGE_BODY: &[u8] = b"Payload too large";

static STAGE1_HTML: &[u8] = b"<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0\"></head><body></body></html>";

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

#[derive(Deserialize)]
pub struct PowValidationRequest {
    pub nonce: Option<String>,
    pub challenge_secret: Option<String>,
    pub answer: Option<String>,
    pub ticket: Option<String>,
}

#[derive(Deserialize)]
pub struct JsValidationRequest {
    pub token: String,
    pub nonce: u32,
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
        let ip = match derive_ip(&req, domain, &remote_addr) {
            Some(ip) => ip,
            None => return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(static_body(IP_ERROR_BODY))
                .unwrap()),
        };
        let domain = domain.to_owned();
        return validate_pow(req, ip, domain).await;
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

    let mut clearance = challenge_clearance(cookie_str, ip, now_secs);
    if clearance >= 3 {
        if let Some(token) = cookie_value(cookie_str, "ArinVdf") {
            let path = req.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/");
            let digest = crate::vdf::request_digest(req.method().as_str(), domain, path);
            if crate::vdf::consume_grant(token, ip, digest, now_secs) {
                clearance = 4;
            }
        }
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
                    let new = d.stage.saturating_add(1).min(4);
                    d.stage = new;
                }
                d.bypassed_requests = 0;
                d.last_reset_secs = now_secs;
            }
            
            let allowed = d.stage == 0 || clearance >= d.stage;
            
            if allowed {
                d.bypassed_requests += 1;
            }
            
            (d.stage, config.backend_base.clone(), allowed)
        })
    };

    if !request_allowed && is_subresource_request(&req) {
        crate::state::LOCAL_CHALLENGED.with(|c| c.set(c.get() + 1));
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")
            .body(empty_body())
            .unwrap());
    }

    if !request_allowed {
        match next_challenge_stage(clearance, current_stage) {
            None => {}
            Some(1) => {
                let cookie_value = create_challenge_cookie_value(ip, now_secs, 1);
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
            Some(2) => {
                let token = create_js_challenge_token(ip, now_secs);
                let mut js_challenge = String::with_capacity(300);
                js_challenge.push_str("<!doctype html><html style=background:#121212><script type=module>import{run}from'https://cdn.jsdelivr.net/gh/libalpm64/Blake3-JS@b4478839f4f88e7bcbb16ecdee0eee02ee05663f/arin-browser.js';run('");
                js_challenge.push_str(&token);
                js_challenge.push_str("')</script>");
                
                crate::state::LOCAL_CHALLENGED.with(|c| c.set(c.get() + 1));
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(full_body(Bytes::from(js_challenge)))
                    .unwrap());
            }
            Some(3) => {
                let challenge_secret = create_pow_ticket(ip, domain, now_secs);
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
            Some(4) => {
                if req.method() != hyper::Method::GET {
                    return Ok(Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(static_body(BLOCKED_BODY))
                        .unwrap());
                }
                let path = req.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/");
                let request_digest = crate::vdf::request_digest(req.method().as_str(), domain, path);
                let session = crate::vdf::session_binding(ip, cookie_value(cookie_str, "Arin").unwrap_or(""));
                let Some(challenge) = crate::vdf::issue(request_digest, session, now_secs) else {
                    return Ok(Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(static_body(CHALLENGE_ERROR_BODY))
                        .unwrap());
                };
                let vdf_html = match crate::vdf::generate_vdf_html(&challenge) {
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
                    .body(full_body(Bytes::from(vdf_html)))
                    .unwrap());
            }
            Some(_) => return Ok(Response::builder()
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
    if content_length_exceeds(&req, MAX_JS_BODY) {
        return Ok(Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(static_body(PAYLOAD_TOO_LARGE_BODY))
            .unwrap());
    }
    let (parts, body) = req.into_parts();
    let whole_body = match Limited::new(body, MAX_JS_BODY).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => return Ok(Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(static_body(PAYLOAD_TOO_LARGE_BODY))
            .unwrap()),
    };
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
    let cookie_str = parts.headers.get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let verified = challenge_clearance(cookie_str, ip, now_secs) >= 1
        && verify_js_challenge_token(&js_request.token, ip, now_secs)
        && verify_js_proof(&js_request.token, js_request.nonce);
    let resp_body = PowValidationResponse { verified };
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store");
    if verified {
        let cookie_value = create_challenge_cookie_value(ip, now_secs, 2);
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
    ip: IpAddr,
    domain: String,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Box<dyn std::error::Error + Send + Sync>> {
    if content_length_exceeds(&req, MAX_POW_BODY) {
        return Ok(Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(static_body(PAYLOAD_TOO_LARGE_BODY))
            .unwrap());
    }
    let (parts, body) = req.into_parts();
    let whole_body = match Limited::new(body, MAX_POW_BODY).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => return Ok(Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(static_body(PAYLOAD_TOO_LARGE_BODY))
            .unwrap()),
    };
    
    let pow_request: PowValidationRequest = match serde_json::from_slice(&whole_body) {
        Ok(request) => request,
        Err(_) => return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(static_body(INVALID_POW_BODY))
            .unwrap()),
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cookie_str = parts.headers.get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let clearance = challenge_clearance(cookie_str, ip, now_secs);
    let PowValidationRequest { nonce, challenge_secret, answer, ticket } = pow_request;
    let (verified, granted_level, grant) = if let (Some(answer), Some(ticket)) = (answer, ticket) {
        if clearance < 3 {
            (false, 4, None)
        } else {
            let session = crate::vdf::session_binding(ip, cookie_value(cookie_str, "Arin").unwrap_or(""));
            let backend_available = crate::state::BACKEND_SEM.with(|sem| sem.borrow().available_permits() > 0);
            let grant = crate::vdf::submit(&ticket, &answer, ip, session, backend_available, now_secs);
            (grant.is_some(), 4, grant)
        }
    } else if let (Some(nonce), Some(challenge_secret)) = (nonce, challenge_secret) {
        if clearance < 2 || !verify_pow_ticket(&challenge_secret, ip, &domain, now_secs) {
            (false, 3, None)
        } else {
            let verified_rx = crate::state::POW_POOL.with(|pool| {
                pool.borrow().submit(nonce, challenge_secret, POW_DIFFICULTY as usize)
            });
            (verified_rx.await.unwrap_or(false), 3, None)
        }
    } else {
        (false, 0, None)
    };

    if verified {
        let forwarded_proto = parts.headers.get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("http");
        
        let cookie_suffix = if forwarded_proto.eq_ignore_ascii_case("https") {
            "; SameSite=None; Secure"
        } else {
            "; SameSite=Lax"
        };
        let set_cookie = if let Some(grant) = grant {
            format!("ArinVdf={}; Path=/; Max-Age=10; HttpOnly{}", grant, cookie_suffix)
        } else {
            let value = create_challenge_cookie_value(ip, now_secs, granted_level);
            format!("Arin={}; Path=/; HttpOnly{}", value, cookie_suffix)
        };
        
        crate::state::DOMAIN_STATS.with(|stats| {
            let mut stats = stats.borrow_mut();
            if let Some(d) = stats.get_mut(&domain) {
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
fn is_subresource_request<B>(req: &Request<B>) -> bool {
    if let Some(destination) = req.headers()
        .get("Sec-Fetch-Dest")
        .and_then(|value| value.to_str().ok())
    {
        return destination != "document";
    }
    let path = req.uri().path();
    let ext = path.rsplit('.').next().unwrap_or("");
    matches!(ext, "css" | "js" | "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" | "woff" | "woff2" | "ttf" | "eot" | "webp" | "mp4" | "webm" | "mp3" | "ogg")
}

#[inline]
fn content_length_exceeds<B>(req: &Request<B>, limit: usize) -> bool {
    req.headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > limit)
}

#[inline]
fn challenge_clearance(cookie_str: &str, ip: IpAddr, now_secs: u64) -> u8 {
    let arin_value = cookie_value(cookie_str, "Arin");
    let Some(value) = arin_value else { return 0 };
    let mut parts = value.split(':');
    let Some(level) = parts.next().and_then(|value| value.parse::<u8>().ok()) else { return 0 };
    let Some(timestamp) = parts.next().and_then(|value| value.parse::<u64>().ok()) else { return 0 };
    let Some(hash) = parts.next() else { return 0 };
    if parts.next().is_some()
        || !(1..=3).contains(&level)
        || timestamp > now_secs
        || now_secs.saturating_sub(timestamp) > CHALLENGE_TTL_SECS
    {
        return 0;
    }
    if hash.eq_ignore_ascii_case(&hash_clearance(ip, timestamp, level)) { level } else { 0 }
}

#[inline]
fn cookie_value<'a>(cookie_str: &'a str, name: &str) -> Option<&'a str> {
    cookie_str.split(';')
        .map(|value| value.trim())
        .find_map(|value| {
            let (key, value) = value.split_once('=')?;
            (key == name).then_some(value)
        })
}

#[inline]
fn create_challenge_cookie_value(ip: IpAddr, timestamp: u64, level: u8) -> String {
    let hash = hash_clearance(ip, timestamp, level);
    let ts_str = timestamp.to_string();
    let mut out = String::with_capacity(ts_str.len() + 3 + hash.len());
    out.push(HEX_CHARS[level as usize] as char);
    out.push(':');
    out.push_str(&ts_str);
    out.push(':');
    out.push_str(&hash);
    out
}

#[inline]
fn next_challenge_stage(clearance: u8, configured_stage: u8) -> Option<u8> {
    if configured_stage == 0 || clearance >= configured_stage {
        None
    } else {
        Some(clearance.saturating_add(1).min(configured_stage).min(4))
    }
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
fn verify_js_proof(token: &str, nonce: u32) -> bool {
    if nonce > 10_000_000 {
        return false;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(token.as_bytes());
    hasher.update(b":");
    hasher.update(nonce.to_string().as_bytes());
    let bytes = hasher.finalize();
    bytes.as_bytes()[0] == 0 && bytes.as_bytes()[1] & 0xF0 == 0
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
fn create_pow_ticket(ip: IpAddr, domain: &str, now_secs: u64) -> String {
    let challenge = generate_challenge_secret();
    let fields = format!("1.{}.{}.{}", now_secs + POW_CHALLENGE_TTL_SECS, POW_DIFFICULTY, challenge);
    let mac = hash_pow_ticket(ip, domain, &fields);
    format!("{}.{}", fields, mac)
}

#[inline]
fn verify_pow_ticket(ticket: &str, ip: IpAddr, domain: &str, now_secs: u64) -> bool {
    let mut parts = ticket.split('.');
    let Some(version) = parts.next() else { return false };
    let Some(expiry) = parts.next().and_then(|value| value.parse::<u64>().ok()) else { return false };
    let Some(difficulty) = parts.next().and_then(|value| value.parse::<u32>().ok()) else { return false };
    let Some(challenge) = parts.next() else { return false };
    let Some(mac) = parts.next() else { return false };
    if parts.next().is_some()
        || version != "1"
        || expiry < now_secs
        || difficulty != POW_DIFFICULTY
        || challenge.len() != crate::pow::POW_CHALLENGE_LENGTH
    {
        return false;
    }
    let fields_len = ticket.len().saturating_sub(mac.len() + 1);
    let fields = &ticket[..fields_len];
    mac.eq_ignore_ascii_case(&hash_pow_ticket(ip, domain, fields))
}

#[inline]
fn hash_pow_ticket(ip: IpAddr, domain: &str, fields: &str) -> String {
    let key = crate::state::COOKIE_KEY.with(|key| *key.borrow());
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(b"arin-pow-ticket-v1");
    match ip {
        IpAddr::V4(addr) => { hasher.update(&addr.octets()); }
        IpAddr::V6(addr) => { hasher.update(&addr.octets()); }
    }
    hasher.update(domain.as_bytes());
    hasher.update(fields.as_bytes());
    let bytes = hasher.finalize();
    hex_encode(bytes.as_bytes())
}

#[inline]
fn hash_clearance(ip: IpAddr, timestamp: u64, level: u8) -> String {
    let key = crate::state::COOKIE_KEY.with(|k| *k.borrow());
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(b"arin-clearance-v1");
    match ip {
        IpAddr::V4(addr) => { hasher.update(&addr.octets()); }
        IpAddr::V6(addr) => { hasher.update(&addr.octets()); }
    }
    hasher.update(&[level]);
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
    let permit = sem.acquire_owned().await.map_err(|e| e.to_string())?;
    
    let (parts, body) = req.into_parts();
    
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
    
    let proxied_req = builder.body(body.boxed()).map_err(|e| e.to_string())?;
    
    let response = crate::state::HTTP_CLIENT.with(|client| {
        let client = (*client.borrow()).clone().unwrap();
        client.request(proxied_req)
    }).await.map_err(|e| e.to_string())?;
    
    let (parts, body) = response.into_parts();
    let body = body.map_frame(move |frame| {
        let _ = &permit;
        frame
    }).boxed();
    Ok(Response::from_parts(parts, body))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_proof_matches_cdn_algorithm() {
        assert!(verify_js_proof("test", 95));
        assert!(!verify_js_proof("test", 94));
    }

    #[test]
    fn pow_ticket_is_bound_and_expires() {
        let ip = "192.0.2.1".parse().unwrap();
        let ticket = create_pow_ticket(ip, "example.com", 100);
        assert!(verify_pow_ticket(&ticket, ip, "example.com", 100));
        assert!(!verify_pow_ticket(&ticket, "192.0.2.2".parse().unwrap(), "example.com", 100));
        assert!(!verify_pow_ticket(&ticket, ip, "other.example", 100));
        assert!(!verify_pow_ticket(&ticket, ip, "example.com", 161));
    }

    #[test]
    fn clearance_advances_one_stage_at_a_time() {
        let ip = "192.0.2.1".parse().unwrap();
        for level in 1..=3 {
            let value = create_challenge_cookie_value(ip, 100, level);
            assert_eq!(challenge_clearance(&format!("Arin={}", value), ip, 100), level);
        }
        let value = create_challenge_cookie_value(ip, 100, 4);
        assert_eq!(challenge_clearance(&format!("Arin={}", value), ip, 100), 0);
        let value = create_challenge_cookie_value(ip, 100, 3);
        assert_eq!(challenge_clearance(&format!("Arin={}", value), "192.0.2.2".parse().unwrap(), 100), 0);
        assert_eq!(challenge_clearance(&format!("Arin={}", value), ip, 401), 0);
        assert_eq!(next_challenge_stage(0, 4), Some(1));
        assert_eq!(next_challenge_stage(1, 4), Some(2));
        assert_eq!(next_challenge_stage(2, 4), Some(3));
        assert_eq!(next_challenge_stage(3, 4), Some(4));
        assert_eq!(next_challenge_stage(4, 4), None);
    }

    #[test]
    fn subresources_never_receive_challenges() {
        let image = Request::builder()
            .header("Sec-Fetch-Dest", "image")
            .uri("/anything")
            .body(())
            .unwrap();
        let document = Request::builder()
            .header("Sec-Fetch-Dest", "document")
            .uri("/anything.png")
            .body(())
            .unwrap();
        let legacy_asset = Request::builder()
            .uri("/anything.png")
            .body(())
            .unwrap();
        assert!(is_subresource_request(&image));
        assert!(!is_subresource_request(&document));
        assert!(is_subresource_request(&legacy_asset));
    }
}
