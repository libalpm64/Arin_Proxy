use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_web::http::header;
use actix_web::cookie::Cookie;
use actix_web::rt::time::sleep;
use awc::Client;
use crate::blake3;
use log::{info, warn, error, debug};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::atomic::Ordering;

use crate::state::AppState;
use crate::pow::{POW_DIFFICULTY, generate_challenge_secret, generate_pow_html};

pub const STAGE_THRESHOLD: u64 = 500;
pub const IP_ENTRY_STALE_DURATION: u64 = 60;
pub const SOFT_RL_LIMIT: u64 = 800;
pub const HARD_RL_LIMIT: u64 = 1000;
pub const MAX_BACKOFF_MS: u64 = 200;

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
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<std::sync::Arc<AppState>>,
) -> Result<HttpResponse, Error> {
    let client_ip = {
        let connection_info = req.connection_info();
        connection_info
            .realip_remote_addr()
            .ok_or_else(|| {
                error!("Failed to determine client IP");
                actix_web::error::ErrorBadRequest("Cannot determine client IP")
            })?
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string()
    };

    // fixed-bucket counters setup for ratleimits.
    // approates a sliding time window efficently.
    // tracks per-IP or per-request counts without unbounded memory growth or heap churn. 
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Increment global request counter immediately; no per-domain iteration required
    // Saves on slow syscalls by not required to fetch from other locations.
    // Avoids having to put it in the jump table as it's just saved as rcx, rax, rdi. (Avoids relocations)
    state.global_total_requests.fetch_add(1, Ordering::Relaxed);
    let request_count = state
        .ip_update_and_get_batched(&client_ip, now_secs, IP_ENTRY_STALE_DURATION);

    if request_count >= SOFT_RL_LIMIT {
        let backoff_ms = ((request_count - SOFT_RL_LIMIT) * MAX_BACKOFF_MS)
            / (HARD_RL_LIMIT - SOFT_RL_LIMIT);
        if backoff_ms > 0 {
            sleep(Duration::from_millis(backoff_ms)).await;
        }
    }

    if request_count > HARD_RL_LIMIT {
        let retry_secs: u64 = 1 + ((request_count - HARD_RL_LIMIT) / 100).min(10);
        let mut resp = HttpResponse::TooManyRequests();
        resp.insert_header((header::RETRY_AFTER, retry_secs.to_string()));
        resp.insert_header(("X-Backoff-ms", MAX_BACKOFF_MS.to_string()));
        return Ok(resp.body("Too many requests"));
    }
    let domain = match req.headers().get("host").and_then(|h| h.to_str().ok()) {
        Some(domain) => domain,
        None => {
            return Err(actix_web::error::ErrorBadRequest("Invalid domain"));
        }
    };
        
    if req.method() == actix_web::http::Method::POST && req.path() == "/pow/validate" {
        return validate_pow(req, body, state).await;
    }

    let ip = derive_ip(&req, domain, &state).unwrap_or_else(|| {
        warn!("Could not determine client IP for domain: {}", domain);
        "".to_string()
    });

    if ip.is_empty() {
        warn!("Empty IP address for domain: {}", domain);
        return Err(actix_web::error::ErrorBadRequest("Cannot determine client IP"));
    }

    // Update IP request tracking with batched local increments (no immediate readback)
    // Avoid double counting if CF-Connecting-IP equals the connection IP
    if ip != client_ip {
        state.ip_update_local_batch(&ip, now_secs, IP_ENTRY_STALE_DURATION);
    }

    let cookie_str = req
        .headers()
        .get("cookie")
        .and_then(|c| c.to_str().ok())
        .unwrap_or("");

    debug!("Cookie string received: {}", cookie_str);
    let cookie_valid = verify_challenge_cookie(cookie_str, &ip, now_secs, &state.cookie_key);
    debug!("Cookie validation result: {} (IP: {}, Time: {})", cookie_valid, ip, now_secs);

    let (current_stage, backend_base, request_allowed) = match state.domains.get_mut(domain) {
        Some(mut domain_settings) => {
            domain_settings.total_requests.fetch_add(1, Ordering::Relaxed);
            if domain_settings
                .last_reset
                .map_or(true, |last_reset| last_reset.elapsed() >= Duration::from_secs(1))
            {
                if domain_settings.bypassed_requests.load(Ordering::Relaxed) >= STAGE_THRESHOLD {
                    // Atomic Stage update counter with cached pointer
                    // If staged_ptr is Some we point it directly to an AtomicUSize data store.
                    // We avoid having a hashmap lookup by using this cache pointer which increases speed.
                    if let Some(stage_arc) = domain_settings.stage_ptr.as_ref() {
                        let cur = stage_arc.load(Ordering::Relaxed);
                        let new = (cur + 1).min(3);
                        stage_arc.store(new, Ordering::Relaxed);
                        domain_settings.current_stage = new;
                        debug!("Domain {} advanced to stage {}", domain, new);
                    } else if let Some(entry) = state.stages.get(domain) {
                        let cur = entry.value().load(Ordering::Relaxed);
                        let new = (cur + 1).min(3);
                        entry.value().store(new, Ordering::Relaxed);
                        domain_settings.current_stage = new;
                        debug!("Domain {} advanced to stage {}", domain, new);
                    }
                }
                domain_settings.bypassed_requests.store(0, Ordering::Relaxed);
                domain_settings.last_reset = Some(std::time::Instant::now());
            }
            
            // Read current stage from cached pointer or shared map
            let stage = if let Some(stage_arc) = domain_settings.stage_ptr.as_ref() {
                stage_arc.load(Ordering::Relaxed)
            } else {
                state
                    .stages
                    .get(domain)
                    .map(|e| e.value().load(Ordering::Relaxed))
                    .unwrap_or(domain_settings.current_stage)
            };
            /*
             Stage allowance:
             - Stage 0 -> All requests allowed
             - Stage 1-2-3 -> Allowed if pass stage challenge
            */
            let allowed = match stage {
                0 => true,
                1 | 2 => cookie_valid,
                3 => { 
                    cookie_valid
                },
                _ => false,
            };
            
            if !cookie_valid && (1..=3).contains(&stage) { // No increment
            } else if allowed {
                domain_settings.bypassed_requests.fetch_add(1, Ordering::Relaxed);
            }
            
            (stage, domain_settings.backend_base.clone(), allowed)
        }
        None => {
            warn!("Request for unconfigured domain: {}", domain);
            return Err(actix_web::error::ErrorNotFound("Domain not configured"));
        }
    };

    if !cookie_valid {
        
        match current_stage {
            0 => { /* Allow request to pass */ }
            1 => {
                let cookie_value = create_challenge_cookie_value(&ip, now_secs, &state.cookie_key);
                let forwarded_proto = req
                    .headers()
                    .get("X-Forwarded-Proto")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| req.connection_info().scheme().to_owned());
                let is_https = forwarded_proto.eq_ignore_ascii_case("https");

                let mut resp = HttpResponse::Ok();
                let mut cookie = Cookie::build("Arin", cookie_value)
                    .path("/")
                    .http_only(true)
                    .finish();
                if is_https {
                    cookie.set_same_site(actix_web::cookie::SameSite::None);
                    cookie.set_secure(true);
                } else {
                    cookie.set_same_site(actix_web::cookie::SameSite::Lax);
                }
                resp.cookie(cookie);
                let html = "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0\"></head><body></body></html>";
                // Count as a challenged request (stage 1)
                state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
                return Ok(resp.content_type("text/html").body(html));
            },
            2 => {
                // Todo !! [Porting]
                // Challenge to do, currently porting Javascript checks this will be done shortly.
                let cookie_value = create_challenge_cookie_value(&ip, now_secs, &state.cookie_key);
                let forwarded_proto = req
                    .headers()
                    .get("X-Forwarded-Proto")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| req.connection_info().scheme().to_owned());
                let cookie_suffix = if forwarded_proto.eq_ignore_ascii_case("https") {
                    "; SameSite=None; Secure"
                } else {
                    "; SameSite=Lax"
                };

                let mut js_challenge = String::with_capacity(160 + cookie_value.len());
                js_challenge.push_str("<!DOCTYPE html><html><head><script>document.cookie = 'Arin=");
                js_challenge.push_str(&cookie_value);
                js_challenge.push_str("; Path=/");
                js_challenge.push_str(cookie_suffix);
                js_challenge.push_str("';window.location.reload();</script></head><body></body></html>");
                state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
                return Ok(HttpResponse::Ok().content_type("text/html").body(js_challenge));
            },
            3 => {
                let challenge_secret = generate_challenge_secret();
                let pow_html = match generate_pow_html(&challenge_secret, POW_DIFFICULTY) {
                    Ok(html) => html,
                    Err(e) => {
                        error!("Failed to generate PoW HTML: {}", e);
                        return Err(actix_web::error::ErrorInternalServerError("Failed to generate challenge"));
                    }
                };
                state.global_challenged_requests.fetch_add(1, Ordering::Relaxed);
                return Ok(HttpResponse::Ok().content_type("text/html").body(pow_html));
            },
            _ => {
                warn!("Invalid stage {} for domain {}", current_stage, domain);
                return Err(actix_web::error::ErrorForbidden("Request blocked"));
            }
        }
    }

    if !request_allowed {
        return Ok(HttpResponse::Forbidden().body("Request blocked"));
    }
    state.global_allowed_requests.fetch_add(1, Ordering::Relaxed);    
    proxy_request(req, body, &backend_base, &state.http_client).await
}

pub async fn validate_pow(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<std::sync::Arc<AppState>>,
) -> Result<HttpResponse, Error> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let pow_request: PowValidationRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(e) => {
            warn!("Invalid PoW validation request: {}", e);
            return Err(actix_web::error::ErrorBadRequest("Invalid POW validation request"));
        }
    };

    let nonce = pow_request.nonce;
    let challenge_secret = pow_request.challenge_secret;
    let difficulty_bits = POW_DIFFICULTY as usize;
    let verified_rx = state.pow_pool.submit(nonce, challenge_secret, difficulty_bits);
    let verified = verified_rx.await.unwrap_or(false);

    if verified {
        // Ensure consistent client IP derivation with handle_request (strip port and use CF header when available)
        let domain = req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let ip = match derive_ip(&req, domain, &state) {
            Some(ip) if !ip.is_empty() => ip,
            _ => {
                warn!("Could not determine IP for PoW validation");
                return Err(actix_web::error::ErrorBadRequest("Cannot determine client IP"));
            }
        };
        
        let cookie_value = create_challenge_cookie_value(&ip, now_secs, &state.cookie_key);
        
        info!("PoW validation successful for IP: {}", ip);
        
        if let Some(mut domain_settings) = state.domains.get_mut(domain) {
            domain_settings.bypassed_requests.fetch_add(1, Ordering::Relaxed);
            domain_settings.last_pow_success = Some(now_secs);
            debug!("PoW completion counted for domain {}: {} bypassed, last success: {}",
                  domain, domain_settings.bypassed_requests.load(Ordering::Relaxed), now_secs);
        }        
        let mut response = HttpResponse::Ok();
        response.cookie(
            Cookie::build("Arin", cookie_value)
                .path("/")
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .finish()
        );

        Ok(response.json(PowValidationResponse { verified: true }))
    } else {
        warn!("PoW validation failed");
        Ok(HttpResponse::Ok().json(PowValidationResponse { verified: false }))
    }
}

async fn proxy_request(
    req: HttpRequest,
    body: web::Bytes,
    backend_base: &str,
    client: &Client,
) -> Result<HttpResponse, actix_web::Error> {
    /* 
     Request cleanup, Cull them after 30 seconds we might want to change this later.
     Some clients have slow request loading or slow Android devices.
    */ 
    let timeout_duration = std::time::Duration::from_secs(30);
    if backend_base.is_empty() {
        error!("Empty backend URL");
        return Err(actix_web::error::ErrorInternalServerError("Backend not configured"));
    }

    let original_host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let path_q = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("");
    let mut backend_url = String::with_capacity(backend_base.len() + path_q.len());
    backend_url.push_str(backend_base);
    backend_url.push_str(path_q);

    // Reuse global AWC client to avoid per-request builder overhead
    let mut req_builder = client.request(req.method().clone(), backend_url.as_str());

    /* 
     Manually parse headers to avoid hop-by-hop headers and other compressors
     This saves CPU resources from having to read the entire HTTP Header.
     Which will allow for more requests to be processed 
    */ 
    for (name, value) in req.headers() {
        let s = name.as_str();
        if is_hop_req_header(s) { continue; }
        req_builder = req_builder.insert_header((name.clone(), value.clone()));
    }
    
    if let Ok(host_val) = header::HeaderValue::from_str(original_host) {
        req_builder = req_builder.insert_header((header::HOST, host_val));
    }

    // Disable automatic compression in the request builder. Saves CPU utilization by using Zero-Copy Costs.
    let backend_response = req_builder
        .no_decompress()
        .send_body(body)
        .await
        .map_err(|e| {
            error!("Failed to send request to backend: {}", e);
            actix_web::error::ErrorBadGateway("Backend request failed or timed out")
        })?;
    
    let status = backend_response.status();
    let mut client_resp = HttpResponse::build(status);
    
    /* 
     Manually parse headers to avoid hop-by-hop headers and other compressors
     This saves CPU resources from having to read the entire HTTP Header.
     Which will allow for more requests to be processed.
    */
    for (name, value) in backend_response.headers() {
        let s = name.as_str();
        if is_hop_resp_header(s) { continue; }
        client_resp.insert_header((name.clone(), value.clone()));
    }

    // Stream body directly to client to avoid buffering
    Ok(client_resp.streaming(backend_response))
}

#[inline]
fn create_challenge_cookie_value(ip: &str, timestamp: u64, key: &[u8; 32]) -> String {
    hash_ip_with_timestamp(ip, timestamp, key)
}

#[inline]
fn verify_challenge_cookie(cookie_str: &str, ip: &str, current_time: u64, key: &[u8; 32]) -> bool {
    let provided_opt = cookie_str
        .split(';')
        .find_map(|s| {
            let trimmed = s.trim();
            trimmed.strip_prefix("Arin=").map(|v| v.trim().trim_matches('"'))
        });

    if let Some(provided) = provided_opt {
        // Compute expected hash at current_time only; accept slight clock skew by checking previous seconds.
        // This keeps verification O(1) with small constant steps.
        for dt in 0..=60 {
            let t = current_time.saturating_sub(dt);
            let expected = hash_ip_with_timestamp(ip, t, key);
            if ct_eq(provided.as_bytes(), expected.as_bytes()) {
                return true;
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
fn hash_ip_with_timestamp(ip: &str, timestamp: u64, key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(ip.as_bytes());
    hasher.update(&timestamp.to_be_bytes());
    let bytes = hasher.finalize();
    hex_encode(bytes.as_bytes())
}

pub async fn get_proxy_stats(
    state: web::Data<std::sync::Arc<AppState>>,
) -> Result<HttpResponse, Error> {
    let total = state.global_total_requests.load(Ordering::Relaxed);
    let challenged = state.global_challenged_requests.load(Ordering::Relaxed);
    let allowed = state.global_allowed_requests.load(Ordering::Relaxed);
    let stats = ProxyStats {
        total_requests: total,
        challenged_requests: challenged,
        allowed_requests: allowed,
    };

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(stats))
}
#[inline]
fn derive_ip(req: &HttpRequest, domain: &str, state: &AppState) -> Option<String> {
    match state.domains.get(domain) {
        Some(domain_settings) if domain_settings.cloudflare_mode => {
            req.headers()
                .get("CF-Connecting-IP")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        }
        _ => req
            .connection_info()
            .realip_remote_addr()
            .map(|addr| addr.split(':').next().unwrap_or("").to_string()),
    }
}
#[inline]
fn is_hop_req_header(name: &str) -> bool {
    const H: [&str; 10] = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "accept-encoding",
    ];
    for h in &H { if name.eq_ignore_ascii_case(h) { return true; } }
    false
}

#[inline]
fn is_hop_resp_header(name: &str) -> bool {
    const H: [&str; 9] = [
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "upgrade",
    ];
    for h in &H { if name.eq_ignore_ascii_case(h) { return true; } }
    false
}