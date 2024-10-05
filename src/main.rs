use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;
use blake3;
use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, Error};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use dashmap::DashMap;
use sha2::{Sha256, Digest};
use rand::Rng;

#[derive(Clone, Serialize, Deserialize)]
struct DomainSettings {
    backend: String,
    cloudflare_mode: bool,
    #[serde(default)]
    stage: Option<u8>,
    #[serde(skip)]
    total_requests: u64,
    #[serde(skip)]
    bypassed_requests: u64,
    #[serde(skip)]
    last_reset: Option<Instant>,
    #[serde(skip)]
    current_stage: u8,
}

lazy_static! {
    static ref STATE: Arc<AppState> = {
        let config: Config = serde_json::from_reader(BufReader::new(File::open("config.json").unwrap())).unwrap();

        let domains: DashMap<String, DomainSettings> = config.domains.into_iter().map(|(k, mut v)| {
            v.current_stage = v.stage.unwrap_or(0);
            v.last_reset = Some(Instant::now());
            (k, v)
        }).collect();

        Arc::new(AppState {
            domains,
            ip_requests: DashMap::new(),
            cookie_secret: config.cookie_secret.into_bytes(),
        })
    };
}

#[derive(Serialize, Deserialize)]
struct Config {
    domains: HashMap<String, DomainSettings>,
    cookie_secret: String,
}

#[derive(Deserialize)]
struct PowValidationRequest {
    private_salt: String,
    public_salt: String,
}

#[derive(Serialize)]
struct PowValidationResponse {
    verified: bool,
}

struct AppState {
    domains: DashMap<String, DomainSettings>,
    ip_requests: DashMap<String, (u64, Instant)>,
    cookie_secret: Vec<u8>,
}

const STAGE_THRESHOLD: u64 = 500;
const COOKIE_VALIDITY_DURATION: u64 = 3600;
const POW_DIFFICULTY: u64 = 6;

async fn handle_request(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<Arc<AppState>>,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    let domain = req.headers().get("host").and_then(|h| h.to_str().ok()).ok_or_else(|| actix_web::error::ErrorBadRequest("Invalid domain"))?;
    
    if req.method() == actix_web::http::Method::POST && req.path() == "/pow/validate" {
        return validate_pow(req, body, state, client).await;
    }
    let ip = if state.domains.get(domain).map(|d| d.cloudflare_mode).unwrap_or(false) {
        req.headers().get("CF-Connecting-IP").and_then(|h| h.to_str().ok()).unwrap_or("").to_string()
    } else {
        req.connection_info().realip_remote_addr().unwrap_or("").to_string()
    };

    {
        let mut ip_entry = state.ip_requests.entry(ip.clone()).or_insert((0, Instant::now()));
        let (count, last_reset) = &mut *ip_entry;
        if last_reset.elapsed() > Duration::from_secs(60) {
            *count = 1;
            *last_reset = Instant::now();
        } else {
            *count += 1;
        }
    }

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let cookie_str = req.headers().get("cookie")
        .and_then(|c| c.to_str().ok())
        .unwrap_or("");

    let cookie_valid = verify_challenge_cookie(cookie_str, &ip, current_time, &state.cookie_secret);

    let mut current_stage = 0;
    let mut backend = String::new();

    if let Some(mut domain_settings) = state.domains.get_mut(domain) {
        domain_settings.total_requests += 1;

        if domain_settings.last_reset.map_or(true, |last_reset| last_reset.elapsed() >= Duration::from_secs(1)) {
            if domain_settings.bypassed_requests >= STAGE_THRESHOLD {
                domain_settings.current_stage = (domain_settings.current_stage + 1).min(3);
            }
            domain_settings.bypassed_requests = 0;
            domain_settings.last_reset = Some(Instant::now());
        }

        current_stage = domain_settings.current_stage;
        backend = domain_settings.backend.clone();

        if cookie_valid {
            domain_settings.bypassed_requests += 1;
        }
    }

    if !cookie_valid {
        match current_stage {
            0 => {
                
            },
            1 => {
                let challenge_cookie = create_challenge_cookie(&ip, current_time, &state.cookie_secret);
                return Ok(HttpResponse::TemporaryRedirect()
                    .insert_header(("Set-Cookie", format!("{}; SameSite=Lax", challenge_cookie)))
                    .insert_header(("Location", req.uri().to_string()))
                    .finish());
            },
            2 => {
                let challenge_cookie = create_challenge_cookie(&ip, current_time, &state.cookie_secret);
                let js_challenge = format!(
                    r#"<!DOCTYPE html><html><head><script>document.cookie = '{}; SameSite=None; Secure'; window.location.reload();</script></head><body></body></html>"#,
                    challenge_cookie
                );
                return Ok(HttpResponse::Ok().content_type("text/html").body(js_challenge));
            },
            3 => {
                let public_salt = generate_public_salt();
                let pow_html = generate_pow_html(&public_salt, POW_DIFFICULTY);
                return Ok(HttpResponse::Ok().content_type("text/html").body(pow_html));
            },
            _ => return Err(actix_web::error::ErrorForbidden("Request blocked")),
        }
    }

    proxy_request(req, body, &backend, &client).await
}

async fn proxy_request(
    req: HttpRequest,
    body: web::Bytes,
    backend: &str,
    client: &Client,
) -> Result<HttpResponse, Error> {
    let original_host = req.headers().get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let backend_url = format!("http://{}{}", backend, req.uri().path_and_query().map(|x| x.as_str()).unwrap_or(""));
    
    let mut backend_req = client.request(req.method().clone(), &backend_url);
    
    for (name, value) in req.headers() {
        if name != "host" {
            backend_req = backend_req.header(name.clone(), value.clone());
        }
    }
    
    backend_req = backend_req.header("Host", original_host);
    let resp = backend_req.body(body).send().await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Backend request failed: {}", e)))?;
    
    let mut client_resp = HttpResponse::build(resp.status());
    for (name, value) in resp.headers() {
        client_resp.insert_header((name.clone(), value.clone()));
    }

    let bytes = resp.bytes().await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to get response body: {}", e)))?;
    
    Ok(client_resp.body(bytes))
}

#[inline]
fn create_challenge_cookie(ip: &str, timestamp: u64, secret: &[u8]) -> String {
    let cookie_value = hash_ip_with_timestamp(ip, timestamp, secret);
    format!("Arin={}", cookie_value)
}

async fn validate_pow(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<Arc<AppState>>,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    let pow_request: PowValidationRequest = serde_json::from_slice(&body)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid POW validation request"))?;

    let mut hasher = Sha256::new();
    hasher.update(pow_request.public_salt.as_bytes());
    hasher.update(pow_request.private_salt.as_bytes());
    let challenge = format!("{:x}", hasher.finalize());

    let verified = challenge.starts_with(&"0".repeat(POW_DIFFICULTY as usize)); // Use POW_DIFFICULTY here

    if verified {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let ip = req.connection_info().realip_remote_addr().unwrap_or("").to_string();
        let challenge_cookie = create_challenge_cookie(&ip, current_time, &state.cookie_secret);
        
        let mut response = HttpResponse::Ok();
        response.cookie(
            actix_web::cookie::Cookie::build("Arin", challenge_cookie)
                .path("/")
                .http_only(true)
                .same_site(actix_web::cookie::SameSite::Lax)
                .finish()
        );

        let domain = req.headers().get("host").and_then(|h| h.to_str().ok()).ok_or_else(|| actix_web::error::ErrorBadRequest("Invalid domain"))?;
        let backend = state.domains.get(domain).map(|d| d.backend.clone()).ok_or_else(|| actix_web::error::ErrorBadRequest("Invalid domain"))?;

        Ok(response.json(PowValidationResponse { verified: true }))
    } else {
        Ok(HttpResponse::Ok().json(PowValidationResponse { verified: false }))
    }
}

#[inline]
fn verify_challenge_cookie(cookie_str: &str, ip: &str, current_time: u64, secret: &[u8]) -> bool {
    if let Some(arin_cookie) = cookie_str.split(';').find(|s| s.trim().starts_with("Arin=")) {
        let hash = arin_cookie.trim_start_matches("Arin=").trim();
        for t in (current_time.saturating_sub(COOKIE_VALIDITY_DURATION))..=current_time {
            if hash == hash_ip_with_timestamp(ip, t, secret) {
                return true;
            }
        }
    }
    false
}

fn generate_public_salt() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    const SALT_LENGTH: usize = 32;
    let mut rng = rand::thread_rng();

    (0..SALT_LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn generate_pow_html(public_salt: &str, difficulty: u64) -> String {
    let html = include_str!("pow_challenge.html");
    html.replace("{public_salt}", public_salt)
        .replace("{difficulty}", &difficulty.to_string())
}

#[inline]
fn hash_ip_with_timestamp(ip: &str, timestamp: u64, secret: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ip.as_bytes());
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(secret);
    hasher.finalize().to_hex().to_string()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = Client::new();
    
    println!("Arin proxy is running on http://127.0.0.1:3000");
    println!("Configured domains:");
    for entry in STATE.domains.iter() {
        let domain = entry.key();
        let settings = entry.value();
        println!("  {} -> {} (Cloudflare mode: {}, Initial stage: {})", 
                 domain, settings.backend, settings.cloudflare_mode, settings.current_stage);
    }

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(STATE.clone()))
            .app_data(web::Data::new(client.clone()))
            .default_service(web::to(handle_request))
    })
    .bind("127.0.0.1:3000")?
    .run()
    .await
}