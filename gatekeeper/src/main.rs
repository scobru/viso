//! Viso PoH Blind-RSA Gatekeeper server and keygen CLI.

mod core;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::core::{
    decode_blinded_msg, ensure_provider_issuer, generate_issuer_keypair, issue_blind_token,
    issue_google_blind_token, load_issuer_from_config, load_or_init_issuers_json, now_unix_ms,
    now_unix_secs, purge_expired_pending, validate_blinded_msg, ConfiguredIssuer, GitHubUser,
    GoogleUser, IssueError, IssuerConfigJson, NullifierStore, PendingOAuth, PublicIssuerInfo,
    MAX_PENDING_STATES,
};

const RATE_WINDOW_MS: u64 = 10 * 60 * 1000;
const RATE_MAX_REQS_PER_IP: usize = 30;
const MAX_RATE_TRACKED_IPS: usize = 10_000;

#[derive(Clone)]
struct OAuthCreds {
    client_id: String,
    client_secret: String,
}

struct AppState {
    http: reqwest::Client,
    public_base_url: String,
    github: Option<OAuthCreds>,
    google: Option<OAuthCreds>,
    hmac_secret: Vec<u8>,
    issuers: HashMap<String, ConfiguredIssuer>,
    store: Mutex<NullifierStore>,
    pending: Mutex<HashMap<String, PendingOAuth>>,
    rate_limits: Mutex<HashMap<String, Vec<u64>>>,
}

#[derive(Deserialize)]
struct OAuthStartQuery {
    key_id: String,
    blinded: String,
}

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("keygen") {
        if let Err(e) = run_keygen(&args[2..]) {
            eprintln!("keygen error: {e}");
            std::process::exit(1);
        }
        return;
    }

    if let Err(e) = run_server().await {
        eprintln!("gatekeeper error: {e}");
        std::process::exit(1);
    }
}

fn run_keygen(args: &[String]) -> Result<(), String> {
    let mut key_id = None;
    let mut out_dir = PathBuf::from("./keys");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key-id" => {
                i += 1;
                key_id = args.get(i).cloned();
            }
            "--out-dir" => {
                i += 1;
                out_dir = PathBuf::from(args.get(i).ok_or("missing --out-dir value")?);
            }
            other => return Err(format!("unknown arg {other:?}; usage: keygen --key-id <provider:tier:epoch> [--out-dir <dir>]")),
        }
        i += 1;
    }
    let key_id = key_id.ok_or("missing --key-id (e.g. github:age1y:2026)")?;
    let parts: Vec<&str> = key_id.split(':').collect();
    if parts.len() != 3 {
        return Err("key_id must have format <provider>:<tier>:<epoch>".into());
    }
    let (sk_path, pk_path, spki_der) = generate_issuer_keypair(&key_id, &out_dir)?;
    println!("Generated issuer keypair for {key_id}:");
    println!("  Private (PKCS#8 DER): {}", sk_path.display());
    println!("  Public  (SPKI DER):   {}", pk_path.display());
    println!("\nAdd to viso-core POH_ISSUERS:");
    println!("PohIssuer {{");
    println!("    key_id: {:?},", key_id);
    println!("    provider: {:?},", parts[0]);
    println!("    tier: {:?},", parts[1]);
    println!("    epoch: {:?},", parts[2]);
    println!("    spki_der: &{:?},", spki_der);
    println!("}},");
    Ok(())
}

fn load_or_create_hmac_secret(data_dir: &Path) -> Result<Vec<u8>, String> {
    if let Ok(hex) = env::var("HMAC_SECRET") {
        let trimmed = hex.trim();
        if trimmed.len() >= 32 {
            return Ok(trimmed.as_bytes().to_vec());
        }
        return Err("HMAC_SECRET must be at least 32 characters".into());
    }
    fs::create_dir_all(data_dir).map_err(|e| format!("create {}: {e}", data_dir.display()))?;
    let path = data_dir.join("hmac.secret");
    if path.exists() {
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if bytes.len() < 32 {
            return Err("stored hmac.secret is too short".into());
        }
        return Ok(bytes);
    }
    let mut secret = vec![0u8; 32];
    OsRng.fill_bytes(&mut secret);
    crate::core::write_secret(&path, &secret)?;
    Ok(secret)
}

fn optional_creds(id_var: &str, secret_var: &str) -> Result<Option<OAuthCreds>, String> {
    let id = env::var(id_var).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let secret = env::var(secret_var).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    match (id, secret) {
        (Some(client_id), Some(client_secret)) => Ok(Some(OAuthCreds { client_id, client_secret })),
        (None, None) => Ok(None),
        _ => Err(format!("both {id_var} and {secret_var} must be set together")),
    }
}

async fn run_server() -> Result<(), String> {
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let public_base_url = env::var("PUBLIC_BASE_URL")
        .map_err(|_| "PUBLIC_BASE_URL env var is required (e.g. https://poh.viso.example)".to_string())?
        .trim_end_matches('/')
        .to_string();
    let github = optional_creds("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET")?;
    let google = optional_creds("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")?;
    if github.is_none() && google.is_none() {
        return Err("configure at least one OAuth provider (GITHUB_CLIENT_ID/SECRET or GOOGLE_CLIENT_ID/SECRET)".into());
    }
    let data_dir = PathBuf::from(env::var("DATA_DIR").unwrap_or_else(|_| "./data".into()));

    let auto_init = matches!(
        env::var("AUTO_INIT_ISSUER").ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    );
    let issuers_path = env::var("ISSUERS_CONFIG").unwrap_or_else(|_| "./issuers.json".into());
    let from_env = env::var("ISSUERS_JSON").ok().filter(|s| !s.trim().is_empty());

    let mut cfg_list: Vec<IssuerConfigJson> = match from_env {
        Some(ref raw) => serde_json::from_str(raw).map_err(|e| format!("parse ISSUERS_JSON: {e}"))?,
        None => {
            let default_kid = if github.is_some() { "github:age1y:2026" } else { "google:verified:2026" };
            let key_id = env::var("AUTO_KEY_ID").unwrap_or_else(|_| default_kid.into());
            let min_age_days = env::var("AUTO_MIN_AGE_DAYS")
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(if key_id.starts_with("google:") { 0 } else { 365 });
            let min_public_repos = env::var("AUTO_MIN_PUBLIC_REPOS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let (raw, created) = load_or_init_issuers_json(
                Path::new(&issuers_path),
                &data_dir,
                auto_init,
                &key_id,
                min_age_days,
                min_public_repos,
            )?;
            if created {
                eprintln!(
                    "Auto-initialized PoH issuer {key_id} in {issuers_path} (ensure DATA_DIR={} is persisted on CapRover).",
                    data_dir.display()
                );
            }
            serde_json::from_str(&raw).map_err(|e| format!("parse {issuers_path}: {e}"))?
        }
    };
    if auto_init && google.is_some() {
        let google_kid = env::var("AUTO_GOOGLE_KEY_ID").unwrap_or_else(|_| "google:verified:2026".into());
        let persist = from_env.is_none().then(|| Path::new(&issuers_path));
        if ensure_provider_issuer(&mut cfg_list, persist, &data_dir, &google_kid, 0, 0)? {
            eprintln!("Auto-initialized Google PoH issuer {google_kid}.");
        }
    }
    if cfg_list.is_empty() {
        return Err("issuers config must define at least one issuer".into());
    }

    let mut issuers = HashMap::new();
    for c in &cfg_list {
        let loaded = load_issuer_from_config(c)?;
        issuers.insert(loaded.key_id.clone(), loaded);
    }

    let hmac_secret = load_or_create_hmac_secret(&data_dir)?;
    let store = NullifierStore::open(data_dir.join("nullifiers.log"))?;

    let state = Arc::new(AppState {
        http: reqwest::Client::builder()
            .user_agent("viso-gatekeeper/0.1")
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?,
        public_base_url,
        github,
        google,
        hmac_secret,
        issuers,
        store: Mutex::new(store),
        pending: Mutex::new(HashMap::new()),
        rate_limits: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/keys", get(keys))
        .route("/github", get(github_start))
        .route("/github/callback", get(github_callback))
        .route("/google", get(google_start))
        .route("/google/callback", get(google_callback))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("bind {bind_addr}: {e}"))?;
    println!("viso-gatekeeper listening on {bind_addr}");
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("serve error: {e}"))
}

async fn health() -> &'static str {
    "ok"
}

async fn keys(State(state): State<Arc<AppState>>) -> (HeaderMap, Json<Vec<PublicIssuerInfo>>) {
    let list = state
        .issuers
        .values()
        .map(|i| PublicIssuerInfo {
            key_id: i.key_id.clone(),
            provider: i.provider.clone(),
            tier: i.tier.clone(),
            epoch: i.epoch.clone(),
            min_age_days: i.min_age_days,
            min_public_repos: i.min_public_repos,
            spki_b64: STANDARD.encode(&i.spki_der),
        })
        .collect();
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    (headers, Json(list))
}

async fn begin_oauth(
    state: &AppState,
    provider: &str,
    q: &OAuthStartQuery,
) -> Result<(String, String), Response> {
    let Some(issuer) = state.issuers.get(&q.key_id) else {
        return Err(html_error(StatusCode::BAD_REQUEST, "Unknown or disabled key_id."));
    };
    if issuer.provider != provider {
        return Err(html_error(
            StatusCode::BAD_REQUEST,
            &format!("Selected key_id is not a {provider} issuer."),
        ));
    }
    let blinded_msg = decode_blinded_msg(&q.blinded, issuer.modulus_bytes)
        .and_then(|bytes| {
            validate_blinded_msg(&bytes, issuer)?;
            Ok(bytes)
        })
        .map_err(|e| html_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let mut rand_state = [0u8; 24];
    OsRng.fill_bytes(&mut rand_state);
    let oauth_state = URL_SAFE_NO_PAD.encode(rand_state);
    let now_ms = now_unix_ms();

    let mut pending = state.pending.lock().await;
    purge_expired_pending(&mut pending, now_ms);
    if pending.len() >= MAX_PENDING_STATES {
        return Err(html_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many pending OAuth requests; retry shortly.",
        ));
    }
    pending.insert(
        oauth_state.clone(),
        PendingOAuth {
            key_id: issuer.key_id.clone(),
            blinded_msg,
            created_at_ms: now_ms,
        },
    );
    Ok((oauth_state, format!("{}/{provider}/callback", state.public_base_url)))
}

async fn consume_callback<'a>(
    state: &'a AppState,
    provider_label: &str,
    q: OAuthCallbackQuery,
) -> Result<(String, PendingOAuth, &'a ConfiguredIssuer), Response> {
    if let Some(err) = q.error {
        return Err(html_error(
            StatusCode::BAD_REQUEST,
            &format!("{provider_label} authorization cancelled or failed: {err}"),
        ));
    }
    let (Some(code), Some(oauth_state)) = (q.code, q.state) else {
        return Err(html_error(StatusCode::BAD_REQUEST, "Missing code or state parameter."));
    };
    let entry = {
        let mut pending = state.pending.lock().await;
        purge_expired_pending(&mut pending, now_unix_ms());
        pending.remove(&oauth_state)
    }
    .ok_or_else(|| html_error(StatusCode::BAD_REQUEST, "OAuth state expired or already used. Please restart from Viso."))?;
    let issuer = state
        .issuers
        .get(&entry.key_id)
        .ok_or_else(|| html_error(StatusCode::INTERNAL_SERVER_ERROR, "Configured issuer disappeared."))?;
    Ok((code, entry, issuer))
}

async fn exchange_code(
    state: &AppState,
    provider_label: &str,
    token_url: &str,
    creds: &OAuthCreds,
    code: &str,
    redirect_uri: &str,
    extra_grant: Option<(&str, &str)>,
) -> Result<String, Response> {
    let mut form = vec![
        ("client_id", creds.client_id.as_str()),
        ("client_secret", creds.client_secret.as_str()),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(g) = extra_grant {
        form.push(g);
    }
    let res = state
        .http
        .post(token_url)
        .header(header::ACCEPT, "application/json")
        .form(&form)
        .send()
        .await;
    match res {
        Ok(resp) if resp.status().is_success() => match resp.json::<TokenResponse>().await {
            Ok(tr) => tr.access_token.ok_or_else(|| {
                let msg = tr.error_description.or(tr.error).unwrap_or_else(|| "missing access_token".into());
                html_error(StatusCode::BAD_GATEWAY, &format!("{provider_label} OAuth failed: {msg}"))
            }),
            Err(e) => Err(html_error(StatusCode::BAD_GATEWAY, &format!("Bad {provider_label} token JSON: {e}"))),
        },
        Ok(resp) => Err(html_error(StatusCode::BAD_GATEWAY, &format!("{provider_label} token endpoint returned {}", resp.status()))),
        Err(e) => Err(html_error(StatusCode::BAD_GATEWAY, &format!("Failed contacting {provider_label}: {e}"))),
    }
}

fn finish_token_response(provider_label: &str, issuer: &ConfiguredIssuer, issued: Result<String, IssueError>) -> Response {
    match issued {
        Ok(token) => html_token_success(provider_label, &token, &issuer.key_id),
        Err(IssueError::Ineligible(m)) => html_error(StatusCode::FORBIDDEN, &m),
        Err(IssueError::AlreadyClaimed(m)) => html_error(StatusCode::CONFLICT, &m),
        Err(IssueError::BadRequest(m)) => html_error(StatusCode::BAD_REQUEST, &m),
        Err(IssueError::Internal(m)) => html_error(StatusCode::INTERNAL_SERVER_ERROR, &m),
    }
}

fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("direct")
        .chars()
        .take(64)
        .collect()
}

async fn check_rate_limit(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let ip = client_ip(headers);
    let now = now_unix_ms();
    let cutoff = now.saturating_sub(RATE_WINDOW_MS);
    let mut map = state.rate_limits.lock().await;
    if map.len() >= MAX_RATE_TRACKED_IPS {
        map.retain(|_, ts| {
            ts.retain(|&t| t >= cutoff);
            !ts.is_empty()
        });
    }
    let entry = map.entry(ip).or_default();
    entry.retain(|&t| t >= cutoff);
    if entry.len() >= RATE_MAX_REQS_PER_IP {
        return Err(html_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many verification attempts from this address. Please wait a few minutes and retry.",
        ));
    }
    entry.push(now);
    Ok(())
}

async fn github_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<OAuthStartQuery>,
) -> Response {
    if let Err(resp) = check_rate_limit(&state, &headers).await {
        return resp;
    }
    let Some(creds) = state.github.as_ref() else {
        return html_error(StatusCode::SERVICE_UNAVAILABLE, "GitHub OAuth is not configured on this gatekeeper.");
    };
    let (oauth_state, redirect_uri) = match begin_oauth(&state, "github", &q).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
        url_encode(&creds.client_id),
        url_encode(&redirect_uri),
        url_encode(&oauth_state),
    );
    Redirect::temporary(&url).into_response()
}

async fn github_callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OAuthCallbackQuery>,
) -> Response {
    let Some(creds) = state.github.as_ref() else {
        return html_error(StatusCode::SERVICE_UNAVAILABLE, "GitHub OAuth is not configured on this gatekeeper.");
    };
    let (code, entry, issuer) = match consume_callback(&state, "GitHub", q).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let redirect_uri = format!("{}/github/callback", state.public_base_url);
    let access_token = match exchange_code(
        &state,
        "GitHub",
        "https://github.com/login/oauth/access_token",
        creds,
        &code,
        &redirect_uri,
        None,
    )
    .await
    {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let user_res = state
        .http
        .get("https://api.github.com/user")
        .bearer_auth(&access_token)
        .header(header::ACCEPT, "application/vnd.github+json")
        .send()
        .await;
    let user = match user_res {
        Ok(resp) if resp.status().is_success() => match resp.json::<GitHubUser>().await {
            Ok(u) => u,
            Err(e) => return html_error(StatusCode::BAD_GATEWAY, &format!("Bad GitHub /user JSON: {e}")),
        },
        Ok(resp) => return html_error(StatusCode::BAD_GATEWAY, &format!("GitHub /user returned {}", resp.status())),
        Err(e) => return html_error(StatusCode::BAD_GATEWAY, &format!("Failed reading GitHub /user: {e}")),
    };

    let issued = {
        let mut store = state.store.lock().await;
        issue_blind_token(&mut store, &state.hmac_secret, issuer, &user, &entry.blinded_msg, now_unix_secs())
    };
    finish_token_response("GitHub", issuer, issued)
}

async fn google_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<OAuthStartQuery>,
) -> Response {
    if let Err(resp) = check_rate_limit(&state, &headers).await {
        return resp;
    }
    let Some(creds) = state.google.as_ref() else {
        return html_error(StatusCode::SERVICE_UNAVAILABLE, "Google OAuth is not configured on this gatekeeper.");
    };
    let (oauth_state, redirect_uri) = match begin_oauth(&state, "google", &q).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email&state={}",
        url_encode(&creds.client_id),
        url_encode(&redirect_uri),
        url_encode(&oauth_state),
    );
    Redirect::temporary(&url).into_response()
}

async fn google_callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<OAuthCallbackQuery>,
) -> Response {
    let Some(creds) = state.google.as_ref() else {
        return html_error(StatusCode::SERVICE_UNAVAILABLE, "Google OAuth is not configured on this gatekeeper.");
    };
    let (code, entry, issuer) = match consume_callback(&state, "Google", q).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let redirect_uri = format!("{}/google/callback", state.public_base_url);
    let access_token = match exchange_code(
        &state,
        "Google",
        "https://oauth2.googleapis.com/token",
        creds,
        &code,
        &redirect_uri,
        Some(("grant_type", "authorization_code")),
    )
    .await
    {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let user_res = state
        .http
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(&access_token)
        .send()
        .await;
    let user = match user_res {
        Ok(resp) if resp.status().is_success() => match resp.json::<GoogleUser>().await {
            Ok(u) => u,
            Err(e) => return html_error(StatusCode::BAD_GATEWAY, &format!("Bad Google userinfo JSON: {e}")),
        },
        Ok(resp) => return html_error(StatusCode::BAD_GATEWAY, &format!("Google userinfo returned {}", resp.status())),
        Err(e) => return html_error(StatusCode::BAD_GATEWAY, &format!("Failed reading Google userinfo: {e}")),
    };

    let issued = {
        let mut store = state.store.lock().await;
        issue_google_blind_token(&mut store, &state.hmac_secret, issuer, &user, &entry.blinded_msg, now_unix_secs())
    };
    finish_token_response("Google", issuer, issued)
}

fn no_store_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            .parse()
            .unwrap(),
    );
    h
}

fn html_token_success(provider_label: &str, token: &str, key_id: &str) -> Response {
    let esc_provider = html_escape(provider_label);
    let esc_token = html_escape(token);
    let esc_key_id = html_escape(key_id);
    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Viso Proof-of-Personhood Token</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1rem; color: #111; line-height: 1.5; }}
  .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 1.5rem; background: #fafafa; }}
  textarea {{ width: 100%; min-height: 110px; font-family: monospace; font-size: 0.85rem; padding: 0.75rem; box-sizing: border-box; }}
  button {{ margin-top: 0.75rem; padding: 0.6rem 1.1rem; font-size: 0.95rem; border-radius: 6px; border: 0; background: #111; color: #fff; cursor: pointer; }}
  .muted {{ color: #555; font-size: 0.9rem; }}
</style>
</head>
<body>
<div class="card">
  <h2>{esc_provider} eligibility verified</h2>
  <p class="muted">Tier: <code>{esc_key_id}</code>. This service never saw your Viso public key.</p>
  <p>Copy this blind-signed token back into Viso to attach the anonymous badge to your persona:</p>
  <textarea id="tok" readonly>{esc_token}</textarea>
  <br>
  <button onclick="navigator.clipboard.writeText(document.getElementById('tok').value).then(() => this.textContent = 'Copied!')">Copy token</button>
</div>
</body>
</html>"#
    );
    (StatusCode::OK, no_store_headers(), Html(body)).into_response()
}

fn html_error(status: StatusCode, msg: &str) -> Response {
    let esc_msg = html_escape(msg);
    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Viso Gatekeeper Error</title></head>
<body style="font-family:system-ui,sans-serif;max-width:600px;margin:3rem auto;padding:0 1rem;">
  <h2>Could not issue attestation</h2>
  <p>{esc_msg}</p>
</body>
</html>"#
    );
    (status, no_store_headers(), Html(body)).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
