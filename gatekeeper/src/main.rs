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
    decode_blinded_msg, generate_issuer_keypair, issue_blind_token, load_issuer_from_config,
    load_or_init_issuers_json, now_unix_ms, now_unix_secs, purge_expired_pending,
    ConfiguredIssuer, GitHubUser, IssueError, IssuerConfigJson, NullifierStore, PendingOAuth,
    PublicIssuerInfo, MAX_PENDING_STATES,
};

struct AppState {
    http: reqwest::Client,
    public_base_url: String,
    github_client_id: String,
    github_client_secret: String,
    hmac_secret: Vec<u8>,
    issuers: HashMap<String, ConfiguredIssuer>,
    store: Mutex<NullifierStore>,
    pending: Mutex<HashMap<String, PendingOAuth>>,
}

#[derive(Deserialize)]
struct GithubStartQuery {
    key_id: String,
    blinded: String,
}

#[derive(Deserialize)]
struct GithubCallbackQuery {
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
    fs::write(&path, &secret).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(secret)
}

async fn run_server() -> Result<(), String> {
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let public_base_url = env::var("PUBLIC_BASE_URL")
        .map_err(|_| "PUBLIC_BASE_URL env var is required (e.g. https://poh.viso.example)".to_string())?
        .trim_end_matches('/')
        .to_string();
    let github_client_id =
        env::var("GITHUB_CLIENT_ID").map_err(|_| "GITHUB_CLIENT_ID env var is required")?;
    let github_client_secret =
        env::var("GITHUB_CLIENT_SECRET").map_err(|_| "GITHUB_CLIENT_SECRET env var is required")?;
    let data_dir = PathBuf::from(env::var("DATA_DIR").unwrap_or_else(|_| "./data".into()));

    let cfg_raw = match env::var("ISSUERS_JSON") {
        Ok(raw) if !raw.trim().is_empty() => raw,
        _ => {
            let issuers_path =
                env::var("ISSUERS_CONFIG").unwrap_or_else(|_| "./issuers.json".into());
            let auto_init = matches!(
                env::var("AUTO_INIT_ISSUER").ok().as_deref(),
                Some("1" | "true" | "TRUE" | "yes" | "YES")
            );
            let key_id = env::var("AUTO_KEY_ID").unwrap_or_else(|_| "github:age1y:2026".into());
            let min_age_days = env::var("AUTO_MIN_AGE_DAYS")
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(365);
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
            raw
        }
    };
    let cfg_list: Vec<IssuerConfigJson> =
        serde_json::from_str(&cfg_raw).map_err(|e| format!("parse issuers config: {e}"))?;
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
            .build()
            .map_err(|e| e.to_string())?,
        public_base_url,
        github_client_id,
        github_client_secret,
        hmac_secret,
        issuers,
        store: Mutex::new(store),
        pending: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/keys", get(keys))
        .route("/github", get(github_start))
        .route("/github/callback", get(github_callback))
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

async fn github_start(
    State(state): State<Arc<AppState>>,
    Query(q): Query<GithubStartQuery>,
) -> Response {
    let Some(issuer) = state.issuers.get(&q.key_id) else {
        return html_error(StatusCode::BAD_REQUEST, "Unknown or disabled key_id.");
    };
    if issuer.provider != "github" {
        return html_error(StatusCode::BAD_REQUEST, "Selected key_id is not a GitHub issuer.");
    }
    let blinded_msg = match decode_blinded_msg(&q.blinded, issuer.modulus_bytes) {
        Ok(b) => b,
        Err(e) => return html_error(StatusCode::BAD_REQUEST, &e.to_string()),
    };

    let mut rand_state = [0u8; 24];
    OsRng.fill_bytes(&mut rand_state);
    let oauth_state = URL_SAFE_NO_PAD.encode(rand_state);
    let now_ms = now_unix_ms();

    {
        let mut pending = state.pending.lock().await;
        purge_expired_pending(&mut pending, now_ms);
        if pending.len() >= MAX_PENDING_STATES {
            return html_error(StatusCode::SERVICE_UNAVAILABLE, "Too many pending OAuth requests; retry shortly.");
        }
        pending.insert(
            oauth_state.clone(),
            PendingOAuth {
                key_id: issuer.key_id.clone(),
                blinded_msg,
                created_at_ms: now_ms,
            },
        );
    }

    let redirect_uri = format!("{}/github/callback", state.public_base_url);
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
        url_encode(&state.github_client_id),
        url_encode(&redirect_uri),
        url_encode(&oauth_state),
    );
    Redirect::temporary(&url).into_response()
}

async fn github_callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<GithubCallbackQuery>,
) -> Response {
    if let Some(err) = q.error {
        return html_error(StatusCode::BAD_REQUEST, &format!("GitHub authorization cancelled or failed: {err}"));
    }
    let (Some(code), Some(oauth_state)) = (q.code, q.state) else {
        return html_error(StatusCode::BAD_REQUEST, "Missing code or state parameter.");
    };

    let pending_entry = {
        let mut pending = state.pending.lock().await;
        let now_ms = now_unix_ms();
        purge_expired_pending(&mut pending, now_ms);
        pending.remove(&oauth_state)
    };
    let Some(entry) = pending_entry else {
        return html_error(StatusCode::BAD_REQUEST, "OAuth state expired or already used. Please restart from Viso.");
    };

    let Some(issuer) = state.issuers.get(&entry.key_id) else {
        return html_error(StatusCode::INTERNAL_SERVER_ERROR, "Configured issuer disappeared.");
    };

    let redirect_uri = format!("{}/github/callback", state.public_base_url);
    let token_res = state
        .http
        .post("https://github.com/login/oauth/access_token")
        .header(header::ACCEPT, "application/json")
        .form(&[
            ("client_id", state.github_client_id.as_str()),
            ("client_secret", state.github_client_secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await;

    let access_token = match token_res {
        Ok(resp) if resp.status().is_success() => match resp.json::<TokenResponse>().await {
            Ok(tr) => match tr.access_token {
                Some(t) => t,
                None => {
                    let msg = tr.error_description.or(tr.error).unwrap_or_else(|| "missing access_token".into());
                    return html_error(StatusCode::BAD_GATEWAY, &format!("GitHub OAuth failed: {msg}"));
                }
            },
            Err(e) => return html_error(StatusCode::BAD_GATEWAY, &format!("Bad GitHub token JSON: {e}")),
        },
        Ok(resp) => return html_error(StatusCode::BAD_GATEWAY, &format!("GitHub token endpoint returned {}", resp.status())),
        Err(e) => return html_error(StatusCode::BAD_GATEWAY, &format!("Failed contacting GitHub: {e}")),
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
        issue_blind_token(
            &mut store,
            &state.hmac_secret,
            issuer,
            &user,
            &entry.blinded_msg,
            now_unix_secs(),
        )
    };

    match issued {
        Ok(token) => html_token_success(&token, &issuer.key_id),
        Err(IssueError::Ineligible(m)) => html_error(StatusCode::FORBIDDEN, &m),
        Err(IssueError::AlreadyClaimed(m)) => html_error(StatusCode::CONFLICT, &m),
        Err(IssueError::BadRequest(m)) => html_error(StatusCode::BAD_REQUEST, &m),
        Err(IssueError::Internal(m)) => html_error(StatusCode::INTERNAL_SERVER_ERROR, &m),
    }
}

fn no_store_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    h
}

fn html_token_success(token: &str, key_id: &str) -> Response {
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
  <h2>GitHub eligibility verified</h2>
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
