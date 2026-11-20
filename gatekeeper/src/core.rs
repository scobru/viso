//! Pure domain logic for the Viso PoH Gatekeeper: issuer key management,
//! GitHub eligibility policy, HMAC-SHA256 nullifier store (append-only log),
//! and RFC 9474 Blind RSA signing.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use blind_rsa_signatures::reexports::rsa::PublicKeyParts as _;
use blind_rsa_signatures::{BlindedMessage, KeyPair, Options, SecretKey};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use viso_core::poh::encode_reply_token;

pub const DEFAULT_MIN_AGE_DAYS: i64 = 365;
pub const OAUTH_STATE_TTL_MS: u64 = 10 * 60 * 1000;
pub const MAX_PENDING_STATES: usize = 10_000;

/// Subset of `GET https://api.github.com/user` used for eligibility + nullifier.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHubUser {
    pub id: u64,
    #[serde(rename = "type")]
    pub user_type: String,
    pub created_at: String,
    #[serde(default)]
    pub public_repos: u64,
}

/// Subset of `GET https://openidconnect.googleapis.com/v1/userinfo` used for eligibility + nullifier.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GoogleUser {
    pub sub: String,
    #[serde(default)]
    pub email_verified: Option<bool>,
}

/// Configuration for one `(provider, tier, epoch)` issuer keypair.
#[derive(Clone)]
pub struct ConfiguredIssuer {
    pub key_id: String,
    pub provider: String,
    pub tier: String,
    pub epoch: String,
    pub min_age_days: i64,
    pub min_public_repos: u64,
    pub spki_der: Vec<u8>,
    pub modulus_bytes: usize,
    pub modulus_be: Vec<u8>,
    pub sk: SecretKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerConfigJson {
    pub key_id: String,
    pub provider: String,
    pub tier: String,
    pub epoch: String,
    #[serde(default = "default_min_age_days")]
    pub min_age_days: i64,
    #[serde(default)]
    pub min_public_repos: u64,
    #[serde(default)]
    pub pkcs8_path: Option<String>,
    #[serde(default)]
    pub pkcs8_b64: Option<String>,
}

fn default_min_age_days() -> i64 {
    DEFAULT_MIN_AGE_DAYS
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicIssuerInfo {
    pub key_id: String,
    pub provider: String,
    pub tier: String,
    pub epoch: String,
    pub min_age_days: i64,
    pub min_public_repos: u64,
    pub spki_b64: String,
}

#[derive(Clone, Debug)]
pub struct PendingOAuth {
    pub key_id: String,
    pub blinded_msg: Vec<u8>,
    pub created_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct NullifierRecord {
    nullifier: String,
    day_ts: u64,
}

#[derive(Debug)]
pub enum IssueError {
    BadRequest(String),
    Ineligible(String),
    AlreadyClaimed(String),
    Internal(String),
}

impl std::fmt::Display for IssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueError::BadRequest(m)
            | IssueError::Ineligible(m)
            | IssueError::AlreadyClaimed(m)
            | IssueError::Internal(m) => f.write_str(m),
        }
    }
}

/// Append-only nullifier store backed by `nullifiers.log` (one JSON record per
/// line, synced to disk before signing). Stores zero PII — only HMAC-SHA256
/// nullifiers and day-rounded UTC timestamps.
pub struct NullifierStore {
    log_path: PathBuf,
    seen: HashMap<[u8; 32], u64>,
}

impl NullifierStore {
    pub fn open(log_path: impl AsRef<Path>) -> Result<Self, String> {
        let log_path = log_path.as_ref().to_path_buf();
        if let Some(parent) = log_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("create data dir {}: {e}", parent.display()))?;
            }
        }
        let mut seen = HashMap::new();
        if log_path.exists() {
            let file = File::open(&log_path)
                .map_err(|e| format!("open {}: {e}", log_path.display()))?;
            for (lineno, line) in BufReader::new(file).lines().enumerate() {
                let line = line.map_err(|e| format!("read line {}: {e}", lineno + 1))?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let rec: NullifierRecord = serde_json::from_str(trimmed)
                    .map_err(|e| format!("parse nullifier line {}: {e}", lineno + 1))?;
                let bytes = data_encoding::HEXLOWER_PERMISSIVE
                    .decode(rec.nullifier.as_bytes())
                    .map_err(|e| format!("bad nullifier hex line {}: {e}", lineno + 1))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| format!("nullifier length != 32 at line {}", lineno + 1))?;
                seen.insert(arr, rec.day_ts);
            }
        }
        Ok(Self { log_path, seen })
    }

    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.seen.contains_key(nullifier)
    }

    pub fn record(&mut self, nullifier: [u8; 32], now_secs: u64) -> Result<(), String> {
        if self.seen.contains_key(&nullifier) {
            return Err("nullifier already recorded".into());
        }
        let day_ts = (now_secs / 86_400) * 86_400;
        let rec = NullifierRecord {
            nullifier: data_encoding::HEXLOWER.encode(&nullifier),
            day_ts,
        };
        let line = serde_json::to_string(&rec).map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| format!("append {}: {e}", self.log_path.display()))?;
        writeln!(file, "{line}").map_err(|e| format!("write nullifier: {e}"))?;
        file.sync_data().map_err(|e| format!("sync nullifier: {e}"))?;
        self.seen.insert(nullifier, day_ts);
        Ok(())
    }
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Deterministic, non-reversible nullifier scoped to `(provider, epoch, account_id)`.
/// Deliberately excludes `tier` so one external account can mint at most one Viso
/// attestation per epoch across all tiers of a provider.
/// Note: google uses `v2` domain separation so accounts whose `poh:google` badge was removed
/// before Viso added local `pohbackup` persistence can re-attest without wiping GitHub nullifiers.
pub fn compute_nullifier_id(
    hmac_secret: &[u8],
    provider: &str,
    epoch: &str,
    account_id: &str,
) -> [u8; 32] {
    let domain = if provider == "google" {
        "viso-poh-nullifier-v2"
    } else {
        "viso-poh-nullifier-v1"
    };
    let msg = format!("{domain}|{provider}|{epoch}|{account_id}");
    hmac_sha256::HMAC::mac(msg.as_bytes(), hmac_secret)
}

/// Convenience wrapper for numeric GitHub user IDs (identical preimage to [`compute_nullifier_id`]).
pub fn compute_nullifier(
    hmac_secret: &[u8],
    provider: &str,
    epoch: &str,
    github_id: u64,
) -> [u8; 32] {
    compute_nullifier_id(hmac_secret, provider, epoch, &github_id.to_string())
}

pub fn check_github_eligibility(
    user: &GitHubUser,
    issuer: &ConfiguredIssuer,
    now_secs: u64,
) -> Result<(), IssueError> {
    if user.user_type != "User" {
        return Err(IssueError::Ineligible(format!(
            "GitHub account type {:?} is not eligible (must be User).",
            user.user_type
        )));
    }
    let created: DateTime<Utc> = DateTime::parse_from_rfc3339(&user.created_at)
        .map_err(|_| IssueError::Internal("invalid created_at timestamp from GitHub".into()))?
        .with_timezone(&Utc);
    let age_secs = now_secs as i64 - created.timestamp();
    let min_age_secs = issuer.min_age_days * 86_400;
    if age_secs < min_age_secs {
        let days = (age_secs.max(0)) / 86_400;
        return Err(IssueError::Ineligible(format!(
            "GitHub account is {days} days old; at least {} days are required.",
            issuer.min_age_days
        )));
    }
    if user.public_repos < issuer.min_public_repos {
        return Err(IssueError::Ineligible(format!(
            "GitHub account has {} public repos; at least {} are required.",
            user.public_repos, issuer.min_public_repos
        )));
    }
    Ok(())
}

pub fn check_google_eligibility(user: &GoogleUser) -> Result<(), IssueError> {
    if user.sub.trim().is_empty() {
        return Err(IssueError::Internal("missing subject id from Google userinfo".into()));
    }
    if user.email_verified != Some(true) {
        return Err(IssueError::Ineligible(
            "Google account must have a verified email address.".into(),
        ));
    }
    Ok(())
}

/// Decode a base64url-encoded blinded message and check modulus-length bounds.
pub fn decode_blinded_msg(blinded_b64: &str, expected_len: usize) -> Result<Vec<u8>, IssueError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(blinded_b64.trim())
        .or_else(|_| STANDARD.decode(blinded_b64.trim()))
        .map_err(|_| IssueError::BadRequest("invalid blinded message encoding".into()))?;
    if bytes.len() != expected_len {
        return Err(IssueError::BadRequest(format!(
            "blinded message length {} does not match RSA modulus size {expected_len}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Validate mathematically that `0 < blinded_msg < N` (in big-endian unsigned form)
/// before touching persistent nullifier state, so malformed requests cannot burn
/// a user's epoch nullifier.
pub fn validate_blinded_msg(blinded_msg: &[u8], issuer: &ConfiguredIssuer) -> Result<(), IssueError> {
    if blinded_msg.len() != issuer.modulus_bytes {
        return Err(IssueError::BadRequest(format!(
            "blinded message length {} does not match RSA modulus size {}",
            blinded_msg.len(),
            issuer.modulus_bytes
        )));
    }
    if blinded_msg.iter().all(|&b| b == 0) {
        return Err(IssueError::BadRequest(
            "blinded message must be non-zero".into(),
        ));
    }
    if blinded_msg >= issuer.modulus_be.as_slice() {
        return Err(IssueError::BadRequest(
            "blinded message must be strictly less than RSA modulus".into(),
        ));
    }
    Ok(())
}

fn issue_verified_blind_token(
    store: &mut NullifierStore,
    hmac_secret: &[u8],
    issuer: &ConfiguredIssuer,
    account_id: &str,
    blinded_msg: &[u8],
    now_secs: u64,
    account_label: &str,
) -> Result<String, IssueError> {
    validate_blinded_msg(blinded_msg, issuer)?;
    let nullifier = compute_nullifier_id(hmac_secret, &issuer.provider, &issuer.epoch, account_id);
    if store.contains(&nullifier) {
        return Err(IssueError::AlreadyClaimed(format!(
            "This {account_label} account has already attested for epoch {}.",
            issuer.epoch
        )));
    }
    // Persist the nullifier BEFORE signing so a crash after signing cannot
    // allow a second mint.
    store
        .record(nullifier, now_secs)
        .map_err(IssueError::Internal)?;

    let blind_sig = issuer
        .sk
        .blind_sign(
            &mut OsRng,
            &BlindedMessage(blinded_msg.to_vec()),
            &Options::default(),
        )
        .map_err(|e| IssueError::Internal(format!("blind_sign failed: {e}")))?;

    encode_reply_token(&issuer.key_id, &blind_sig.0).map_err(IssueError::Internal)
}

/// Atomically verify GitHub eligibility, check & persist the nullifier, and
/// issue a `VISO-POH-V1:` blind signature token.
pub fn issue_blind_token(
    store: &mut NullifierStore,
    hmac_secret: &[u8],
    issuer: &ConfiguredIssuer,
    user: &GitHubUser,
    blinded_msg: &[u8],
    now_secs: u64,
) -> Result<String, IssueError> {
    if issuer.provider != "github" {
        return Err(IssueError::BadRequest(format!(
            "unsupported provider {:?}",
            issuer.provider
        )));
    }
    check_github_eligibility(user, issuer, now_secs)?;
    issue_verified_blind_token(
        store,
        hmac_secret,
        issuer,
        &user.id.to_string(),
        blinded_msg,
        now_secs,
        "GitHub",
    )
}

/// Atomically verify Google eligibility (`email_verified == true`), check & persist
/// the nullifier, and issue a `VISO-POH-V1:` blind signature token.
pub fn issue_google_blind_token(
    store: &mut NullifierStore,
    hmac_secret: &[u8],
    issuer: &ConfiguredIssuer,
    user: &GoogleUser,
    blinded_msg: &[u8],
    now_secs: u64,
) -> Result<String, IssueError> {
    if issuer.provider != "google" {
        return Err(IssueError::BadRequest(format!(
            "unsupported provider {:?}",
            issuer.provider
        )));
    }
    check_google_eligibility(user)?;
    issue_verified_blind_token(
        store,
        hmac_secret,
        issuer,
        user.sub.trim(),
        blinded_msg,
        now_secs,
        "Google",
    )
}

/// Write a secret file readable by its owner only (0600 on Unix), never over an existing one.
pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(bytes).and_then(|()| f.sync_all()).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Tighten an existing secret file to owner-only (0600 on Unix). Best effort: a read-only
/// mount (e.g. a Docker secret) can't be changed, and that must not stop the gatekeeper.
pub fn restrict_secret(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            eprintln!("warning: could not chmod 600 {}: {e}", path.display());
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Generate a fresh RSA-2048 keypair, write `<prefix>.pkcs8.der` and
/// `<prefix>.spki.der` into `out_dir`, and return the SPKI DER bytes.
pub fn generate_issuer_keypair(
    key_id: &str,
    out_dir: &Path,
) -> Result<(PathBuf, PathBuf, Vec<u8>), String> {
    fs::create_dir_all(out_dir).map_err(|e| format!("create {}: {e}", out_dir.display()))?;
    let safe_name: String = key_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let sk_path = out_dir.join(format!("{safe_name}.pkcs8.der"));
    let pk_path = out_dir.join(format!("{safe_name}.spki.der"));
    if sk_path.exists() || pk_path.exists() {
        return Err(format!("refusing to overwrite existing key files in {}", out_dir.display()));
    }
    let kp = KeyPair::generate(&mut OsRng, 2048).map_err(|e| format!("keygen: {e}"))?;
    let sk_der = kp.sk.to_der().map_err(|e| format!("sk to_der: {e}"))?;
    let pk_der = kp.pk.to_der().map_err(|e| format!("pk to_der: {e}"))?;
    write_secret(&sk_path, &sk_der)?;
    fs::write(&pk_path, &pk_der).map_err(|e| format!("write {}: {e}", pk_path.display()))?;
    Ok((sk_path, pk_path, pk_der))
}

/// Read `issuers_path`, or when `auto_init` is true and the file does not exist yet,
/// automatically mint an issuer keypair under `data_dir/keys` and write `issuers_path`.
/// Safe across restarts: subsequent boots read the existing `issuers_path` unchanged.
pub fn load_or_init_issuers_json(
    issuers_path: &Path,
    data_dir: &Path,
    auto_init: bool,
    key_id: &str,
    min_age_days: i64,
    min_public_repos: u64,
) -> Result<(String, bool), String> {
    if issuers_path.exists() {
        let raw = fs::read_to_string(issuers_path)
            .map_err(|e| format!("read ISSUERS_CONFIG {}: {e}", issuers_path.display()))?;
        return Ok((raw, false));
    }
    if !auto_init {
        return Err(format!(
            "read ISSUERS_CONFIG {}: file not found (set AUTO_INIT_ISSUER=1 to generate automatically)",
            issuers_path.display()
        ));
    }
    let parts: Vec<&str> = key_id.split(':').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(format!(
            "AUTO_KEY_ID {key_id:?} must have format <provider>:<tier>:<epoch>"
        ));
    }
    let keys_dir = data_dir.join("keys");
    let safe_name: String = key_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let existing_sk = keys_dir.join(format!("{safe_name}.pkcs8.der"));
    let sk_path = if existing_sk.exists() {
        existing_sk
    } else {
        generate_issuer_keypair(key_id, &keys_dir)?.0
    };
    let cfg = vec![IssuerConfigJson {
        key_id: key_id.to_string(),
        provider: parts[0].to_string(),
        tier: parts[1].to_string(),
        epoch: parts[2].to_string(),
        min_age_days,
        min_public_repos,
        pkcs8_path: Some(sk_path.to_string_lossy().into_owned()),
        pkcs8_b64: None,
    }];
    let json = serde_json::to_string_pretty(&cfg).map_err(|e| format!("serialize config: {e}"))?;
    if let Some(parent) = issuers_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    fs::write(issuers_path, &json)
        .map_err(|e| format!("write {}: {e}", issuers_path.display()))?;
    Ok((json, true))
}

/// When `auto_init` is true and no issuer for `provider` is present yet in
/// `cfg_list`, mint a keypair under `data_dir/keys`, append it, and persist
/// `issuers_path` if `persist_file` is `Some`.
pub fn ensure_provider_issuer(
    cfg_list: &mut Vec<IssuerConfigJson>,
    persist_path: Option<&Path>,
    data_dir: &Path,
    key_id: &str,
    min_age_days: i64,
    min_public_repos: u64,
) -> Result<bool, String> {
    let parts: Vec<&str> = key_id.split(':').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(format!("key_id {key_id:?} must have format <provider>:<tier>:<epoch>"));
    }
    if cfg_list.iter().any(|c| c.provider == parts[0]) {
        return Ok(false);
    }
    let keys_dir = data_dir.join("keys");
    let safe_name: String = key_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let existing_sk = keys_dir.join(format!("{safe_name}.pkcs8.der"));
    let sk_path = if existing_sk.exists() {
        existing_sk
    } else {
        generate_issuer_keypair(key_id, &keys_dir)?.0
    };
    cfg_list.push(IssuerConfigJson {
        key_id: key_id.to_string(),
        provider: parts[0].to_string(),
        tier: parts[1].to_string(),
        epoch: parts[2].to_string(),
        min_age_days,
        min_public_repos,
        pkcs8_path: Some(sk_path.to_string_lossy().into_owned()),
        pkcs8_b64: None,
    });
    if let Some(path) = persist_path {
        let json = serde_json::to_string_pretty(cfg_list).map_err(|e| format!("serialize config: {e}"))?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        fs::write(path, &json).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(true)
}

pub fn load_issuer_from_config(cfg: &IssuerConfigJson) -> Result<ConfiguredIssuer, String> {
    let der = if let Some(b64) = cfg.pkcs8_b64.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        STANDARD
            .decode(b64)
            .or_else(|_| URL_SAFE_NO_PAD.decode(b64))
            .map_err(|e| format!("decode pkcs8_b64 for {}: {e}", cfg.key_id))?
    } else if let Some(path) = cfg.pkcs8_path.as_deref().filter(|s| !s.is_empty()) {
        restrict_secret(Path::new(path));
        fs::read(path).map_err(|e| format!("read {path}: {e}"))?
    } else {
        return Err(format!("issuer {} must set pkcs8_path or pkcs8_b64", cfg.key_id));
    };
    let sk = SecretKey::from_der(&der).map_err(|e| format!("bad RSA key for {}: {e}", cfg.key_id))?;
    let pk = sk.public_key().map_err(|e| format!("derive pk: {e}"))?;
    let modulus_bytes = pk.as_ref().size();
    let modulus_be = pk.as_ref().n().to_bytes_be();
    let spki_der = pk.to_der().map_err(|e| format!("pk to_der: {e}"))?;
    Ok(ConfiguredIssuer {
        key_id: cfg.key_id.clone(),
        provider: cfg.provider.clone(),
        tier: cfg.tier.clone(),
        epoch: cfg.epoch.clone(),
        min_age_days: cfg.min_age_days,
        min_public_repos: cfg.min_public_repos,
        spki_der,
        modulus_bytes,
        modulus_be,
        sk,
    })
}

pub fn purge_expired_pending(pending: &mut HashMap<String, PendingOAuth>, now_ms: u64) {
    pending.retain(|_, v| now_ms.saturating_sub(v.created_at_ms) <= OAUTH_STATE_TTL_MS);
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn restrict_secret_tightens_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("viso-restrict-{}", std::process::id()));
        fs::write(&p, b"k").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        super::restrict_secret(&p);
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        fs::remove_file(&p).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn write_secret_is_owner_only_and_never_overwrites() {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("viso-secret-{}", std::process::id()));
        let _ = fs::remove_file(&p);
        super::write_secret(&p, b"k").unwrap();
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(super::write_secret(&p, b"x").is_err());
        assert_eq!(fs::read(&p).unwrap(), b"k");
        fs::remove_file(&p).unwrap();
    }

    use super::*;
    use blind_rsa_signatures::KeyPair;
    use viso_core::poh::{blind_request, finalize_attestation, verify_attestation_with, PohIssuer};

    fn fixture_issuer(key_id: &str, tier: &str, epoch: &str, min_repos: u64) -> ConfiguredIssuer {
        let kp = KeyPair::generate(&mut OsRng, 2048).unwrap();
        let spki_der = kp.pk.to_der().unwrap();
        let modulus_be = kp.pk.as_ref().n().to_bytes_be();
        ConfiguredIssuer {
            key_id: key_id.into(),
            provider: "github".into(),
            tier: tier.into(),
            epoch: epoch.into(),
            min_age_days: 365,
            min_public_repos: min_repos,
            spki_der,
            modulus_bytes: 256,
            modulus_be,
            sk: kp.sk,
        }
    }

    fn temp_log(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "viso-gk-test-{name}-{}-{}.log",
            std::process::id(),
            now_unix_ms()
        ));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn end_to_end_github_eligibility_blind_sign_and_nullifier_persistence() {
        let log_path = temp_log("e2e");
        let hmac_secret = b"test-hmac-secret-32-bytes-minimum";
        let iss_age = fixture_issuer("github:age1y:2026", "age1y", "2026", 0);
        let iss_dev = fixture_issuer("github:dev1y:2026", "dev1y", "2026", 3);
        let iss_2027 = fixture_issuer("github:age1y:2027", "age1y", "2027", 0);

        let now_secs = 1_800_000_000u64; // ~2027-01-15
        let user = GitHubUser {
            id: 424242,
            user_type: "User".into(),
            created_at: "2020-01-01T00:00:00Z".into(),
            public_repos: 10,
        };

        let viso_issuers = [
            PohIssuer {
                key_id: &iss_age.key_id,
                provider: "github",
                tier: "age1y",
                epoch: "2026",
                spki_der: &iss_age.spki_der,
            },
            PohIssuer {
                key_id: &iss_dev.key_id,
                provider: "github",
                tier: "dev1y",
                epoch: "2026",
                spki_der: &iss_dev.spki_der,
            },
            PohIssuer {
                key_id: &iss_2027.key_id,
                provider: "github",
                tier: "age1y",
                epoch: "2027",
                spki_der: &iss_2027.spki_der,
            },
        ];

        let persona_pk = [9u8; 32];
        let (blinded_b64, pending) = blind_request(&mut OsRng, &viso_issuers[0], &persona_pk).unwrap();
        let blinded_bytes = decode_blinded_msg(&blinded_b64, 256).unwrap();

        let mut store = NullifierStore::open(&log_path).unwrap();
        let token = issue_blind_token(
            &mut store,
            hmac_secret,
            &iss_age,
            &user,
            &blinded_bytes,
            now_secs,
        )
        .unwrap();

        // Unblind & verify in viso-core
        let slot = finalize_attestation(&token, &pending, &viso_issuers).unwrap();
        let badge = verify_attestation_with(&slot, &persona_pk, &viso_issuers).unwrap();
        assert_eq!(badge.provider, "github");
        assert_eq!(badge.tier, "age1y");
        assert_eq!(badge.epoch, "2026");

        // Re-opening store from disk still rejects same GitHub account — even on a DIFFERENT tier in the same epoch!
        let mut reopened = NullifierStore::open(&log_path).unwrap();
        let (b2, _) = blind_request(&mut OsRng, &viso_issuers[1], &[8u8; 32]).unwrap();
        let b2_bytes = decode_blinded_msg(&b2, 256).unwrap();
        let dup = issue_blind_token(
            &mut reopened,
            hmac_secret,
            &iss_dev,
            &user,
            &b2_bytes,
            now_secs,
        );
        assert!(matches!(dup, Err(IssueError::AlreadyClaimed(_))));

        // Next epoch (2027) is allowed for the same GitHub account.
        let (b3, p3) = blind_request(&mut OsRng, &viso_issuers[2], &[8u8; 32]).unwrap();
        let b3_bytes = decode_blinded_msg(&b3, 256).unwrap();
        let t3 = issue_blind_token(
            &mut reopened,
            hmac_secret,
            &iss_2027,
            &user,
            &b3_bytes,
            now_secs,
        )
        .unwrap();
        let s3 = finalize_attestation(&t3, &p3, &viso_issuers).unwrap();
        assert_eq!(
            verify_attestation_with(&s3, &[8u8; 32], &viso_issuers).unwrap().epoch,
            "2027"
        );

        let _ = fs::remove_file(&log_path);
    }

    #[test]
    fn rejects_young_account_bot_and_low_repo_count() {
        let log_path = temp_log("ineligible");
        let mut store = NullifierStore::open(&log_path).unwrap();
        let iss = fixture_issuer("github:dev1y:2026", "dev1y", "2026", 3);
        let now_secs = DateTime::parse_from_rfc3339("2026-11-15T00:00:00Z")
            .unwrap()
            .timestamp() as u64;
        let dummy_blinded = vec![1u8; 256];

        let young = GitHubUser {
            id: 1,
            user_type: "User".into(),
            created_at: "2026-06-01T00:00:00Z".into(),
            public_repos: 10,
        };
        assert!(matches!(
            issue_blind_token(&mut store, b"sec", &iss, &young, &dummy_blinded, now_secs),
            Err(IssueError::Ineligible(_))
        ));

        let bot = GitHubUser {
            id: 2,
            user_type: "Bot".into(),
            created_at: "2020-01-01T00:00:00Z".into(),
            public_repos: 10,
        };
        assert!(matches!(
            issue_blind_token(&mut store, b"sec", &iss, &bot, &dummy_blinded, now_secs),
            Err(IssueError::Ineligible(_))
        ));

        let low_repos = GitHubUser {
            id: 3,
            user_type: "User".into(),
            created_at: "2020-01-01T00:00:00Z".into(),
            public_repos: 1,
        };
        assert!(matches!(
            issue_blind_token(&mut store, b"sec", &iss, &low_repos, &dummy_blinded, now_secs),
            Err(IssueError::Ineligible(_))
        ));

        let _ = fs::remove_file(&log_path);
    }

    #[test]
    fn loads_issuer_from_pkcs8_b64() {
        let kp = KeyPair::generate(&mut OsRng, 2048).unwrap();
        let sk_b64 = STANDARD.encode(kp.sk.to_der().unwrap());
        let expected_spki = kp.pk.to_der().unwrap();
        let cfg = IssuerConfigJson {
            key_id: "github:age1y:2026".into(),
            provider: "github".into(),
            tier: "age1y".into(),
            epoch: "2026".into(),
            min_age_days: 365,
            min_public_repos: 0,
            pkcs8_path: None,
            pkcs8_b64: Some(sk_b64),
        };
        let loaded = load_issuer_from_config(&cfg).unwrap();
        assert_eq!(loaded.spki_der, expected_spki);
    }

    #[test]
    fn auto_init_generates_once_and_reuses_across_restarts() {
        let base = std::env::temp_dir().join(format!(
            "viso-gk-autoinit-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        let issuers_path = base.join("issuers.json");

        let (raw1, created1) =
            load_or_init_issuers_json(&issuers_path, &base, true, "github:age1y:2026", 365, 0)
                .unwrap();
        assert!(created1);
        let list1: Vec<IssuerConfigJson> = serde_json::from_str(&raw1).unwrap();
        let issuer1 = load_issuer_from_config(&list1[0]).unwrap();

        let (raw2, created2) =
            load_or_init_issuers_json(&issuers_path, &base, true, "github:age1y:2026", 365, 0)
                .unwrap();
        assert!(!created2);
        let list2: Vec<IssuerConfigJson> = serde_json::from_str(&raw2).unwrap();
        let issuer2 = load_issuer_from_config(&list2[0]).unwrap();
        assert_eq!(issuer1.spki_der, issuer2.spki_der);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn end_to_end_google_eligibility_blind_sign_and_nullifier_persistence() {
        let kp_v = KeyPair::generate(&mut OsRng, 2048).unwrap();
        let iss_google = ConfiguredIssuer {
            key_id: "google:verified:2026".into(),
            provider: "google".into(),
            tier: "verified".into(),
            epoch: "2026".into(),
            min_age_days: 0,
            min_public_repos: 0,
            spki_der: kp_v.pk.to_der().unwrap(),
            modulus_bytes: kp_v.pk.as_ref().size(),
            modulus_be: kp_v.pk.as_ref().n().to_bytes_be(),
            sk: kp_v.sk,
        };
        let kp_next = KeyPair::generate(&mut OsRng, 2048).unwrap();
        let iss_next = ConfiguredIssuer {
            key_id: "google:verified:2027".into(),
            provider: "google".into(),
            tier: "verified".into(),
            epoch: "2027".into(),
            min_age_days: 0,
            min_public_repos: 0,
            spki_der: kp_next.pk.to_der().unwrap(),
            modulus_bytes: kp_next.pk.as_ref().size(),
            modulus_be: kp_next.pk.as_ref().n().to_bytes_be(),
            sk: kp_next.sk,
        };
        let viso_issuers = vec![
            PohIssuer {
                key_id: "google:verified:2026",
                provider: "google",
                tier: "verified",
                epoch: "2026",
                spki_der: Box::leak(iss_google.spki_der.clone().into_boxed_slice()),
            },
            PohIssuer {
                key_id: "google:verified:2027",
                provider: "google",
                tier: "verified",
                epoch: "2027",
                spki_der: Box::leak(iss_next.spki_der.clone().into_boxed_slice()),
            },
        ];

        let log_path = temp_log("google-e2e");
        let mut store = NullifierStore::open(&log_path).unwrap();
        let hmac_secret = b"test-hmac-secret-at-least-32-bytes-long!";
        let persona_pk = [9u8; 32];
        let now_secs = 1_794_800_000;

        // Unverified email is rejected
        let unverified = GoogleUser {
            sub: "110234567890".into(),
            email_verified: Some(false),
        };
        let (blinded_b64, pending) =
            blind_request(&mut OsRng, &viso_issuers[0], &persona_pk).unwrap();
        let blinded_bytes = decode_blinded_msg(&blinded_b64, 256).unwrap();
        assert!(matches!(
            issue_google_blind_token(&mut store, hmac_secret, &iss_google, &unverified, &blinded_bytes, now_secs),
            Err(IssueError::Ineligible(_))
        ));

        // Verified email issues token and persists nullifier
        let user = GoogleUser {
            sub: "110234567890".into(),
            email_verified: Some(true),
        };
        let token = issue_google_blind_token(
            &mut store,
            hmac_secret,
            &iss_google,
            &user,
            &blinded_bytes,
            now_secs,
        )
        .unwrap();
        let slot_bytes = finalize_attestation(&token, &pending, &viso_issuers).unwrap();
        let badge = verify_attestation_with(&slot_bytes, &persona_pk, &viso_issuers).unwrap();
        assert_eq!(badge.provider, "google");
        assert_eq!(badge.tier, "verified");

        // Same Google account cannot mint again in 2026
        assert!(matches!(
            issue_google_blind_token(&mut store, hmac_secret, &iss_google, &user, &blinded_bytes, now_secs),
            Err(IssueError::AlreadyClaimed(_))
        ));

        // Next epoch is allowed
        let (b2, p2) = blind_request(&mut OsRng, &viso_issuers[1], &persona_pk).unwrap();
        let b2_bytes = decode_blinded_msg(&b2, 256).unwrap();
        let t2 = issue_google_blind_token(&mut store, hmac_secret, &iss_next, &user, &b2_bytes, now_secs).unwrap();
        let s2 = finalize_attestation(&t2, &p2, &viso_issuers).unwrap();
        assert_eq!(verify_attestation_with(&s2, &persona_pk, &viso_issuers).unwrap().epoch, "2027");

        let _ = fs::remove_file(&log_path);
    }

    #[test]
    fn malformed_blinded_msg_rejected_without_burning_nullifier() {
        let log_path = temp_log("malformed-blinded");
        let mut store = NullifierStore::open(&log_path).unwrap();
        let iss = fixture_issuer("github:age1y:2026", "age1y", "2026", 0);
        let viso_iss = [PohIssuer {
            key_id: &iss.key_id,
            provider: "github",
            tier: "age1y",
            epoch: "2026",
            spki_der: &iss.spki_der,
        }];
        let hmac_secret = b"test-hmac-secret-at-least-32-bytes-long!";
        let now_secs = 1_800_000_000u64;
        let user = GitHubUser {
            id: 777_888,
            user_type: "User".into(),
            created_at: "2020-01-01T00:00:00Z".into(),
            public_repos: 5,
        };

        // 0xFF..FF >= RSA modulus N: must be rejected before recording nullifier
        let over_mod = vec![0xFFu8; iss.modulus_bytes];
        assert!(matches!(
            issue_blind_token(&mut store, hmac_secret, &iss, &user, &over_mod, now_secs),
            Err(IssueError::BadRequest(_))
        ));
        // Zero message must also be rejected before recording nullifier
        let zero_msg = vec![0u8; iss.modulus_bytes];
        assert!(matches!(
            issue_blind_token(&mut store, hmac_secret, &iss, &user, &zero_msg, now_secs),
            Err(IssueError::BadRequest(_))
        ));

        // Legitimate request for the exact same user still succeeds afterwards!
        let (blinded_b64, pending) = blind_request(&mut OsRng, &viso_iss[0], &[5u8; 32]).unwrap();
        let blinded = decode_blinded_msg(&blinded_b64, iss.modulus_bytes).unwrap();
        let tok = issue_blind_token(&mut store, hmac_secret, &iss, &user, &blinded, now_secs).unwrap();
        let slot = finalize_attestation(&tok, &pending, &viso_iss).unwrap();
        assert_eq!(verify_attestation_with(&slot, &[5u8; 32], &viso_iss).unwrap().tier, "age1y");

        let _ = fs::remove_file(&log_path);
    }
}
