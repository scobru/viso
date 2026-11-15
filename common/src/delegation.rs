//! Signed persona-to-persona handoff / delegation certificate.
//!
//! Both the source persona (`from`) and the target persona (`to`) sign the same
//! domain-separated message, proving possession of both Ed25519 keys.
//! Supporting apps (for example Radica) can verify and store this certificate
//! in their own state so an identity anchored to `from` — even when `from`'s
//! Viso contract is permanently destroyed on Freenet — can delegate its
//! profile, PoH badge, or operations to an active persona `to` without mutating
//! the destroyed Viso contract or weakening Viso's destruction guarantee.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const DELEGATION_VERSION: u32 = 1;
pub const DELEGATION_DEFAULT_SCOPE: &str = "*";
pub const MAX_SCOPE_LEN: usize = 128;

const DELEGATION_DOMAIN: &[u8] = b"viso-delegation-v1";

/// Portable dual-signed handoff certificate between two Viso personas.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DelegationProofV1 {
    pub version: u32,
    /// Source persona public key (base58).
    pub from: String,
    /// Target persona public key (base58).
    pub to: String,
    /// Application or capability scope (e.g. `"*"` or `"radica"`).
    pub scope: String,
    pub time_ms: u64,
    /// Ed25519 signature by `from` over [`delegation_message`], lowercase hex (128 chars).
    pub sig_from: String,
    /// Ed25519 signature by `to` over [`delegation_message`], lowercase hex (128 chars).
    pub sig_to: String,
}

/// Verified delegation extracted from a [`DelegationProofV1`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifiedDelegation {
    pub from: VerifyingKey,
    pub to: VerifyingKey,
    pub scope: String,
    pub time_ms: u64,
}

/// Parse an Ed25519 public key from base58 (preferred) or 64-char lowercase/uppercase hex.
pub fn parse_pubkey(s: &str) -> Result<VerifyingKey, String> {
    let bytes: Vec<u8> = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .map_err(|e| e.to_string())?
    } else {
        bs58::decode(s).into_vec().map_err(|e| e.to_string())?
    };
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
}

pub fn format_pubkey(pk: &VerifyingKey) -> String {
    bs58::encode(pk.as_bytes()).into_string()
}

/// Validate a delegation scope string: non-empty ASCII without whitespace, quotes, or backslashes.
pub fn check_scope(scope: &str) -> Result<(), String> {
    if scope.is_empty() {
        return Err("scope must not be empty".into());
    }
    if scope.len() > MAX_SCOPE_LEN {
        return Err(format!("scope exceeds {MAX_SCOPE_LEN} bytes"));
    }
    if !scope
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
    {
        return Err("scope must contain printable ASCII without spaces, quotes, or backslashes".into());
    }
    Ok(())
}

/// Canonical domain-separated message signed by both `from` and `to`:
/// `"viso-delegation-v1" || from(32) || to(32) || u32le(scope.len()) || scope || u64le(time_ms)`
pub fn delegation_message(
    from: &VerifyingKey,
    to: &VerifyingKey,
    scope: &str,
    time_ms: u64,
) -> Vec<u8> {
    let sb = scope.as_bytes();
    let mut m = Vec::with_capacity(DELEGATION_DOMAIN.len() + 32 + 32 + 4 + sb.len() + 8);
    m.extend_from_slice(DELEGATION_DOMAIN);
    m.extend_from_slice(from.as_bytes());
    m.extend_from_slice(to.as_bytes());
    m.extend_from_slice(&(sb.len() as u32).to_le_bytes());
    m.extend_from_slice(sb);
    m.extend_from_slice(&time_ms.to_le_bytes());
    m
}

/// Create and dual-sign a [`DelegationProofV1`] transferring authority for `scope` from `from_sk` to `to_sk`.
pub fn sign_delegation(
    from_sk: &SigningKey,
    to_sk: &SigningKey,
    scope: &str,
    time_ms: u64,
) -> Result<DelegationProofV1, String> {
    check_scope(scope)?;
    let from_pk = from_sk.verifying_key();
    let to_pk = to_sk.verifying_key();
    if from_pk == to_pk {
        return Err("source and target personas must be different".into());
    }
    let msg = delegation_message(&from_pk, &to_pk, scope, time_ms);
    let sig_from = from_sk.sign(&msg);
    let sig_to = to_sk.sign(&msg);
    Ok(DelegationProofV1 {
        version: DELEGATION_VERSION,
        from: format_pubkey(&from_pk),
        to: format_pubkey(&to_pk),
        scope: scope.to_string(),
        time_ms,
        sig_from: data_encoding::HEXLOWER.encode(&sig_from.to_bytes()),
        sig_to: data_encoding::HEXLOWER.encode(&sig_to.to_bytes()),
    })
}

fn decode_sig_hex(s: &str, label: &str) -> Result<Signature, String> {
    let bytes = data_encoding::HEXLOWER_PERMISSIVE
        .decode(s.as_bytes())
        .map_err(|e| format!("bad {label} hex: {e}"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| format!("{label} must be 64 bytes"))?;
    Ok(Signature::from_bytes(&arr))
}

/// Verify both Ed25519 signatures and structural invariants on a [`DelegationProofV1`].
pub fn verify_delegation(proof: &DelegationProofV1) -> Result<VerifiedDelegation, String> {
    if proof.version != DELEGATION_VERSION {
        return Err(format!("unsupported delegation version {}", proof.version));
    }
    check_scope(&proof.scope)?;
    let from = parse_pubkey(&proof.from)?;
    let to = parse_pubkey(&proof.to)?;
    if from == to {
        return Err("source and target personas must be different".into());
    }
    let sig_from = decode_sig_hex(&proof.sig_from, "sig_from")?;
    let sig_to = decode_sig_hex(&proof.sig_to, "sig_to")?;
    let msg = delegation_message(&from, &to, &proof.scope, proof.time_ms);
    from.verify(&msg, &sig_from)
        .map_err(|_| "bad source (from) delegation signature".to_string())?;
    to.verify(&msg, &sig_to)
        .map_err(|_| "bad target (to) delegation signature".to_string())?;
    Ok(VerifiedDelegation {
        from,
        to,
        scope: proof.scope.clone(),
        time_ms: proof.time_ms,
    })
}

impl DelegationProofV1 {
    /// Format as deterministic JSON without pulling `serde_json` into `viso-core`.
    pub fn to_json(&self) -> Result<String, String> {
        check_scope(&self.scope)?;
        // Parse keys/sigs to guarantee strictly alphanumeric JSON field values.
        let _ = parse_pubkey(&self.from)?;
        let _ = parse_pubkey(&self.to)?;
        let _ = decode_sig_hex(&self.sig_from, "sig_from")?;
        let _ = decode_sig_hex(&self.sig_to, "sig_to")?;
        Ok(format!(
            "{{\"version\":{},\"from\":\"{}\",\"to\":\"{}\",\"scope\":\"{}\",\"time_ms\":{},\"sig_from\":\"{}\",\"sig_to\":\"{}\"}}",
            self.version, self.from, self.to, self.scope, self.time_ms, self.sig_from, self.sig_to
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify_round_trip() {
        let sk_old = SigningKey::generate(&mut OsRng);
        let sk_new = SigningKey::generate(&mut OsRng);
        let proof = sign_delegation(&sk_old, &sk_new, "*", 1_794_781_500_000).unwrap();
        let verified = verify_delegation(&proof).unwrap();
        assert_eq!(verified.from, sk_old.verifying_key());
        assert_eq!(verified.to, sk_new.verifying_key());
        assert_eq!(verified.scope, "*");
        assert_eq!(verified.time_ms, 1_794_781_500_000);
        let json = proof.to_json().unwrap();
        assert!(json.contains("\"version\":1"));
        assert!(json.contains(&proof.from));
        assert!(json.contains(&proof.to));
    }

    #[test]
    fn self_delegation_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        assert!(sign_delegation(&sk, &sk, "*", 1000).is_err());
    }

    #[test]
    fn tampered_target_or_sig_rejected() {
        let sk_old = SigningKey::generate(&mut OsRng);
        let sk_new = SigningKey::generate(&mut OsRng);
        let sk_evil = SigningKey::generate(&mut OsRng);
        let mut proof = sign_delegation(&sk_old, &sk_new, "radica", 5000).unwrap();

        let mut wrong_to = proof.clone();
        wrong_to.to = format_pubkey(&sk_evil.verifying_key());
        assert!(verify_delegation(&wrong_to).is_err());

        proof.scope = "*".into();
        assert!(verify_delegation(&proof).is_err());
    }

    #[test]
    fn invalid_scope_rejected() {
        let sk_old = SigningKey::generate(&mut OsRng);
        let sk_new = SigningKey::generate(&mut OsRng);
        assert!(sign_delegation(&sk_old, &sk_new, "", 1000).is_err());
        assert!(sign_delegation(&sk_old, &sk_new, "has space", 1000).is_err());
        assert!(sign_delegation(&sk_old, &sk_new, "bad\"quote", 1000).is_err());
    }
}
