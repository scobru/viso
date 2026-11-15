//! Anonymous Proof-of-Personhood (PoH) attestations via RFC 9474 Blind RSA
//! (`RSABSSA-SHA384-PSS-Randomized`).
//!
//! Each `(provider, tier, epoch)` tuple uses a distinct RSA-2048 issuer keypair
//! so the blind signer cannot learn the target Viso identity pubkey, while the
//! user cannot spoof a tier or epoch they did not qualify for.
//!
//! Not used by `identity-contract` or `viso-delegate`, so RSA stays out of
//! their WASM builds and derived addresses remain unchanged.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use blind_rsa_signatures::{
    BlindSignature, MessageRandomizer, Options, PublicKey, Secret, Signature,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

const POH_DOMAIN: &[u8] = b"viso-poh-v1";
pub const TOKEN_PREFIX: &str = "VISO-POH-V1:";

/// A pinned PoH issuer public key for a single `(provider, tier, epoch)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PohIssuer<'a> {
    pub key_id: &'a str,
    pub provider: &'a str,
    pub tier: &'a str,
    pub epoch: &'a str,
    /// SubjectPublicKeyInfo (DER) bytes of the RSA-2048..4096 public key.
    pub spki_der: &'a [u8],
}

/// Trusted production PoH issuers. Drop a `key_id` here to revoke trust.
/// Synced automatically from `gatekeeper/issuers.json` by `scripts/sync-poh-issuers.ps1`.
// BEGIN POH_ISSUERS
pub const POH_ISSUERS: &[PohIssuer<'static>] = &[];
// END POH_ISSUERS

/// Wire format stored in a `poh:<provider>` identity slot (CBOR).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PohAttestationV1 {
    pub version: u32,
    pub key_id: String,
    #[serde(with = "serde_bytes")]
    pub msg_randomizer: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// Verified PoH badge surfaced to consumers (`viso-client`, Viso UI, dApps).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PohBadge {
    pub provider: String,
    pub tier: String,
    pub epoch: String,
    pub key_id: String,
}

/// Token payload returned by the Gatekeeper (`VISO-POH-V1:<base64(CBOR)>`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PohBlindReplyV1 {
    pub version: u32,
    pub key_id: String,
    #[serde(with = "serde_bytes")]
    pub blind_sig: Vec<u8>,
}

/// Local client state kept across the OAuth round-trip to unblind the reply.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PendingBlindState {
    pub version: u32,
    pub key_id: String,
    pub pubkey: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub blind_secret: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub msg_randomizer: Vec<u8>,
}

/// Domain-separated message bound to `(key_id, identity_pubkey)`.
pub fn poh_msg(key_id: &str, identity_pubkey: &[u8; 32]) -> Vec<u8> {
    let kb = key_id.as_bytes();
    let mut out = Vec::with_capacity(POH_DOMAIN.len() + 4 + kb.len() + 32);
    out.extend_from_slice(POH_DOMAIN);
    out.extend_from_slice(&(kb.len() as u32).to_le_bytes());
    out.extend_from_slice(kb);
    out.extend_from_slice(identity_pubkey);
    out
}

pub fn parse_issuer_pk(spki_der: &[u8]) -> Result<PublicKey, String> {
    PublicKey::from_spki(spki_der, None)
        .or_else(|_| PublicKey::from_der(spki_der))
        .map_err(|e| format!("invalid PoH issuer RSA public key: {e}"))
}

pub fn find_issuer<'a, 'b>(issuers: &'a [PohIssuer<'b>], key_id: &str) -> Option<&'a PohIssuer<'b>> {
    issuers.iter().find(|i| i.key_id == key_id)
}

/// Blind `poh_msg(issuer.key_id, identity_pubkey)` locally using `rng`.
/// Returns `(blinded_msg_base64url, PendingBlindState)`.
pub fn blind_request<R: CryptoRng + RngCore>(
    rng: &mut R,
    issuer: &PohIssuer<'_>,
    identity_pubkey: &[u8; 32],
) -> Result<(String, PendingBlindState), String> {
    let pk = parse_issuer_pk(issuer.spki_der)?;
    let msg = poh_msg(issuer.key_id, identity_pubkey);
    let res = pk
        .blind(rng, &msg, true, &Options::default())
        .map_err(|e| format!("blind failed: {e}"))?;
    let msg_randomizer = res
        .msg_randomizer
        .ok_or_else(|| "missing msg_randomizer".to_string())?
        .0
        .to_vec();
    let blinded_b64 = URL_SAFE_NO_PAD.encode(&res.blind_msg.0);
    let pending = PendingBlindState {
        version: 1,
        key_id: issuer.key_id.to_string(),
        pubkey: *identity_pubkey,
        blind_secret: res.secret.0,
        msg_randomizer,
    };
    Ok((blinded_b64, pending))
}

/// Encode a blind signature reply from the Gatekeeper into `VISO-POH-V1:...`.
pub fn encode_reply_token(key_id: &str, blind_sig: &[u8]) -> Result<String, String> {
    let reply = PohBlindReplyV1 {
        version: 1,
        key_id: key_id.to_string(),
        blind_sig: blind_sig.to_vec(),
    };
    let cbor = crate::to_cbor(&reply)?;
    Ok(format!("{TOKEN_PREFIX}{}", STANDARD.encode(cbor)))
}

/// Decode a `VISO-POH-V1:...` token (accepts standard or URL-safe base64).
pub fn decode_reply_token(token: &str) -> Result<PohBlindReplyV1, String> {
    let trimmed = token.trim();
    let b64 = trimmed
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| format!("expected {TOKEN_PREFIX} token"))?;
    let raw = STANDARD
        .decode(b64)
        .or_else(|_| URL_SAFE_NO_PAD.decode(b64))
        .map_err(|e| format!("invalid token base64: {e}"))?;
    let reply: PohBlindReplyV1 = crate::from_cbor(&raw)?;
    if reply.version != 1 {
        return Err(format!("unsupported PoH reply version {}", reply.version));
    }
    if reply.key_id.is_empty() || reply.blind_sig.is_empty() {
        return Err("malformed PoH reply fields".into());
    }
    Ok(reply)
}

/// Unblind a Gatekeeper reply token, verify it against `issuers`, and serialize
/// the `PohAttestationV1` slot payload ready to be signed into `poh:<provider>`.
pub fn finalize_attestation(
    token: &str,
    pending: &PendingBlindState,
    issuers: &[PohIssuer<'_>],
) -> Result<Vec<u8>, String> {
    if pending.version != 1 {
        return Err(format!("unsupported pending PoH state version {}", pending.version));
    }
    let reply = decode_reply_token(token)?;
    if reply.key_id != pending.key_id {
        return Err(format!(
            "token key_id {:?} does not match pending request {:?}",
            reply.key_id, pending.key_id
        ));
    }
    let issuer = find_issuer(issuers, &reply.key_id)
        .ok_or_else(|| format!("unknown PoH issuer {:?}", reply.key_id))?;
    let pk = parse_issuer_pk(issuer.spki_der)?;
    let rand_arr: [u8; 32] = pending
        .msg_randomizer
        .as_slice()
        .try_into()
        .map_err(|_| "invalid pending msg_randomizer length".to_string())?;
    let msg = poh_msg(&pending.key_id, &pending.pubkey);
    let sig = pk
        .finalize(
            &BlindSignature(reply.blind_sig),
            &Secret(pending.blind_secret.clone()),
            Some(MessageRandomizer(rand_arr)),
            &msg,
            &Options::default(),
        )
        .map_err(|e| format!("PoH unblind/verify failed: {e}"))?;
    let slot = PohAttestationV1 {
        version: 1,
        key_id: pending.key_id.clone(),
        msg_randomizer: pending.msg_randomizer.clone(),
        sig: sig.0,
    };
    let cbor = crate::to_cbor(&slot)?;
    verify_attestation_with(&cbor, &pending.pubkey, issuers)?;
    Ok(cbor)
}

/// Verify a `poh:<provider>` slot against the pinned production [`POH_ISSUERS`].
pub fn verify_attestation(
    slot_bytes: &[u8],
    identity_pubkey: &[u8; 32],
) -> Result<PohBadge, String> {
    verify_attestation_with(slot_bytes, identity_pubkey, POH_ISSUERS)
}

/// Verify a `poh:<provider>` slot against an explicit issuer registry.
pub fn verify_attestation_with(
    slot_bytes: &[u8],
    identity_pubkey: &[u8; 32],
    issuers: &[PohIssuer<'_>],
) -> Result<PohBadge, String> {
    let att: PohAttestationV1 = crate::from_cbor(slot_bytes)?;
    if att.version != 1 {
        return Err(format!("unsupported PoH slot version {}", att.version));
    }
    let issuer = find_issuer(issuers, &att.key_id)
        .ok_or_else(|| format!("unknown or revoked PoH issuer {:?}", att.key_id))?;
    let pk = parse_issuer_pk(issuer.spki_der)?;
    let rand_arr: [u8; 32] = att
        .msg_randomizer
        .as_slice()
        .try_into()
        .map_err(|_| "invalid msg_randomizer length".to_string())?;
    let msg = poh_msg(&att.key_id, identity_pubkey);
    pk.verify(
        &Signature(att.sig),
        Some(MessageRandomizer(rand_arr)),
        &msg,
        &Options::default(),
    )
    .map_err(|_| "bad PoH blind signature".to_string())?;
    Ok(PohBadge {
        provider: issuer.provider.to_string(),
        tier: issuer.tier.to_string(),
        epoch: issuer.epoch.to_string(),
        key_id: issuer.key_id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::{BlindedMessage, KeyPair, SecretKey};
    use rand::rngs::OsRng;

    fn test_keypair() -> (Vec<u8>, SecretKey) {
        let kp = KeyPair::generate(&mut OsRng, 2048).unwrap();
        let spki = kp.pk.to_der().unwrap();
        (spki, kp.sk)
    }

    #[test]
    fn blind_sign_finalize_and_verify_round_trip() {
        let (spki, sk) = test_keypair();
        let issuers = [PohIssuer {
            key_id: "github:age1y:2026",
            provider: "github",
            tier: "age1y",
            epoch: "2026",
            spki_der: &spki,
        }];
        let pk = [7u8; 32];

        let (blinded_b64, pending) = blind_request(&mut OsRng, &issuers[0], &pk).unwrap();
        let blinded_bytes = URL_SAFE_NO_PAD.decode(&blinded_b64).unwrap();
        let blind_sig = sk
            .blind_sign(&mut OsRng, &BlindedMessage(blinded_bytes), &Options::default())
            .unwrap();
        let token = encode_reply_token("github:age1y:2026", &blind_sig.0).unwrap();

        let slot_bytes = finalize_attestation(&token, &pending, &issuers).unwrap();
        let badge = verify_attestation_with(&slot_bytes, &pk, &issuers).unwrap();
        assert_eq!(badge.provider, "github");
        assert_eq!(badge.tier, "age1y");
        assert_eq!(badge.epoch, "2026");
        assert_eq!(badge.key_id, "github:age1y:2026");
    }

    #[test]
    fn rejects_other_identity_wrong_issuer_and_spoofed_tier() {
        let (spki_age, sk_age) = test_keypair();
        let (spki_dev, _) = test_keypair();
        let issuers = [
            PohIssuer {
                key_id: "github:age1y:2026",
                provider: "github",
                tier: "age1y",
                epoch: "2026",
                spki_der: &spki_age,
            },
            PohIssuer {
                key_id: "github:dev1y:2026",
                provider: "github",
                tier: "dev1y",
                epoch: "2026",
                spki_der: &spki_dev,
            },
        ];
        let pk = [3u8; 32];

        let (blinded_b64, pending) = blind_request(&mut OsRng, &issuers[0], &pk).unwrap();
        let blinded_bytes = URL_SAFE_NO_PAD.decode(&blinded_b64).unwrap();
        let blind_sig = sk_age
            .blind_sign(&mut OsRng, &BlindedMessage(blinded_bytes), &Options::default())
            .unwrap();
        let token = encode_reply_token("github:age1y:2026", &blind_sig.0).unwrap();
        let slot_bytes = finalize_attestation(&token, &pending, &issuers).unwrap();

        // Transferring the slot to another persona fails.
        assert!(verify_attestation_with(&slot_bytes, &[4u8; 32], &issuers).is_err());

        // Revoking/removing the issuer rejects the slot.
        assert!(verify_attestation_with(&slot_bytes, &pk, &[]).is_err());

        // Swapping key_id in the stored slot to claim a higher tier fails.
        let mut att: PohAttestationV1 = crate::from_cbor(&slot_bytes).unwrap();
        att.key_id = "github:dev1y:2026".into();
        let tampered = crate::to_cbor(&att).unwrap();
        assert!(verify_attestation_with(&tampered, &pk, &issuers).is_err());
    }
}
