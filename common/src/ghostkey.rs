//! Optional Freenet ghostkey badge. The `ghostkey` slot holds a bundle the
//! ghostkeys delegate produced (`SignMessage`) over [`binding_payload`] of
//! the identity's pubkey. Verified client-side: cert chain back to the
//! Freenet master key, then the Ed25519 signature, then the binding.
//! Not used by the contract, so RSA stays out of the WASM.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use serde::{Deserialize, Serialize};

const BIND_TAG: &[u8] = b"viso-ghostkey-v1:";

/// Wire format of the ghostkeys delegate's signed bundle.
#[derive(Serialize, Deserialize)]
struct SignedBundle {
    scoped_payload: Vec<u8>,
    signature: Vec<u8>,
    certificate_pem: String,
}

/// Mirrors the delegate's `ScopedPayload`; the requestor is not checked.
#[derive(Deserialize)]
struct ScopedPayload {
    #[allow(dead_code)]
    requestor: ciborium::value::Value,
    payload: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GhostkeyBadge {
    /// First 8 bytes of blake3(verifying key), base58 — ghostkeys' fingerprint.
    pub fingerprint: String,
    /// Notary info, e.g. `donation_amount:20`.
    pub info: String,
}

/// What the ghostkey must sign to vouch for this viso identity.
pub fn binding_payload(identity_pubkey: &[u8; 32]) -> Vec<u8> {
    [BIND_TAG, identity_pubkey].concat()
}

pub fn verify_badge(bundle: &[u8], identity_pubkey: &[u8; 32]) -> Result<GhostkeyBadge, String> {
    verify_with(bundle, identity_pubkey, &None)
}

/// `master` None = the Freenet master key compiled into ghostkey_lib.
fn verify_with(
    bundle: &[u8],
    identity_pubkey: &[u8; 32],
    master: &Option<VerifyingKey>,
) -> Result<GhostkeyBadge, String> {
    let b: SignedBundle = crate::from_cbor(bundle)?;
    let cert = GhostkeyCertificateV1::from_armored_string(&b.certificate_pem)
        .map_err(|e| format!("bad certificate: {e}"))?;
    let info = cert
        .verify(master)
        .map_err(|e| format!("certificate chain invalid: {e}"))?;
    let sig = Signature::from_slice(&b.signature).map_err(|e| e.to_string())?;
    cert.verifying_key
        .verify(&b.scoped_payload, &sig)
        .map_err(|_| "bad ghostkey signature".to_string())?;
    let scoped: ScopedPayload = crate::from_cbor(&b.scoped_payload)?;
    if scoped.payload != binding_payload(identity_pubkey) {
        return Err("ghostkey proof is for a different identity".into());
    }
    let h = blake3::hash(cert.verifying_key.as_bytes());
    Ok(GhostkeyBadge {
        fingerprint: bs58::encode(&h.as_bytes()[..8]).into_string(),
        info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ghostkey_lib::notary_certificate::NotaryCertificateV1;
    use rand::rngs::OsRng;

    /// Chain signed by a throwaway master (production master can't be used).
    fn fixture(payload: Vec<u8>) -> (Vec<u8>, VerifyingKey) {
        let (master_sk, master_vk) = ghostkey_lib::util::create_keypair(&mut OsRng).unwrap();
        let (notary, notary_sk) = NotaryCertificateV1::new(&master_sk, &"donation_amount:20".to_string()).unwrap();
        let (cert, sk) = GhostkeyCertificateV1::new(&notary, &notary_sk);
        let scoped = crate::to_cbor(&serde_json_free_scoped(payload)).unwrap();
        let sig = sk.sign(&scoped).to_bytes().to_vec();
        let bundle = SignedBundle {
            scoped_payload: scoped,
            signature: sig,
            certificate_pem: cert.to_armored_string().unwrap(),
        };
        (crate::to_cbor(&bundle).unwrap(), master_vk)
    }

    #[derive(Serialize)]
    struct TestScoped {
        requestor: String,
        payload: Vec<u8>,
    }
    fn serde_json_free_scoped(payload: Vec<u8>) -> TestScoped {
        TestScoped { requestor: "app".into(), payload }
    }

    #[test]
    fn accepts_bound_identity() {
        let pk = [9u8; 32];
        let (bundle, master) = fixture(binding_payload(&pk));
        let badge = verify_with(&bundle, &pk, &Some(master)).unwrap();
        assert_eq!(badge.info, "donation_amount:20");
        assert!(!badge.fingerprint.is_empty());
    }

    #[test]
    fn rejects_other_identity_and_foreign_master() {
        let pk = [9u8; 32];
        let (bundle, master) = fixture(binding_payload(&pk));
        assert!(verify_with(&bundle, &[1u8; 32], &Some(master)).is_err());
        // Throwaway chain must not verify against the real Freenet master.
        assert!(verify_badge(&bundle, &pk).is_err());
    }
}
