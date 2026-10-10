//! The `ante` slot: a persona's proof of commitment.
//!
//! The slot holds one CBOR [`AnteProof`] in the unchanged ante v0.2.0 wire
//! format, ground and signed by the **persona's own key** for
//! [`PURPOSE`]. It shows the persona *cost something* to make — not that it
//! is unique or human-held (see ante's DESIGN.md). Consumers pick their own
//! `min_bits` policy against [`verify_slot`]'s result.
//!
//! The identity contract does not know about this slot (any correctly
//! signed slot is valid there); verification is consumer-side only, which
//! keeps the contract's wasm bytes — and every identity address — unchanged.

use ante_core::{pow, AnteProof};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub use ante_core::VerifyError;

pub const SLOT_ANTE: &str = "ante";

/// Domain separation: a proof for any other purpose (e.g. ante's own
/// `ante:identity-level:v1`) is rejected here.
pub const PURPOSE: &str = "viso:persona-level:v1";

/// Decode and verify an `ante` slot for persona `pk`; returns achieved bits.
/// Rejects proofs for another key or another purpose.
pub fn verify_slot(pk: &VerifyingKey, bytes: &[u8]) -> Result<u32, String> {
    let proof: AnteProof = ante_core::from_cbor(bytes)?;
    if proof.identity_vk != pk.to_bytes() {
        return Err("ante proof is for a different key".into());
    }
    if proof.purpose != PURPOSE {
        return Err(format!("ante proof has unexpected purpose {:?}", proof.purpose));
    }
    proof.verify(0).map_err(|e| e.to_string())
}

/// Bits a candidate nonce demonstrates for persona `pk`.
pub fn bits(pk: &VerifyingKey, nonce: u64) -> u32 {
    pow::bits(PURPOSE, &pk.to_bytes(), nonce)
}

/// Search `[start, start + count)` for a nonce reaching `target_bits`.
/// Lets a single-threaded UI grind in chunks and yield between them.
pub fn grind_step(pk: &VerifyingKey, start: u64, count: u64, target_bits: u32) -> Option<u64> {
    let vk = pk.to_bytes();
    let end = start.saturating_add(count);
    (start..end).find(|n| pow::bits(PURPOSE, &vk, *n) >= target_bits)
}

/// Sign a found nonce into slot content (CBOR AnteProof).
pub fn make_slot(sk: &SigningKey, nonce: u64, ts_ms: u64) -> Vec<u8> {
    ante_core::to_cbor(&AnteProof::create(sk, PURPOSE.to_string(), nonce, ts_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn slot_for(k: &SigningKey, target: u32) -> Vec<u8> {
        let nonce = grind_step(&k.verifying_key(), 0, u64::MAX, target).unwrap();
        make_slot(k, nonce, 1_700_000_000_000)
    }

    #[test]
    fn round_trip_reports_bits() {
        let k = sk(1);
        let bits = verify_slot(&k.verifying_key(), &slot_for(&k, 10)).unwrap();
        assert!(bits >= 10);
    }

    #[test]
    fn proof_for_another_persona_rejected() {
        let slot = slot_for(&sk(2), 8);
        assert!(verify_slot(&sk(3).verifying_key(), &slot).is_err());
    }

    #[test]
    fn foreign_purpose_rejected() {
        let k = sk(4);
        let vk = k.verifying_key().to_bytes();
        let nonce = pow::grind("ante:identity-level:v1", &vk, 8).unwrap();
        let p = AnteProof::create(&k, "ante:identity-level:v1".into(), nonce, 1);
        assert!(verify_slot(&k.verifying_key(), &ante_core::to_cbor(&p)).is_err());
    }

    #[test]
    fn garbage_rejected() {
        assert!(verify_slot(&sk(5).verifying_key(), b"not cbor").is_err());
    }

    #[test]
    fn grind_step_respects_window() {
        let pk = sk(6).verifying_key();
        let n = grind_step(&pk, 0, u64::MAX, 12).unwrap();
        assert!(bits(&pk, n) >= 12);
        assert_eq!(grind_step(&pk, 0, n, 12), None, "n is the smallest hit");
    }

    /// ante's pinned vector still decodes and verifies through our pinned
    /// ante-core: guards against the dependency drifting off v0.2.0.
    #[test]
    fn ante_wire_vector_still_verifies() {
        let p = ante_core::testvec::proof();
        let back: AnteProof = ante_core::from_cbor(&ante_core::to_cbor(&p)).unwrap();
        assert!(back.verify(0).is_ok());
    }
}
