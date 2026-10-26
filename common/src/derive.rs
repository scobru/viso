//! Identity key derivation: one master seed, unlinkable per-index ed25519
//! keypairs. Deterministic forever — this is the backup format.

use ed25519_dalek::SigningKey;

const CONTEXT: &str = "whoiam identity v1";

pub fn identity_signing_key(seed: &[u8; 32], index: u32) -> SigningKey {
    let mut ikm = [0u8; 36];
    ikm[..32].copy_from_slice(seed);
    ikm[32..].copy_from_slice(&index.to_le_bytes());
    SigningKey::from_bytes(&blake3::derive_key(CONTEXT, &ikm))
}

const APP_CONTEXT: &str = "viso app secret v1";

/// The secret one app gets for one persona (connect flow with `key=v1`): the app uses it as its delegated app key
/// and to encrypt its data, so a sign-in on any device with the same Viso seed brings the same data back.
/// `app` is the app's scope ([`crate::connect::app_scope`]): another app gets an unrelated secret.
/// Deterministic forever, like the identity keys: changing it locks users out of their app data.
pub fn app_secret(persona: &SigningKey, app: &str) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + app.len());
    ikm.extend_from_slice(&persona.to_bytes()); // fixed 32 bytes first: no ambiguity with the app string
    ikm.extend_from_slice(app.as_bytes());
    blake3::derive_key(APP_CONTEXT, &ikm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let seed = [7u8; 32];
        assert_eq!(
            identity_signing_key(&seed, 0).to_bytes(),
            identity_signing_key(&seed, 0).to_bytes()
        );
    }

    /// Golden vector: derivation is the backup format — a change here means
    /// every user's seed stops restoring their identities, and the
    /// `deterministic` test above cannot catch it (both sides change
    /// together). Failing this is breaking every backup in existence.
    #[test]
    fn golden_derivation() {
        let seed = [7u8; 32];
        let hex = |i: u32| {
            data_encoding::HEXLOWER
                .encode(identity_signing_key(&seed, i).verifying_key().as_bytes())
        };
        assert_eq!(hex(0), "2a76f1666f3aac4f859a1f35300050b69275202d3b880d9f165083c92818b0b5");
        assert_eq!(hex(1), "e62a914becffd666c412644071c11b1787347bf1c1b7c77a2cc5997921a673eb");
    }

    #[test]
    fn distinct_per_index_and_seed() {
        let seed = [7u8; 32];
        let other = [8u8; 32];
        let k0 = identity_signing_key(&seed, 0).verifying_key();
        let k1 = identity_signing_key(&seed, 1).verifying_key();
        let o0 = identity_signing_key(&other, 0).verifying_key();
        assert_ne!(k0, k1);
        assert_ne!(k0, o0);
    }

    #[test]
    fn app_secret_per_persona_and_app() {
        let seed = [7u8; 32];
        let p0 = identity_signing_key(&seed, 0);
        let p1 = identity_signing_key(&seed, 1);
        let a = app_secret(&p0, "contract/web/AppA");
        assert_eq!(a, app_secret(&p0, "contract/web/AppA"));
        assert_ne!(a, app_secret(&p0, "contract/web/AppB"));
        assert_ne!(a, app_secret(&p1, "contract/web/AppA"));
        assert_ne!(a, p0.to_bytes()); // never the persona key itself
    }

    /// Golden vector: apps encrypt user data with this secret.
    #[test]
    fn golden_app_secret() {
        let p0 = identity_signing_key(&[7u8; 32], 0);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&app_secret(&p0, "contract/web/AppA")),
            "6e828acbcc0982c608d2bcda05338e52d0ff46a77c72a84d1252109f28ea3682"
        );
    }
}
