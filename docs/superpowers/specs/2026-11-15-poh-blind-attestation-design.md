# Viso Anonymous Proof-of-Personhood (Blind RSA Attestation) — Design

2026-11-15. Status: draft for review.

## Goal

Allow a Viso persona to prove off-chain real-world account ownership (starting with **GitHub**, extensible to **Google** and others) with **zero-knowledge / cryptographic unlinkability** and **1-account → 1-persona Sybil resistance**:

1. **Unlinkable**: Neither the OAuth Gatekeeper nor any Freenet reader learns which GitHub account backs a Viso persona.
2. **Non-transferable**: A proof issued for persona `pk_A` verifies **only** inside `pk_A`'s contract and cannot be moved to `pk_B`.
3. **1 account → 1 persona per epoch**: The same GitHub account cannot mint a second attestation in the same epoch.
4. **Zero blockchain / zero gas / contract-unchanged**: No EVM wallet, no gas, and **zero byte changes** to `identity_contract.wasm` or `viso-delegate.wasm` (preserving all existing derived persona addresses).

---

## Cryptographic Protocol: RFC 9474 Blind RSA (`RSABSSA-SHA384-PSS-Randomized`)

Why Blind RSA over Semaphore for OAuth:
- GitHub OAuth already requires a Gatekeeper server (holding the OAuth `client_secret`) to talk to `api.github.com`. There is no on-chain state to anchor.
- Standard **RFC 9474 Blind RSA** provides information-theoretic blinding during issuance: the Gatekeeper signs a blinded digest of `viso_pubkey` without ever learning `viso_pubkey`.
- Verification is offline, pure-Rust (`blind-rsa-signatures`) and pure-TS (`@cloudflare/blindrsa-ts` / WebCrypto), ~300 bytes on wire, with no Merkle trees, no Groth16 `.zkey` downloads, and no separate Attester bot.

### Attribute Binding via Key Separation

In Blind RSA the signer cannot inspect the message. To prevent a user who qualifies for tier `T1` from requesting a blind signature claiming tier `T2`, **each `(provider, tier, epoch)` tuple has its own RSA-2048 keypair** `(sk_iss, pk_iss)`:

- Example `key_id` strings:
  - `"github:age1y:2026"` — GitHub `User` account created `>= 365` days ago.
  - `"github:dev1y:2026"` — GitHub `User` account created `>= 365` days ago, with `>= 3` non-fork public repos (optional stricter tier).
- Public keys (`pk_iss` in SPKI DER + `key_id` + metadata) are pinned in `viso-core` (mirroring how `ghostkey_lib` pins the Freenet master key).
- `key_id` is uniquely identified on wire by `key_fingerprint = blake3(spki_der)[..8]` (8 bytes) alongside the human-readable `key_id` string.

### Signed Message Format

The message blinded by Viso UI and verified by consumers is strictly domain-separated and bound to the persona's 32-byte Ed25519 public key:

```
poh_msg(key_id, pk) =
  "viso-poh-v1" || u32le(len(key_id)) || key_id_utf8 || pk (32 bytes)
```

Because `RSABSSA-SHA384-PSS-Randomized` (RFC 9474) prepends a random 32-byte `msg_randomizer` (`salt_prefix`) during `Blind()`, the final stored attestation carries:
- `msg_randomizer: [u8; 32]` (output of `Blind()`)
- `sig: Vec<u8>` (256-byte RSA-2048 PSS signature after `Finalize()` / unblinding)

Consumers reconstruct `poh_msg(key_id, pk)` from the persona's own `VerifyingKey` and verify `(msg_randomizer, sig)` against the pinned `pk_iss` for `key_id`.

---

## Anti-Sybil Nullifier & Epoch Policy (Gatekeeper)

Upon GitHub OAuth completion (`GET https://api.github.com/user`, no elevated OAuth scopes required for public user metadata):

1. **Eligibility checks**:
   - `type == "User"` (reject `"Bot"`, `"Organization"`).
   - `now - parse_iso8601(created_at) >= 365 days` (for `age1y`).
   - Additional tier checks if requested (e.g. non-fork public repos `>= 3` for `dev1y`).
2. **Global-per-epoch nullifier (prevents multi-tier Sybil minting)**:
   - Compute:
     ```
     nullifier = HMAC-SHA256(gatekeeper_hmac_secret, "viso-poh-nullifier-v1|" + provider + "|" + epoch + "|" + github_numeric_id)
     ```
   - Notice `tier` is **excluded** from the nullifier: one GitHub account can mint **at most one** attestation per `(provider, epoch)` across all tiers, preventing a user from minting `age1y` for persona A and `dev1y` for persona B.
   - Store **only** `nullifier (32B)` and `day_ts` (day-rounded UTC timestamp) in SQLite. **Never store** `github_id`, `login`, `email`, OAuth tokens, IP addresses, or `blinded_msg`.
3. **Epoch rotation**:
   - Epochs are annual (e.g. `"2026"`, `"2027"`) or semi-annual.
   - If a user destroys a Viso persona (`DestroyedMarker`) or rotates keys, they can obtain a fresh attestation in the next epoch without breaking Sybil resistance within an epoch.
   - Consumers decide accepted epochs (e.g. current epoch and previous epoch).

---

## End-to-End Flow

```
  Viso UI (Freenet)                         Gatekeeper (HTTPS)                  GitHub
  -----------------                         ------------------                  ------
  1. User picks persona `pk` & `key_id`
  2. blind_state = Blind(pk_iss, poh_msg)
     (keeps `secret` locally in UI/delegate)
  3. Opens Gatekeeper URL with
     ?key_id=...&blinded=<b64url>
     (NOTE: `pk` is NEVER sent!)    ----->  4. Redirects to GitHub OAuth  --->  User logs in
                                    <-----  5. OAuth callback code         <---  Authorization code
                                            6. Fetches `/user` (id, created_at)
                                            7. Checks eligibility + nullifier
                                            8. Records nullifier in SQLite
                                            9. blind_sig = BlindSign(sk_iss, blinded)
                                    <----- 10. Shows `VISO-POH-V1:<b64>` token
  11. User pastes token into Viso UI
      (optionally after a delay for timing privacy)
  12. Unblind + verify against `pk_iss` and `pk`
  13. Encode `PohAttestationV1` (CBOR)
  14. Sign slot `poh:github` with persona Ed25519 key
  15. Push UPDATE to persona identity contract on Freenet
```

### Timing & Correlation Privacy

- **Zero link in network logs**: `pk` never leaves the user's browser toward the Gatekeeper; the Gatekeeper never knows the user's Freenet node URL.
- **Timing decorrelation**: Because Step 10 yields a portable `VISO-POH-V1:` token and Step 11-15 happen locally at user discretion, waiting before publishing breaks even coarse OAuth-to-Freenet-PUT timing correlation.
- **Persistence across tab reload**: Viso UI stores pending `(persona_index, key_id, blind_secret)` in `viso-delegate` (origin-isolated node store, under a non-underscore key like `pohpending:<index>`) so refreshing Viso before pasting the token does not lose the blinding secret.

---

## Viso Slot Schema (`docs/resources.md` extension)

Slot name: `poh:<provider>`, starting with:

- `SLOT_POH_GITHUB = "poh:github"`

Using a namespaced slot per provider (`poh:github`, later `poh:google`) allows independent addition and independent tombstoning (deletion) without modifying `identity_contract.wasm` or other slots.

Payload (CBOR, well within `MAX_SLOT_BYTES = 128 KiB` at ~350 bytes):

```rust
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PohAttestationV1 {
    pub version: u32,           // 1
    pub key_id: String,         // e.g. "github:age1y:2026"
    #[serde(with = "serde_bytes")]
    pub msg_randomizer: Vec<u8>,// 32 bytes (RFC 9474)
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,           // 256 bytes (RSA-2048 PSS)
}
```

### Verification Rules (Client-Side, Untrusted Node)

1. `version == 1`.
2. `key_id` is in the pinned `POH_ISSUERS` registry (with valid `(provider, tier, epoch, spki_der)`).
3. `msg_randomizer.len() == 32` and `sig.len() == 256` (for RSA-2048).
4. Recompute `poh_msg(key_id, persona_pk)`.
5. Verify `RSABSSA-SHA384-PSS-Randomized` signature against `pk_iss` for `(poh_msg, msg_randomizer, sig)`.
6. Failure policy (same as `ghostkey` in `viso-client`): an invalid/unknown `poh:*` slot is ignored (`None` / omitted from `Identity::poh`), **not** a `FetchError::Malformed` hard failure, so key deprecation or future providers never break `fetch()`.

---

## Crate & Component Changes

### 1. `d:\viso`
- **`common/` (`viso-core`)**:
  - Add feature `poh` (enabled in `ui/` and `toolkit/viso-client/`, **disabled** in `contracts/identity-contract` and `delegates/viso-delegate` so WASM hashes never change).
  - Add `common/src/poh.rs`: `PohAttestationV1`, `PohBadge { provider, tier, epoch, key_id }`, `POH_ISSUERS`, `poh_msg`, `blind_request`, `finalize_attestation`, `verify_attestation`, plus unit tests & golden test vectors.
  - Add `SLOT_POH_GITHUB` constant in `common/src/resources.rs`.
- **`toolkit/viso-client/`**:
  - Enable `poh` feature on `viso-core`.
  - Add `pub poh: Vec<PohBadge>` to `Identity`, populated by scanning `poh:*` keys in `raw_slots`.
- **`ui/`**:
  - Enable `poh` feature on `viso-core`.
  - Add `PersonaPoh` card in `ui/src/views.rs` (parallel to `PersonaGhostkey`), plus `actions.rs` helpers (`start_poh_github`, `attach_poh_github`, `remove_poh_github`) and delegate persistence for the pending blinding secret.
- **`gatekeeper/` (new standalone Rust or Node/TS microservice)**:
  - Minimal stateless HTTP server + SQLite (`nullifiers` table).
  - Serves `GET /github` (OAuth start), `GET /github/callback` (verify GitHub user + BlindSign + render `VISO-POH-V1:` token), `GET /keys` (public JWKS/SPKI metadata).
  - Ships with a `Dockerfile` (mirrors `radica/attester` deployment model).
- **`docs/resources.md`**:
  - Document `poh:<provider>` slot format and `POH_ISSUERS` trust model.

### 2. `d:\radica` (Follow-up consumer integration)
- Read `poh:github` from a user's Viso identity contract (via Freenet node WebSocket + CBOR + `@cloudflare/blindrsa-ts` verification against the same pinned `POH_ISSUERS`).
- Surface anonymous `"Verified Human (GitHub)"` badge on profiles/cards and optionally grant baseline anti-Sybil weight in Greenhouse / community anti-spam rules.

---

## Trust & Threat Model Summary

| Threat | Mitigation |
|---|---|
| Gatekeeper tries to link GitHub user to Viso persona | Mathematically prevented by RFC 9474 blinding; `pk` never leaves client |
| User tries to mint 2 Viso personas with 1 GitHub account | Prevented by `HMAC(secret, "github" \| epoch \| github_id)` nullifier in Gatekeeper DB |
| User copies someone else's `poh:github` slot onto own persona | Fails verification: `poh_msg` binds the persona's own `pk`, and the slot itself is Ed25519-signed by `pk` |
| User upgrades own tier (claims `dev1y` with `age1y` sig) | Impossible: each `(provider, tier, epoch)` uses a distinct RSA keypair |
| Compromised Gatekeeper key | Revoke/remove that `key_id` from `POH_ISSUERS` in `viso-core` (same model as `RECEIPT_ISSUERS` in Radica) |
| Compromised Gatekeeper server minting fake humans | Gatekeeper is open-source & minimal; future hardening can move to `M-of-N` threshold/multi-gatekeeper issuance without changing Viso's contract |
