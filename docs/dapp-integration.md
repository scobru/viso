# Integrating Viso into a Freenet dApp

This guide explains how to integrate **Viso** into your Freenet application:
1. **Connect Flow ("Sign in with Viso")**: Authenticate users without passwords or centralized servers.
2. **Reading Persona Data**: Retrieve public profiles (`name`, `bio`) and avatars.
3. **Anti-Spam & Sybil Resistance**: Verify the persona's proof-of-commitment level (`ante` slot) and anonymous Proof-of-Personhood (`poh:github` slot).
4. **Writing as a persona**: let one sign-in authorize an app key that signs your contract writes.
5. **Policy Gating with GitHub PoH (`poh:github`)**: Require a verified GitHub account (via Blind RSA, zero linkability) in Rust or TypeScript.

Ready-to-use implementations are provided for both **TypeScript / JavaScript** (for web dApps) and **Rust** (for backend/native nodes).

---

## 1. How Viso Works

- **Every persona is an Ed25519 keypair** derived deterministically from a master seed stored in the user's local Freenet node delegate.
- **Each persona has a public contract** on Freenet whose address is computed directly from its public key and the Viso identity contract code.
- **Contract state is composed of signed slots**:
  - `profile`: CBOR object containing `{ name: string, bio: string }`.
  - `avatar`: Raw PNG or WebP image bytes (≤ 128 KiB).
  - `ante`: Cryptographic proof-of-work commitment (BLAKE3) signed by the persona.
- The serving node is untrusted: consumers verify Ed25519 signatures and PoW client-side.

---

## 2. Connect Flow ("Sign in with Viso")

When your app needs to know *who* the user is, you redirect the user to the Viso site with a challenge. Viso prompts the user to select a persona, signs a single-use proof bound to your app's origin and path, and returns to your callback URL.

### Step 1: Redirect to Viso

Generate a random single-use nonce (`challenge`) and redirect the user:

```
http://<node-host>:7509/v1/contract/web/<VISO_SITE_CONTRACT_KEY>/?connect=v1&challenge=<CHALLENGE>&return=<RETURN_URL>
```

- `challenge`: Random string (`[A-Za-z0-9._~-]`, ≤ 256 characters). Store this in your app session or memory to verify upon return.
- `return`: URL-encoded callback URL (must match the app's current origin + pathname).
- `base` (optional): a canonical origin+pathname to sign instead of `return`'s, e.g. `http://127.0.0.1:7509/v1/contract/web/<APP_KEY>/`. It is used only when its path equals `return`'s path (and it has no query or fragment); otherwise Viso signs `return`'s origin+path as before. Use it when your app publishes the certificate, so the user's node host is not exposed. Verify the proof against the base you sent, and fall back to your own origin+pathname for a Viso that ignores `base`.
- `key=v1` + `epk` (optional): ask Viso to derive a per-app secret for you. `epk` is a fresh, single-use **X25519 public key** (64 hex chars) you generate for this request and keep the private half of; Viso refuses `key=v1` without it. The secret comes back **encrypted** in the callback fragment as `#esk=<viso_epk_hex>.<ciphertext_hex>`, never in the clear (URLs end up in browser history). Decrypt: `shared = X25519(your_private, viso_epk)`; `key = blake3_derive_key("viso connect v1 app secret", shared || viso_epk || your_epk)`; secret = ChaCha20-Poly1305 decrypt of the ciphertext (32-byte secret + 16-byte tag) with `key` and an all-zero 12-byte nonce. Discard your private key afterwards.
- `<VISO_SITE_CONTRACT_KEY>`: The contract key of the Viso site (e.g. `GzHy3jnEtj26EoGqMsBpoawcY378hK9kp91rTcNYiAac` on local test nodes).

> **Navigation note in Freenet Sandbox:**  
> If your dApp runs in the Freenet web sandbox (inside the shell iframe), initiate navigation using the shell's postMessage bridge:
> ```js
> window.parent.postMessage({
>   __freenet_shell__: true,
>   type: 'navigate',
>   href: visoUrl
> }, '*');
> ```

---

### Step 2: Handle the Callback

Viso bounces back to your `return` URL with query parameters:

- **If accepted:**  
  `?viso=ok&pk=<HEX_32B_PUBKEY>&sig=<HEX_64B_SIG>&challenge=<ECHO>&ts=<TIMESTAMP_MS>`
- **If cancelled:**  
  `?viso=denied`

---

### Step 3: Verify the Proof

You **must** verify:
1. `challenge` matches the one you generated (burn it immediately — one-time use).
2. `ts` is fresh (within ±10 minutes of current time).
3. `sig` is a valid Ed25519 signature by `pk` over the domain-separated message:
   ```
   "whoiam-connect-v1" || pk (32B) || len(return_base) (u32-le) || return_base || len(challenge) (u32-le) || challenge || ts (u64-le)
   ```
   where `return_base` is your app's `origin + pathname`.

#### Verification in TypeScript (using `@noble/ed25519`):

```typescript
import * as ed from "@noble/ed25519";

const enc = new TextEncoder();
const unhex = (h: string) => ed.etc.hexToBytes(h);

export function connectMessage(pk: Uint8Array, returnBase: string, challenge: string, ts: number): Uint8Array {
  const parts = [
    enc.encode("whoiam-connect-v1"),
    pk
  ];
  
  for (const str of [returnBase, challenge]) {
    const b = enc.encode(str);
    parts.push(new Uint8Array(new Uint32Array([b.length]).buffer), b);
  }
  
  parts.push(new Uint8Array(new BigUint64Array([BigInt(ts)]).buffer));
  
  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export async function verifyConnectProof(
  pkHex: string,
  sigHex: string,
  returnBase: string,
  challenge: string,
  ts: number,
  expectedChallenge: string,
  maxAgeMs = 10 * 60 * 1000
): Promise<boolean> {
  // 1. Challenge check
  if (challenge !== expectedChallenge) return false;

  // 2. Freshness check
  const now = Date.now();
  if (Math.abs(now - ts) > maxAgeMs) return false;

  // 3. Cryptographic signature check
  try {
    const pk = unhex(pkHex);
    const sig = unhex(sigHex);
    const msg = connectMessage(pk, returnBase, challenge, ts);
    return await ed.verifyAsync(sig, msg, pk);
  } catch {
    return false;
  }
}
```

#### Verification in Rust (`viso-core`):

```rust
use viso_core::connect::verify_connect;
use ed25519_dalek::VerifyingKey;

let pk = VerifyingKey::from_bytes(&pk_bytes)?;
let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes)?;

verify_connect(&pk, &sig, &return_base, &challenge, ts, now_ms, 10 * 60 * 1000)?;
```

---

## 3. Fetching the Persona's Contract State

Once you have verified the public key `pk`, you can fetch the persona's public profile and avatar.

### Deriving the Contract Address

The identity contract key is derived offline from the public key and the identity contract code:

```
Parameters: CBOR { version: 1, pubkey: <32-byte Ed25519 key> }
Contract:   identity_contract.wasm
```

In Rust, use `viso_client::contract_key(&pk)`.

### Option A: Using `viso-client` (Rust)

Add `viso-client` to your `Cargo.toml`:

```toml
[dependencies]
viso-client = { git = "https://github.com/scobru/viso", package = "viso-client" }
```

Fetching an identity:

```rust
use viso_client::{fetch, parse_pubkey};

let pk = parse_pubkey("3bYj...")?;
let identity = fetch(
    "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native",
    &pk
).await?;

// Name & Bio
if let Some(profile) = identity.profile {
    println!("Name: {}", profile.name);
    println!("Bio: {}", profile.bio);
}

// Avatar
if let Some(avatar_png_bytes) = identity.avatar {
    println!("Avatar size: {} bytes", avatar_png_bytes.len());
}

// Proof-of-Commitment level (anti-spam)
if let Some(level_bits) = identity.ante_bits {
    println!("Persona commitment level: {} bits", level_bits);
}
```

### Option B: In a Web Frontend (TypeScript / WebSocket)

In a web dApp, connect to the Freenet WebSocket API (`ws://127.0.0.1:7509/v1/contract/command` or via Freenet's WebApi bridge).

1. Send a `Get` request for the contract key.
2. Deserialize the returned state using CBOR.
3. Verify the individual slot signatures with the persona's public key.
4. Render:
   - `profile`: display `name` (max 64 chars) and `bio` (max 280 chars) as plain text.
   - `avatar`: convert PNG bytes to an `object URL` or `data:image/png;base64,...`.
   - `ante`: check `ante_bits`.

---

## 4. Anti-Spam Policy with `ante`

To prevent bot spam, check the persona's `ante_bits`:

```typescript
function canUserPost(personaAnteBits: number | null): boolean {
  const MIN_REQUIRED_BITS = 16; // Adjust based on your dApp's policy
  return (personaAnteBits ?? 0) >= MIN_REQUIRED_BITS;
}
```

See [docs/mining-and-ante.md](mining-and-ante.md) for full details on how mining works and how to set appropriate difficulty thresholds.

---

## 5. Writing as a Persona: Delegating to an App Key

The connect flow proves *who* the user is, once. But Viso never signs your app's data: your contracts need every write (a post, a vote, a list) signed, and you cannot send the user back to Viso for each one. The pattern used by [FreePolls](https://github.com/scobru/freepolls), [FreeNames](https://github.com/scobru/freenames) and [FH](https://github.com/scobru/FH): **the sign-in authorizes an app key**, and the app key signs the writes.

### How it works

1. On each node your app keeps a random Ed25519 **app key** (in a delegate store or `localStorage`; inside the sandboxed web container pages have no storage, so FreePolls ships a small per-app identity delegate).
2. The connect flow uses the challenge **`wd1.<app key hex>.<random nonce>`**. Viso signs it for your `return` URL, so the proof says: *this app key may act for me in the app served at this path*.
3. Keep the proof as a **certificate**: `{ base, challenge, ts, sig }` (`base` = your `return` URL, `sig` = Viso's signature).
4. Every write is signed by the app key with a domain-separated message (e.g. `myapp-post1|<params>|<ts>|<body>`) and carries the certificate.
5. Your contract checks, for each write: the certificate's path is the app path in the contract's **parameters**, Viso's signature over the certificate holds for the persona, the app key is the one in the challenge, and the app key signed the write.

Put the app path (`/v1/contract/web/<your app id>/`) in your contracts' parameters, next to the persona key: a delegation made for another app is then useless in yours, and the same app on another node (other host) still works, because only the path is compared.

### In the contract (Rust)

The [`whoiam-delegation`](https://github.com/scobru/freenames/tree/main/delegation) crate does the checks (no Freenet dependency):

```toml
whoiam-delegation = { git = "https://github.com/scobru/freenames", rev = "d6dc35f8d0d85c0d95430c5da3c3eeb8e9ee9120" }
```

```rust
use whoiam_delegation::{check, verify, Cert, R};

/// params = persona (32 bytes) || app path
fn check_write(params: &[u8], body: &str, ts: u64, sig: &str, cert: &Cert) -> R<()> {
    let persona = hex::encode(&params[..32]);
    let app = std::str::from_utf8(&params[32..]).map_err(|e| e.to_string())?;
    let app_key = check(&persona, app, cert)?; // path, Viso's signature, `wd1.` challenge
    verify(&app_key, format!("myapp-post1|{}|{ts}|{body}", hex::encode(params)).as_bytes(), sig)
}
```

Merges must converge in any order: keep, per item, the newest signed write (ties broken by signature), as FH's list contract does.

### In the web app (TypeScript)

```ts
import * as ed from "@noble/ed25519";
const hex = ed.etc.bytesToHex, enc = new TextEncoder();
const APP_PATH = location.pathname;                                  // e.g. /v1/contract/web/<your app id>/
const linkBase = () => `${location.protocol}//${location.host}${APP_PATH}`;

// 1. start: remember a one-time challenge naming this node's app key, then go to Viso (through the shell)
const appKey = hex(await ed.getPublicKeyAsync(appSecret));
const challenge = `wd1.${appKey}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`;
await storePut("signin-pending", challenge);
goTo(`${visoUrl}?connect=v1&challenge=${challenge}&return=${encodeURIComponent(linkBase())}`);

// 2. callback (?viso=ok&pk&sig&challenge&ts): burn the challenge, check freshness and Viso's signature (section 2)
const cert = { base: linkBase(), challenge: q.get("challenge")!, ts: Number(q.get("ts")), sig: q.get("sig")! };
await storePut("session", JSON.stringify({ persona: q.get("pk"), cert }));

// 3. every write: sign with the app key, send the certificate along
const sig = hex(await ed.signAsync(enc.encode(`myapp-post1|${paramsHex}|${ts}|${body}`), appSecret));
```

Complete versions, with the identity delegate fallback: FreePolls `ui/src/lib.ts` (`startSignIn`, `finishSignIn`, `session`), FH `src/sync.ts`.

### Without Viso: an identity made in the app

Users without Viso can create a key in your app: the app signs the very same certificate with that key (`connectMessage(persona, base, challenge, ts)`), so contracts cannot tell the difference. Show the key once for backup: pasting it in any app that uses this pattern, on any node, brings the same identity back. See `createLocalIdentity` in FreePolls or FH.

### Things to know

- **No expiry, no revocation yet.** Contracts have no clock, so a certificate is valid forever: whoever controls a node the user signed in from can keep writing as the persona in that app.
- **Viso's screen says "sign in to <origin>"**, not "authorize this key". Tell users in your app what signing in allows.
- **One app key per node.** A new node is a new sign-in; the persona, not the key, owns the data. If the app key changes, ask the user to sign in again.
- **Keep anonymous keys apart.** Certificates are public: never reuse the delegated app key for actions that must not be linked to the persona (FreePolls keeps respondents' keys separate).

---

## 6. Requiring Anonymous GitHub Proof-of-Personhood (`poh:github`)

If your dApp wants to enforce a **unique/real human policy** (for example, requiring users to hold a verified GitHub account `>= 1 year old` to post, vote, claim an allocation, or bypass proof-of-work fees), you can require the persona's `poh:github` slot.

Because attestations use **RFC 9474 Blind RSA (`RSABSSA-SHA384-PSS-Randomized`)**:
- Your app learns **only** that the persona holds a valid signature from a trusted Gatekeeper issuer (`provider = "github"`, `tier = "age1y"`, `epoch = "2026"`).
- Your app **never** learns the user's GitHub username or ID, and the Gatekeeper **never** learns which Viso public key received the badge.

### Step 1: Identify the user with Sign-in with Viso

Use the normal Connect Flow (Section 2) to obtain and verify the persona's Ed25519 public key `pk`.

### Step 2: Fetch and enforce the `poh:github` policy

#### Option A: Rust (`viso-client`)

`viso_client::fetch` automatically verifies every `poh:*` slot signature and Blind-RSA proof against `viso_core::poh::POH_ISSUERS`, populating `identity.poh` (invalid or unrecognized slots are ignored):

```rust
use viso_client::{fetch, parse_pubkey};

let pk = parse_pubkey(&persona_pk_hex)?;
let identity = fetch(
    "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native",
    &pk,
).await?;

// Simple policy: require any verified GitHub PoH badge
if !identity.has_poh("github") {
    return Err("This action requires a verified GitHub PoH badge in Viso".into());
}

// Strict policy: inspect tier / epoch
let valid_tier = identity
    .poh_badge("github")
    .is_some_and(|b| b.tier == "age1y" && b.epoch == "2026");
```

#### Option B: Browser / TypeScript (WebCrypto `RSA-PSS` + `SHA-384`)

In a web dApp you can verify `poh:github` with zero RSA libraries using the browser's built-in `crypto.subtle`:

1. Fetch the persona's identity contract state (`Get` on `visoIdentityInstance(pkHex)`), check that `destroyed` is unset, and verify the `poh:github` slot's Ed25519 signature by `pk` (see `common/src/state.rs`).
2. Decode the slot bytes as CBOR `PohAttestationV1 { version: 1, key_id, msg_randomizer, sig }`.
3. Look up `key_id` in your pinned issuer registry (synced from your Gatekeeper's `GET /keys`, or synced via `scripts/sync-poh-issuers.ps1`).
4. Verify the Blind-RSA signature over `msg_randomizer || "viso-poh-v1" || u32le(len(key_id)) || key_id || pk_bytes`:

```typescript
const enc = new TextEncoder();

export interface PohIssuer {
  keyId: string;
  provider: string;
  tier: string;
  epoch: string;
  spkiDerHex: string; // RSA SubjectPublicKeyInfo DER (hex), from Gatekeeper /keys
}

export interface PohBadge {
  provider: string;
  tier: string;
  epoch: string;
  keyId: string;
}

function unhex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function pohMessage(keyId: string, pkBytes: Uint8Array): Uint8Array {
  const kb = enc.encode(keyId);
  const len = new Uint8Array(new Uint32Array([kb.length]).buffer);
  return concatBytes(enc.encode("viso-poh-v1"), len, kb, pkBytes);
}

export async function verifyPohAttestation(
  att: { version: number; key_id: string; msg_randomizer: Uint8Array; sig: Uint8Array },
  pkBytes: Uint8Array,
  issuers: readonly PohIssuer[],
): Promise<PohBadge | null> {
  if (att.version !== 1 || att.msg_randomizer.length !== 32 || !att.sig.length) {
    return null;
  }
  const issuer = issuers.find((i) => i.keyId === att.key_id);
  if (!issuer) return null;

  const key = await crypto.subtle.importKey(
    "spki",
    unhex(issuer.spkiDerHex),
    { name: "RSA-PSS", hash: "SHA-384" },
    false,
    ["verify"],
  );

  // RFC 9474 RSABSSA-SHA384-PSS-Randomized prepends msg_randomizer and uses 48-byte PSS salt
  const input = concatBytes(att.msg_randomizer, pohMessage(att.key_id, pkBytes));
  const ok = await crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 48 },
    key,
    att.sig,
    input,
  );

  return ok
    ? { provider: issuer.provider, tier: issuer.tier, epoch: issuer.epoch, keyId: issuer.keyId }
    : null;
}

// Example policy helper:
export function requiresGithubPoh(badges: PohBadge[]): boolean {
  return badges.some((b) => b.provider === "github" && b.tier === "age1y");
}
```

### Keeping Issuer Keys in Sync

Use `scripts/sync-poh-issuers.ps1` to pull active public keys from a running Gatekeeper (`/keys`) and update `common/src/poh.rs` (`POH_ISSUERS`) automatically:

```powershell
.\scripts\sync-poh-issuers.ps1 -FromUrl https://viso-poh.scobrudot.dev
```

If you reject an unverified user in your app UI, prompt them to open Viso, select their persona, and complete **"Anonymous GitHub PoH → Connect with GitHub"** — once attached, your app sees the `poh:github` slot on the next persona fetch without requiring a new login.

---

## 7. Persona-to-Persona Handoff (`DelegationProofV1`)

When a user wants to rotate keys or keep an existing app identity anchored to `from` (even if `from`'s Viso contract on Freenet is `Destroyed on Freenet`) while fetching mutable profile slots / PoH badges from a live persona `to`, Viso can issue a dual-signed JSON certificate under **"Delegate to another persona"**:

```json
{
  "version": 1,
  "from": "<base58 Ed25519 pubkey>",
  "to": "<base58 Ed25519 pubkey>",
  "scope": "*",
  "time_ms": 1794781500000,
  "sig_from": "<128-char hex Ed25519 signature by from>",
  "sig_to": "<128-char hex Ed25519 signature by to>"
}
```

Both `from` and `to` sign the exact same domain-separated message, proving ownership of both Ed25519 keys without weakening Viso's global contract-destruction guarantees:

```text
"viso-delegation-v1" || from(32 bytes) || to(32 bytes) || u32le(scope.len) || scope(utf8) || u64le(time_ms)
```

### Verification in Rust (`viso-core` / `viso-client`)

```rust
use viso_client::delegation::{verify_delegation, DelegationProofV1};

let proof: DelegationProofV1 = /* parsed JSON */;
let verified = verify_delegation(&proof)?;
// Store in your app state: `verified.from` delegates `verified.scope` to `verified.to`.
```

### Verification in TypeScript (`@noble/ed25519`)

```ts
import * as ed from "@noble/ed25519";

const enc = new TextEncoder();

function delegationMessage(fromBytes: Uint8Array, toBytes: Uint8Array, scope: string, timeMs: number): Uint8Array {
  const domain = enc.encode("viso-delegation-v1");
  const scopeBytes = enc.encode(scope);
  const out = new Uint8Array(domain.length + 32 + 32 + 4 + scopeBytes.length + 8);
  const view = new DataView(out.buffer);
  let off = 0;
  out.set(domain, off); off += domain.length;
  out.set(fromBytes, off); off += 32;
  out.set(toBytes, off); off += 32;
  view.setUint32(off, scopeBytes.length, true); off += 4;
  out.set(scopeBytes, off); off += scopeBytes.length;
  view.setBigUint64(off, BigInt(timeMs), true);
  return out;
}

export async function verifyDelegationProof(
  proof: { version: number; from: string; to: string; scope: string; time_ms: number; sig_from: string; sig_to: string },
  decodePubkey: (pk: string) => Uint8Array,
  unhex: (h: string) => Uint8Array,
): Promise<boolean> {
  if (proof.version !== 1 || !proof.scope || proof.from === proof.to) return false;
  const fromBytes = decodePubkey(proof.from);
  const toBytes = decodePubkey(proof.to);
  const msg = delegationMessage(fromBytes, toBytes, proof.scope, proof.time_ms);
  const okFrom = await ed.verifyAsync(unhex(proof.sig_from), msg, fromBytes);
  const okTo = await ed.verifyAsync(unhex(proof.sig_to), msg, toBytes);
  return okFrom && okTo;
}
```
