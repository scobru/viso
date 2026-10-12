# Integrating Viso into a Freenet dApp

This guide explains how to integrate **Viso** into your Freenet application:
1. **Connect Flow ("Sign in with Viso")**: Authenticate users without passwords or centralized servers.
2. **Reading Persona Data**: Retrieve public profiles (`name`, `bio`) and avatars.
3. **Anti-Spam & Sybil Resistance**: Verify the persona's proof-of-commitment level (`ante` slot).
4. **Writing as a persona**: let one sign-in authorize an app key that signs your contract writes.

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
