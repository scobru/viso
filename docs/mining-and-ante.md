# Mining & Proof of Commitment (`ante`) in Viso

This document explains how **persona-level mining** works in Viso, why it exists, how users raise their level in the UI, and how dApps can leverage it for sybil resistance and anti-spam protection.

---

## 1. Why Proof of Commitment?

On decentralized, pseudonymous networks like Freenet:
- Anyone can generate millions of fresh Ed25519 keypairs at zero computational cost.
- A malicious actor can easily launch **Sybil attacks**, flooding chat rooms, guestbooks, forums, and poll systems with fake identities.
- Traditional anti-spam mechanisms (phone numbers, captchas, KYC, centralized OAuth) destroy user privacy and violate Freenet's censorship-resistant ethos.

**Viso solves this using [Ante](https://github.com/soudasuwa/ante)**:
Instead of requiring identity verification, a persona can bind a verifiable **Proof of Commitment (PoW)** to its public key. This proves that the owner spent measurable CPU effort creating that specific persona.

> **Key takeaway:** A persona level proves that an identity **cost something** to produce. It does *not* claim that the persona is unique or tied to a real-world human, but it ensures that spamming $N$ messages requires $N \times \text{Work}$, making automated mass-spam economically unfeasible.

---

## 2. Cryptographic Specification

The commitment proof is stored in the persona's public contract under the slot name **`ante`**.

### The Proof Structure (`AnteProof` v0.2.0)

A CBOR-encoded structure containing:
- `identity_vk`: The 32-byte Ed25519 public key of the persona.
- `purpose`: String constant: **`viso:persona-level:v1`**.
- `nonce`: A 64-bit unsigned integer (`u64`).
- `ts`: Timestamp in milliseconds when the proof was signed.
- `signature`: A 64-byte Ed25519 signature over the proof by `identity_vk`.

### The Mining Challenge

The proof-of-work challenge is deterministic and unique to each persona:

$$\text{Challenge} = \text{"ante:pow-challenge:v1"} \parallel \text{len}(purpose)_{u32le} \parallel purpose \parallel identity\_vk$$

To find a valid proof, the miner increments a 64-bit `nonce` until the hash exhibits the desired number of leading zero bits:

$$\text{Hash} = \text{BLAKE3}(\text{Challenge} \parallel nonce_{u64le})$$

$$\text{Bits} = \text{CountLeadingZeros}(\text{Hash})$$

### The Signature

Once the nonce is found, the persona signs:
$$\text{"ante:proof-signature:v1"} \parallel identity\_vk \parallel \text{len}(purpose)_{u32le} \parallel purpose \parallel nonce_{u64le} \parallel ts_{u64le}$$

Because the proof commits to `identity_vk`, **a proof cannot be transferred, reused, or stolen by any other persona**.

---

## 3. Difficulty Levels and Mining Time

Difficulty scales exponentially: every $+1$ bit doubles the required work.

| Level | Expected Hashes ($2^n$) | Typical Time (Browser/WASM) | Typical Use Case |
|---|---|---|---|
| **16 bits** | $\approx 65,536$ | **~50 – 100 ms** | Fast speed-bump: prevents basic spam bots, zero-cost throwaways |
| **20 bits** | $\approx 1,048,576$ | **~1 – 2 seconds** | Standard persona level: guestbook signers, poll voters, community chats |
| **24 bits** | $\approx 16,777,216$ | **~15 – 30 seconds** | High-reputation personas: moderation, admin actions, governance proposals |

---

## 4. How Mining Works in the Viso UI

In the Viso web application:

1. Under each persona card, there is a **Persona level** widget.
2. The UI shows the current level (e.g. `none yet` or `20 bits`).
3. The user can select a target: `16 bits`, `20 bits`, or `24 bits`.
4. When the user clicks **Raise level**:
   - The browser starts hashing in chunks of 20,000 hashes (`GRIND_CHUNK`).
   - Between chunks, the WebAssembly worker/runtime yields to the browser event loop (`sleep_ms(0)`). This ensures the UI remains fully interactive (no freezing) and displays an accurate progress percentage.
   - Once a valid nonce is found, the UI signs the `AnteProof` with the persona's private key.
   - The signed proof is published to Freenet as the persona's `ante` slot.
   - Viso prevents downgrading: an existing level cannot be replaced by a lower difficulty proof.

---

## 5. Implementing Anti-Spam in your dApp

### Why dApps must verify client-side

The Freenet node returns the raw contract state. Since the serving node is untrusted:
1. Recompute the leading zero bits from the `nonce` and the persona's `pubkey`.
2. Verify the Ed25519 signature on the proof.
3. Compare against your dApp's minimum policy.

### Checking Level in Rust (`viso-client`)

`viso-client` verifies the proof automatically during `fetch()`:

```rust
use viso_client::{fetch, parse_pubkey};

let pk = parse_pubkey("3bYj...")?;
let identity = fetch(node_ws_url, &pk).await?;

const MIN_BITS: u32 = 18;

match identity.ante_bits {
    Some(bits) if bits >= MIN_BITS => {
        println!("Persona level verified ({} bits) — allowing action", bits);
    }
    Some(bits) => {
        println!("Persona level too low ({} < {} bits) — rejected", bits, MIN_BITS);
    }
    None => {
        println!("No persona level found — rejected", MIN_BITS);
    }
}
```

### Checking Level in TypeScript / JavaScript

Using `@noble/ed25519` and `@noble/hashes/blake3`:

```typescript
import * as ed from "@noble/ed25519";
import { blake3 } from "@noble/hashes/blake3.js";

const enc = new TextEncoder();
const u32le = (n: number) => new Uint8Array(new Uint32Array([n]).buffer);
const u64le = (n: number) => new Uint8Array(new BigUint64Array([BigInt(n)]).buffer);

function countLeadingZeroBits(bytes: Uint8Array): number {
  let count = 0;
  for (const b of bytes) {
    count += Math.clz32(b) - 24;
    if (b !== 0) break;
  }
  return count;
}

export function verifyPersonaLevel(
  identityPubkey: Uint8Array,
  nonce: number,
  ts: number,
  signature: Uint8Array
): { valid: boolean; bits: number } {
  const purpose = "viso:persona-level:v1";
  const pBytes = enc.encode(purpose);

  // 1. Recompute PoW challenge
  const challenge = new Uint8Array(
    enc.encode("ante:pow-challenge:v1").length + 4 + pBytes.length + identityPubkey.length
  );
  let offset = 0;
  for (const part of [enc.encode("ante:pow-challenge:v1"), u32le(pBytes.length), pBytes, identityPubkey]) {
    challenge.set(part, offset);
    offset += part.length;
  }

  // 2. Compute BLAKE3 hash and count leading zero bits
  const hashInput = new Uint8Array(challenge.length + 8);
  hashInput.set(challenge);
  hashInput.set(u64le(nonce), challenge.length);

  const hash = blake3(hashInput);
  const bits = countLeadingZeroBits(hash);

  // 3. Verify signature
  const signPayload = new Uint8Array(
    enc.encode("ante:proof-signature:v1").length + identityPubkey.length + 4 + pBytes.length + 8 + 8
  );
  offset = 0;
  for (const part of [
    enc.encode("ante:proof-signature:v1"),
    identityPubkey,
    u32le(pBytes.length),
    pBytes,
    u64le(nonce),
    u64le(ts)
  ]) {
    signPayload.set(part, offset);
    offset += part.length;
  }

  const validSig = ed.verify(signature, signPayload, identityPubkey);
  return { valid: validSig, bits };
}
```

### Recommended dApp Policies

- **Public Chat / Comments:** Require `16 bits`. Fast for users, but makes mass-bot attacks 65,000x more expensive.
- **Polls / Voting (like FreeForms):** Require `18 – 20 bits` to prevent one person from spinning up hundreds of disposable voting accounts.
- **Micro-Blogging / Publishing:** Require `20 bits` to register an author profile.
