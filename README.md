# Viso

> **Your decentralized face on Freenet.** Unlinkable personas with cryptographic proof of commitment.

One place for your avatar and profile on [Freenet](https://freenet.org); every
app that knows your public key can fetch them, and an update here shows up
everywhere.

- Each **persona (Viso)** is an Ed25519 keypair derived from one master seed
  (back up the seed once, every persona — even future ones — is
  recoverable). Personas are unlinkable in public.
- Each persona has a **public contract** (address derived from its pubkey)
  holding signed resource slots: `avatar`, `profile`, `ante`, `poh:*` (e.g. `poh:github`), and more in the future.
  See [docs/resources.md](docs/resources.md) for slot specifications and [docs/dapp-integration.md](docs/dapp-integration.md) for the dApp integration guide.
- Built-in **persona level** (`ante` slot): a proof of commitment (PoW blake3)
  ground in the UI and signed by the persona's own key (displayed as `Seeded · 16b`, `Forged · 20b`, `Veteran · 24b` commitment badges), so apps can distinguish
  legitimate users from zero-cost sybil spam. Built on [ante](https://github.com/soudasuwa/ante).
  See [docs/mining-and-ante.md](docs/mining-and-ante.md) for how mining and anti-spam policies work.
- Optional **Anonymous Proof-of-Personhood** (`poh:github`, `poh:google` slots): issued via RFC 9474 Blind RSA
  (`RSABSSA-SHA384-PSS-Randomized`) by [gatekeeper/](gatekeeper/). Proves a persona is backed by
  a real GitHub account (≥ 1 year old) or verified Google account without revealing the external identity or letting the issuer
  link it to the Viso public key.
- The **delegate** is an origin-isolated secret store on your node
  holding the seed; all key derivation and signing happen in the UI.
- **Destroying & Delegating** a persona: destroying publishes a signed permanent marker so public slots on Freenet can no longer be updated, while keeping the Ed25519 key available on your device (`Share with apps`, `Export private key`, local-only label renaming, and `"Sign in with Viso"`). Any persona — including a destroyed one — can issue a dual-signed **`DelegationProofV1`** certificate handing off mutable identity slots (e.g., `profile`, `avatar`, `poh:github`) to an active persona for a specific app (`radica`) or globally (`*`). See Section 7 of [docs/dapp-integration.md](docs/dapp-integration.md).
- **Hiding a persona** from the grid (live or destroyed) is a local-only toggle on its detail page — it never touches Freenet state, badges or the key itself, just this device's view.

## Workspace

| crate / dir | description |
|---|---|
| `common/` (`viso-core`) | Types, signing, LWW merge, derivation — pure Rust, tested |
| `common-ante/` (`viso-ante`) | The `ante` proof-of-commitment slot (verify / grind / sign) |
| `contracts/identity-contract/` | The public identity contract (WASM) |
| `delegates/viso-delegate/` | Seed store delegate (WASM) |
| `toolkit/viso-client/` | Rust consumer crate + `viso-fetch` CLI example |
| `ui/` (`viso-ui`) | Dioxus web UI, published to Freenet as a site contract |
| `gatekeeper/` (`viso-gatekeeper`) | Blind-RSA PoH Gatekeeper (GitHub OAuth + `/keys` endpoint + CapRover Dockerfile) |
| `demo/` (`viso-demo`) | Connect-flow demo app (verify proof, fetch profile, check level) |
| `e2e/` | Playwright test suite |

## Guides & Documentation

- [**Integrating Viso into a dApp**](docs/dapp-integration.md): Step-by-step guide with **TypeScript / JavaScript** and **Rust** examples for the Connect flow ("Sign in with Viso"), profile reading, avatar loading, `ante` / `poh:github` anti-Sybil policies, and writing as a persona through a delegated app key.
- [**Mining & Proof of Commitment (`ante`)**](docs/mining-and-ante.md): Everything about persona-level mining, BLAKE3 PoW mechanics, grinding in the UI, and implementing anti-spam policies.
- [**Public Resources & Slots Specification**](docs/resources.md): Full specification of slots (`profile`, `avatar`, `ante`, `poh:*`), lifecycle rules, and wire formats.
- [**Gatekeeper Deployment & Issuer Sync**](gatekeeper/README.md): Running `viso-gatekeeper` locally or on CapRover and syncing issuer keys with [scripts/sync-poh-issuers.ps1](scripts/sync-poh-issuers.ps1).

## Consuming a Viso persona (Rust)

```rust
let pk = viso_client::parse_pubkey("…bs58 or hex…")?;
let id = viso_client::fetch(
    "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native", &pk).await?;

// id.profile: Option<ProfileV1 { name, bio }>
// id.avatar: Option<Vec<u8>>
// id.ante_bits: Option<u32> — verified persona level; apply your own min_bits policy
// id.has_poh("github") / id.poh: Vec<PohBadge> — verified Blind-RSA PoH attestations
```

Signatures and proof-of-work are verified client-side; the serving node is untrusted.

### Connect flow ("Sign in with Viso")

Apps can ask the user to prove persona ownership:
open the Viso site with `?connect=v1&challenge=…&return=…`,
verify the signed callback (`viso=ok&pk=…&sig=…`), then fetch the proven key's contract.
See the connect-flow section of [docs/resources.md](docs/resources.md) and the demo app in [demo/](demo/).

From a shell:

```sh
cargo run -p viso-client --example viso-fetch -- --key <pubkey> --avatar-out avatar.png
```

## Building & Testing

```sh
cargo test --workspace
```

## Publishing to Freenet

The Viso web app can be published as a Freenet static website contract using `fdev`:

```sh
# Via PowerShell (Windows):
./scripts/publish-ui.ps1

# Or via Bash (Linux / macOS):
./scripts/publish-ui.sh
```

Or manually:

```sh
cd ui && dx build --release --base-path "."
fdev website init viso
fdev website publish --key viso target/dx/viso-ui/release/web/public
```

Once published on your local node, open:
`http://127.0.0.1:7509/v1/contract/web/<CONTRACT_KEY>/`

Published site key: `viso`  
Website Contract Address: `GzHy3jnEtj26EoGqMsBpoawcY378hK9kp91rTcNYiAac`

## Roadmap

- Phase 2: App association handshake
- Phase 3: OAuth-like cross-app delegation grants
- TypeScript client toolkit
