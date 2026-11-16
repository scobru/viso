# Viso PoH Gatekeeper

Blind-RSA (RFC 9474) OAuth gatekeeper for Viso anonymous Proof-of-Personhood (`poh:github` and `poh:google`).

## What it sees vs. what it never sees

- **GitHub (`poh:github`)**: sees GitHub OAuth `id`, `type`, `created_at`, `public_repos`.
- **Google (`poh:google`)**: sees Google OIDC `sub` and `email_verified`.
- **Stores**: Only `HMAC-SHA256(secret, "viso-poh-nullifier-v1|<provider>|<epoch>|<account_id>")` + day-rounded UTC timestamp in `$DATA_DIR/nullifiers.log`. No usernames, emails, IDs, tokens, or IPs.
- **Never sees**: The user's Viso persona public key or Freenet node URL.

## Quick start

1. Generate an RSA-2048 keypair for an epoch/tier:

```sh
cargo run -p viso-gatekeeper -- keygen --key-id github:age1y:2026 --out-dir ./keys
```

2. Paste the printed `PohIssuer { ... }` entry into `common/src/poh.rs` (`POH_ISSUERS`).
3. Create `issuers.json`:

```json
[
  {
    "key_id": "github:age1y:2026",
    "provider": "github",
    "tier": "age1y",
    "epoch": "2026",
    "min_age_days": 365,
    "min_public_repos": 0,
    "pkcs8_path": "./keys/github_age1y_2026.pkcs8.der"
  }
]
```

4. Run the server with a GitHub OAuth App (callback URL `<PUBLIC_BASE_URL>/github/callback`):

```sh
PUBLIC_BASE_URL=https://poh.example.org \
GITHUB_CLIENT_ID=... \
GITHUB_CLIENT_SECRET=... \
ISSUERS_CONFIG=./issuers.json \
DATA_DIR=./data \
cargo run -p viso-gatekeeper
```

## Deploy on CapRover

Root `captain-definition` builds `./gatekeeper/Dockerfile`.

1. Create a CapRover app (e.g. `viso-poh`), set **HTTP Container Port** to `8080`, enable **HTTPS + Force HTTPS**, and add a **Persistent Directory** mapped to **`/data`**.
2. Create OAuth apps with callback `<PUBLIC_BASE_URL>/github/callback` (GitHub) and/or `<PUBLIC_BASE_URL>/google/callback` (Google OAuth Web Application).
3. In **App Configs → Environment Variables**, set:
   - `PUBLIC_BASE_URL=https://poh.yourdomain.com`
   - For GitHub: `GITHUB_CLIENT_ID=...`, `GITHUB_CLIENT_SECRET=...`
   - For Google: `GOOGLE_CLIENT_ID=...`, `GOOGLE_CLIENT_SECRET=...`
   *(Optional: `AUTO_KEY_ID` defaults to `github:age1y:2026`, `AUTO_GOOGLE_KEY_ID` defaults to `google:verified:2026`, `AUTO_MIN_AGE_DAYS=365`, `HMAC_SECRET` auto-created in `/data/hmac.secret`.)*
4. Deploy from `d:\viso` via `caprover deploy` (or connect GitHub repo in Deployment). On first startup (`AUTO_INIT_ISSUER=1`), the container automatically mints RSA-2048 keypairs under `/data/keys/` (one for each configured provider), writes `/data/issuers.json`, and reuses them on every future restart.
5. Once live, pin the public key into Viso (and Radica) directly from `/keys`:
   ```sh
   ./scripts/sync-poh-issuers.ps1 -FromUrl https://poh.yourdomain.com
   ```
