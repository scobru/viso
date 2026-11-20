//! User-intent actions: onboard, edit, backup, destroy. Every action signs
//! locally with a key derived on demand from the delegate-held seed.

use dioxus::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_bytes::ByteBuf;
use viso_core::delegate_api::{
    IdentityEntry, IdentityMeta, WhoiamDelegateRequest, KEY_META, KEY_SEED,
};
use viso_core::derive::identity_signing_key;
use viso_core::resources::{check_avatar_bytes, check_profile, ProfileV1, SLOT_AVATAR, SLOT_PROFILE};
use viso_core::state::{sign_destroy, sign_slot, IdentityStateV1};

use crate::api;
use crate::keys;
use crate::state::*;

/// Cached per (seed, index): views ask on every render, and each derivation
/// is an Ed25519 scalar multiplication.
pub fn identity_pubkey(index: u32) -> Option<VerifyingKey> {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    thread_local! {
        static CACHE: RefCell<([u8; 32], BTreeMap<u32, VerifyingKey>)> = RefCell::default();
    }
    let s = seed()?;
    Some(CACHE.with_borrow_mut(|(cached_seed, keys)| {
        if *cached_seed != s {
            *cached_seed = s;
            keys.clear();
        }
        *keys
            .entry(index)
            .or_insert_with(|| identity_signing_key(&s, index).verifying_key())
    }))
}

/// Raw 32-byte secret key scalar of the persona's Ed25519 keypair.
pub fn persona_secret_bytes(index: u32) -> Result<[u8; 32], String> {
    signing_key(index).map(|sk| sk.to_bytes())
}

/// Sign a dual-key persona handoff certificate (`from_index` -> `to_index`)
/// using keys derived locally from the delegate seed. Works even when
/// `from_index`'s Viso contract is destroyed on Freenet.
pub fn sign_delegation_proof(
    from_index: u32,
    to_index: u32,
    scope: &str,
    time_ms: u64,
) -> Result<viso_core::delegation::DelegationProofV1, String> {
    let scope = scope.trim();
    let scope = if scope.is_empty() {
        viso_core::delegation::DELEGATION_DEFAULT_SCOPE
    } else {
        scope
    };
    let from_sk = signing_key(from_index)?;
    let to_sk = signing_key(to_index)?;
    viso_core::delegation::sign_delegation(&from_sk, &to_sk, scope, time_ms)
}

fn signing_key(index: u32) -> Result<SigningKey, String> {
    seed()
        .map(|s| identity_signing_key(&s, index))
        .ok_or_else(|| "seed not loaded".to_string())
}

/// How long to wait for the delegate's Stored ack. The node answers
/// delegate requests locally, so honest failures surface fast.
const KV_ACK_TIMEOUT_MS: u32 = 10_000;
/// How long to wait for a contract Put/Update confirmation.
const CONTRACT_ACK_TIMEOUT_MS: u32 = 30_000;

/// Poll until `done()` or timeout. The protocol has no request ids, so
/// "done" is a caller-chosen observation (an ack counter passing its
/// pre-send baseline, or state reflecting the write).
async fn wait_until(mut done: impl FnMut() -> bool, timeout_ms: u32, what: &str) -> Result<(), String> {
    // Wall clock, not a tick count: background tabs throttle timers to 1/s
    // or worse, which stretched a 30s timeout to minutes.
    let deadline = keys::now_ms() + timeout_ms as u64;
    loop {
        if done() {
            return Ok(());
        }
        if keys::now_ms() >= deadline {
            break;
        }
        crate::sleep_ms(100).await;
    }
    Err(format!("{what} was not confirmed — nothing was changed remotely. Reload and try again."))
}

/// Store a delegate value and wait for its Stored ack. Send success only
/// means the frame left the browser; a swallowed delegate error would
/// otherwise masquerade as persistence.
async fn kv_store_confirmed(key: &str, value: Vec<u8>) -> Result<(), String> {
    let baseline = api::kv_acks(key);
    api::kv_request(WhoiamDelegateRequest::Store {
        key: key.into(),
        value: ByteBuf::from(value),
    })
    .await?;
    wait_until(
        || api::kv_acks(key) > baseline,
        KV_ACK_TIMEOUT_MS,
        &format!("storing {key:?} in the key store"),
    )
    .await
}

/// PUT an empty contract and wait for the node's PutResponse. Same reason
/// as `kv_store_confirmed`: a resolved `send()` is not an accepted write.
async fn put_identity_confirmed(pk: &VerifyingKey, what: &str) -> Result<(), String> {
    let baseline = api::contract_acks(pk);
    let pkb = pk.to_bytes();
    let held = |pkb: &[u8; 32]| IDENTITY_STATES.peek().get(pkb).is_some_and(|e| e.is_some());
    let had_state = held(&pkb);
    api::put_identity(pk, &IdentityStateV1::default()).await?;
    wait_until(
        // Subscription echo counts too: the node can apply the PUT and
        // notify us without the PutResponse ever arriving.
        || api::contract_acks(pk) > baseline || (!had_state && held(&pkb)),
        CONTRACT_ACK_TIMEOUT_MS,
        what,
    )
    .await
}

/// Persist meta, then mirror it locally — only after the delegate confirms,
/// so the UI never shows identities the store doesn't hold.
async fn store_meta(meta: &IdentityMeta) -> Result<(), String> {
    kv_store_confirmed(KEY_META, viso_core::to_cbor(meta)?).await?;
    *META.write() = meta.clone();
    Ok(())
}

/// First run: generate the master seed and persist it in the delegate.
/// SEED_LOADED flips only after the Stored ack — an optimistic write here
/// would both fake onboarding on a failed store AND disarm the
/// empty-delegate-response detector (it only fires while the seed is
/// unloaded).
pub async fn create_seed() -> Result<(), String> {
    use rand::RngCore;
    let mut s = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut s);
    kv_store_confirmed(KEY_SEED, s.to_vec()).await?;
    *SEED_LOADED.write() = Some(Some(s));
    store_meta(&IdentityMeta::default()).await
}

/// Parse a backup: 64 hex chars or a BIP39 24-word phrase.
pub fn parse_backup(input: &str) -> Result<[u8; 32], String> {
    let trimmed = input.trim();
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() == 64 && compact.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(compact.to_lowercase().as_bytes())
            .map_err(|e| e.to_string())?;
        return <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "not 32 bytes".into());
    }
    let mnemonic = bip39::Mnemonic::parse_normalized(&trimmed.to_lowercase())
        .map_err(|e| format!("not hex and not a valid recovery phrase: {e}"))?;
    let (entropy, len) = mnemonic.to_entropy_array();
    <[u8; 32]>::try_from(&entropy[..len]).map_err(|_| "phrase must encode 32 bytes (24 words)".into())
}

/// The backup file contents for a seed. Pure so the round-trip with
/// [`parse_backup`] is testable without a browser.
pub fn backup_text_for(s: &[u8; 32]) -> Result<String, String> {
    let hex = data_encoding::HEXLOWER.encode(s);
    let words = bip39::Mnemonic::from_entropy(s).map_err(|e| e.to_string())?;
    Ok(format!(
        "viso master seed — KEEP THIS SECRET, KEEP THIS SAFE\n\
         Anyone with this seed controls every persona derived from it,\n\
         including ones you create in the future.\n\n\
         hex:\n{hex}\n\nrecovery phrase (24 words):\n{words}\n"
    ))
}

/// The backup file contents for the current seed.
pub fn backup_text() -> Result<String, String> {
    backup_text_for(&seed().ok_or("seed not loaded")?)
}

/// Restore: store the seed, then probe derived addresses for existing
/// identities. Probing GETs indices 0..PROBE_LIMIT and simply waits a fixed
/// window for states to arrive; anything found lands in meta.
/// ponytail: fixed 8s window + 16-index cap instead of true gap detection —
/// add response-driven probing if identities beyond 16 become real.
pub async fn restore_seed(input: String) -> Result<(), String> {
    restore_seed_opts(input, false).await
}

pub async fn restore_seed_opts(input: String, ensure_index_zero: bool) -> Result<(), String> {
    const PROBE_LIMIT: u32 = 16;
    let s = parse_backup(&input)?;
    kv_store_confirmed(KEY_SEED, s.to_vec()).await?;
    *SEED_LOADED.write() = Some(Some(s));

    let mut send_failures = 0u32;
    for index in 0..PROBE_LIMIT {
        let pk = identity_signing_key(&s, index).verifying_key();
        if let Err(e) = api::fetch_identity(&pk).await {
            api::log(&format!("restore probe {index} failed to send: {e}"));
            send_failures += 1;
        }
    }
    // Every probe failing to SEND is not "searched and found nothing" —
    // it's "couldn't search". Empty-meta success here would read as a bad
    // backup phrase and invite recreating identity 0 over a live one.
    if send_failures == PROBE_LIMIT {
        return Err("couldn't reach the network to search for your personas — reload and try again".into());
    }
    crate::sleep_ms(8000).await;

    let mut meta = IdentityMeta::default();
    {
        let states = IDENTITY_STATES.read();
        for index in 0..PROBE_LIMIT {
            let pk = identity_signing_key(&s, index).verifying_key();
            if let Some(Some(state)) = states.get(&pk.to_bytes()) {
                if state.destroyed.is_none() {
                    meta.identities.push(IdentityEntry {
                        index,
                        label: format!("persona {index}"),
                        hidden: false,
                    });
                }
                // Destroyed identities stay out of the list but still push
                // the watermark: their indices are retired forever.
                meta.next_index = meta.next_index.max(index + 1);
            }
        }
    }
    if ensure_index_zero && !meta.identities.iter().any(|e| e.index == 0) {
        let index0_destroyed = {
            let pk0 = identity_signing_key(&s, 0).verifying_key();
            IDENTITY_STATES
                .read()
                .get(&pk0.to_bytes())
                .and_then(|e| e.as_ref())
                .is_some_and(|st| st.destroyed.is_some())
        };
        if !index0_destroyed {
            let pk = identity_signing_key(&s, 0).verifying_key();
            let _ = api::put_identity(&pk, &IdentityStateV1::default()).await;
            IDENTITY_STATES
                .write()
                .insert(pk.to_bytes(), Some(IdentityStateV1::default()));
            meta.identities.push(IdentityEntry {
                index: 0,
                label: "persona 0".into(),
                hidden: false,
            });
            meta.identities.sort_by_key(|e| e.index);
            meta.next_index = meta.next_index.max(1);
        } else if meta.identities.is_empty() {
            let fresh_index = meta.alloc_index();
            let pk = identity_signing_key(&s, fresh_index).verifying_key();
            let _ = api::put_identity(&pk, &IdentityStateV1::default()).await;
            IDENTITY_STATES
                .write()
                .insert(pk.to_bytes(), Some(IdentityStateV1::default()));
            meta.identities.push(IdentityEntry {
                index: fresh_index,
                label: format!("persona {fresh_index}"),
                hidden: false,
            });
            meta.identities.sort_by_key(|e| e.index);
            meta.next_index = meta.next_index.max(fresh_index + 1);
        }
    }
    store_meta(&meta).await
}

/// Returns `true` if the fetched contract state for `index` carries a signed
/// permanent destruction marker.
pub fn is_persona_destroyed(index: u32) -> bool {
    let Some(pk) = identity_pubkey(index) else {
        return false;
    };
    IDENTITY_STATES
        .read()
        .get(&pk.to_bytes())
        .and_then(|e| e.as_ref())
        .is_some_and(|s| s.destroyed.is_some())
}

/// Returns `true` if this persona is locally hidden from the grid.
pub fn is_persona_hidden(index: u32) -> bool {
    META.read().identities.iter().any(|e| e.index == index && e.hidden)
}

/// Hide or unhide a persona on this device only — Freenet state is untouched.
pub async fn set_persona_hidden(index: u32, hidden: bool) -> Result<(), String> {
    let mut meta = META.read().clone();
    let Some(entry) = meta.identities.iter_mut().find(|e| e.index == index) else {
        return Err(format!("no local persona at index {index}"));
    };
    entry.hidden = hidden;
    store_meta(&meta).await
}

/// Remove a destroyed (unusable) persona and its temporary PoH secrets from this
/// device's local metadata list without modifying Freenet state.
pub async fn forget_destroyed_persona(index: u32) -> Result<(), String> {
    let mut meta = META.read().clone();
    meta.identities.retain(|e| e.index != index);
    meta.next_index = meta.next_index.max(index + 1);
    store_meta(&meta).await?;
    for prov in ["github", "google"] {
        for key in [
            poh_pending_key_for(index, prov),
            poh_staged_key_for(index, prov),
            poh_backup_key_for(index, prov),
        ] {
            let _ = api::kv_request(WhoiamDelegateRequest::Delete { key }).await;
        }
        POH_PENDING.write().remove(&(index, prov.to_string()));
        POH_STAGED.write().remove(&(index, prov.to_string()));
        POH_BACKUP.write().remove(&(index, prov.to_string()));
    }
    Ok(())
}

/// Create a fresh persona at the next unused index (preserving `label`) and
/// forget the destroyed one at `old_index` from this device.
pub async fn replace_destroyed_persona(old_index: u32, label: String) -> Result<u32, String> {
    let new_index = create_identity(label).await?;
    forget_destroyed_persona(old_index).await?;
    Ok(new_index)
}

/// Manually re-attach one index restore probing missed (e.g. the contract
/// rotted off the network). Re-PUTs an empty state to revive the address.
pub async fn readd_index(index: u32) -> Result<(), String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let mut meta = META.read().clone();
    if meta.identities.iter().any(|e| e.index == index) {
        return Err(format!("index {index} is already attached"));
    }
    put_identity_confirmed(&pk, "reviving the persona contract").await?;
    IDENTITY_STATES
        .write()
        .insert(pk.to_bytes(), Some(IdentityStateV1::default()));
    meta.identities.push(IdentityEntry {
        index,
        label: format!("persona {index}"),
        hidden: false,
    });
    meta.identities.sort_by_key(|e| e.index);
    meta.next_index = meta.next_index.max(index + 1);
    store_meta(&meta).await
}

/// Create the next identity: allocate from the monotonic watermark (a
/// destroyed identity's index must never be reused — the rederived key
/// would inherit its permanently-destroyed contract), PUT its (empty)
/// contract, and record it in meta only after the node confirms the Put.
pub async fn create_identity(label: String) -> Result<u32, String> {
    let mut meta = META.read().clone();
    let index = meta.alloc_index();
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    put_identity_confirmed(&pk, "creating the persona contract").await?;
    // Confirmed by the PutResponse — this entry is no longer speculative.
    IDENTITY_STATES
        .write()
        .insert(pk.to_bytes(), Some(IdentityStateV1::default()));
    let label = if label.trim().is_empty() {
        format!("persona {index}")
    } else {
        label.trim().to_string()
    };
    meta.identities.push(IdentityEntry { index, label, hidden: false });
    meta.next_index = index + 1;
    store_meta(&meta).await?;
    Ok(index)
}

pub async fn rename_identity(index: u32, label: String) -> Result<(), String> {
    let mut meta = META.read().clone();
    let entry = meta
        .identities
        .iter_mut()
        .find(|e| e.index == index)
        .ok_or("no such persona")?;
    entry.label = label.trim().to_string();
    store_meta(&meta).await
}

/// Sign one slot, push it, and wait for confirmation: either an
/// UpdateResponse ack or the subscription echo landing the slot in local
/// state (dispatch merges notifications for tracked contracts). No
/// optimistic apply — "published ✓" must mean the node accepted it.
async fn publish_slot(index: u32, name: &str, bytes: Vec<u8>) -> Result<(), String> {
    if is_persona_destroyed(index) {
        return Err("this persona was permanently destroyed on Freenet and cannot be updated".into());
    }
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let time_ms = keys::now_ms();
    let slot = sign_slot(&sk, name, time_ms, bytes);
    let mut delta = IdentityStateV1::default();
    delta.slots.insert(name.to_string(), slot);
    let baseline = api::contract_acks(&pk);
    let contract_id = keys::identity_key(&pk).id().to_string();
    let started_ms = keys::now_ms();
    api::update_identity(&pk, &delta).await?;
    let slot_name = name.to_string();
    let pkb = pk.to_bytes();
    let cid_check = contract_id.clone();
    wait_until(
        move || {
            if api::contract_acks(&pk) > baseline {
                return true;
            }
            if IDENTITY_STATES
                .peek()
                .get(&pkb)
                .and_then(|e| e.as_ref())
                .and_then(|s| s.slots.get(&slot_name))
                .is_some_and(|s| s.time_ms >= time_ms)
            {
                return true;
            }
            LAST_CONTRACT_ERR
                .peek()
                .as_ref()
                .is_some_and(|(ts, msg)| *ts >= started_ms && msg.contains(&cid_check))
        },
        CONTRACT_ACK_TIMEOUT_MS,
        "publishing",
    )
    .await?;
    if let Some((ts, msg)) = LAST_CONTRACT_ERR.peek().as_ref() {
        if *ts >= started_ms && msg.contains(&contract_id) {
            if msg.contains("identity destroyed") {
                // Re-fetch so local state mirrors the destruction marker.
                let _ = api::fetch_identity(&pk).await;
                return Err(
                    "this persona is permanently destroyed on Freenet and cannot be updated".into(),
                );
            }
            return Err(msg.clone());
        }
    }
    // Confirmed: mirror locally (idempotent if the echo already merged it).
    api::merge_identity(&pk, &delta)
}

pub async fn save_profile(index: u32, name: String, bio: String) -> Result<(), String> {
    let profile = ProfileV1 {
        name: name.trim().to_string(),
        bio: bio.trim().to_string(),
    };
    check_profile(&profile)?;
    publish_slot(index, SLOT_PROFILE, viso_core::to_cbor(&profile)?).await
}

pub async fn publish_avatar(index: u32, png: Vec<u8>) -> Result<(), String> {
    check_avatar_bytes(&png)?;
    publish_slot(index, SLOT_AVATAR, png).await
}

pub async fn remove_avatar(index: u32) -> Result<(), String> {
    publish_slot(index, SLOT_AVATAR, vec![]).await
}

/// Verified proof-of-commitment bits of this persona's published `ante`
/// slot, if any.
pub fn persona_level(index: u32) -> Option<u32> {
    let pk = identity_pubkey(index)?;
    let states = IDENTITY_STATES.read();
    let slot = states.get(&pk.to_bytes())?.as_ref()?.slots.get(viso_ante::SLOT_ANTE)?;
    viso_ante::verify_slot(&pk, &slot.bytes).ok()
}

/// Verified ghostkey badge of this persona's published `ghostkey` slot.
pub fn persona_ghostkey(index: u32) -> Option<viso_core::ghostkey::GhostkeyBadge> {
    let pk = identity_pubkey(index)?;
    let states = IDENTITY_STATES.read();
    let slot = states.get(&pk.to_bytes())?.as_ref()?.slots.get(viso_core::resources::SLOT_GHOSTKEY)?;
    viso_core::ghostkey::verify_badge(&slot.bytes, &pk.to_bytes()).ok()
}

/// Publish a ghostkey proof (base64 of the delegate's signed bundle) after
/// verifying it locally; an invalid bundle never reaches the network.
pub async fn attach_ghostkey(index: u32, bundle_b64: String) -> Result<(), String> {
    use base64::Engine;
    let pk = identity_pubkey(index).ok_or("no identity")?;
    let bundle = base64::engine::general_purpose::STANDARD
        .decode(bundle_b64.trim())
        .map_err(|e| format!("not base64: {e}"))?;
    viso_core::ghostkey::verify_badge(&bundle, &pk.to_bytes())?;
    publish_slot(index, viso_core::resources::SLOT_GHOSTKEY, bundle).await
}

/// Ask the user's ghostkeys delegate to sign the binding for this persona
/// (it prompts for access itself), then publish the verified result.
pub async fn request_ghostkey_badge(index: u32) -> Result<(), String> {
    use ghostkey_common::{GhostkeyRequest, GhostkeyResponse};
    let pk = identity_pubkey(index).ok_or("no identity")?;
    *api::GHOSTKEY_REPLY.write() = None;
    api::ghostkey_request(GhostkeyRequest::SignWithDefault {
        message: viso_core::ghostkey::binding_payload(&pk.to_bytes()),
    })
    .await?;
    // The user may have to approve a prompt, so wait generously.
    wait_until(|| api::GHOSTKEY_REPLY.peek().is_some(), 120_000, "ghostkey signature").await?;
    match api::GHOSTKEY_REPLY.write().take() {
        Some(GhostkeyResponse::SignResult { scoped_payload, signature, certificate_pem }) => {
            let bundle = viso_core::ghostkey::bundle_from_sign_result(scoped_payload, signature, certificate_pem)?;
            viso_core::ghostkey::verify_badge(&bundle, &pk.to_bytes())?;
            publish_slot(index, viso_core::resources::SLOT_GHOSTKEY, bundle).await
        }
        Some(GhostkeyResponse::NoIdentityAvailable) => {
            Err("could not find a ghostkey on this node".into())
        }
        Some(GhostkeyResponse::PermissionDenied { .. } | GhostkeyResponse::AccessDenied { .. }) => {
            Err("ghostkey access denied".into())
        }
        Some(GhostkeyResponse::Error { message }) => Err(message),
        _ => Err("unexpected ghostkeys reply".into()),
    }
}

pub async fn remove_ghostkey(index: u32) -> Result<(), String> {
    publish_slot(index, viso_core::resources::SLOT_GHOSTKEY, vec![]).await
}

pub fn poh_pending_key_for(index: u32, provider: &str) -> String {
    if provider == "github" {
        format!("pohpending:{index}")
    } else {
        format!("pohpending:{provider}:{index}")
    }
}

pub fn poh_staged_key_for(index: u32, provider: &str) -> String {
    if provider == "github" {
        format!("pohstaged:{index}")
    } else {
        format!("pohstaged:{provider}:{index}")
    }
}

pub fn poh_backup_key_for(index: u32, provider: &str) -> String {
    format!("pohbackup:{provider}:{index}")
}

/// Verified Proof-of-Personhood badge (`poh:<provider>`) for this persona, if published.
/// Checks pinned production `POH_ISSUERS`, or an optional local/custom SPKI
/// supplied for testing.
pub fn persona_poh(
    index: u32,
    provider: &str,
    custom_issuer: Option<(&str, &[u8])>,
) -> Option<(viso_core::poh::PohBadge, bool)> {
    let pk = identity_pubkey(index)?;
    let states = IDENTITY_STATES.read();
    let slot_name = viso_core::resources::poh_slot(provider);
    let slot = states
        .get(&pk.to_bytes())?
        .as_ref()?
        .slots
        .get(&slot_name)?;
    if slot.bytes.is_empty() {
        return None;
    }
    if let Ok(badge) = viso_core::poh::verify_attestation(&slot.bytes, &pk.to_bytes()) {
        return Some((badge, true));
    }
    if let Some((key_id, spki_der)) = custom_issuer {
        let parts: Vec<&str> = key_id.split(':').collect();
        if parts.len() == 3 {
            let issuers = [viso_core::poh::PohIssuer {
                key_id,
                provider: parts[0],
                tier: parts[1],
                epoch: parts[2],
                spki_der,
            }];
            if let Ok(badge) =
                viso_core::poh::verify_attestation_with(&slot.bytes, &pk.to_bytes(), &issuers)
            {
                return Some((badge, false));
            }
        }
    }
    None
}

pub fn persona_poh_github(
    index: u32,
    custom_issuer: Option<(&str, &[u8])>,
) -> Option<(viso_core::poh::PohBadge, bool)> {
    persona_poh(index, "github", custom_issuer)
}

/// Request any pending PoH blinding state, staged attestation, or local backup for `index`
/// across supported providers from the node delegate.
pub async fn load_poh_pending(index: u32) {
    for prov in ["github", "google"] {
        for key in [
            poh_pending_key_for(index, prov),
            poh_staged_key_for(index, prov),
            poh_backup_key_for(index, prov),
        ] {
            let _ = api::kv_request(WhoiamDelegateRequest::Get { key }).await;
        }
    }
}

/// Discard the active PoH blinding secret for `(index, provider)` so a fresh OAuth flow
/// can be started intentionally.
pub async fn clear_poh_pending(index: u32, provider: &str) -> Result<(), String> {
    api::kv_request(WhoiamDelegateRequest::Delete {
        key: poh_pending_key_for(index, provider),
    })
    .await?;
    POH_PENDING.write().remove(&(index, provider.to_string()));
    Ok(())
}

/// Build the blinded PoH OAuth URL for `(index, provider)`, persist `PendingBlindState`
/// in `viso-delegate` so the blinding secret survives reloads, and return the URL.
pub async fn start_poh(
    index: u32,
    provider: &str,
    gatekeeper_url: &str,
    key_id: &str,
    spki_der: &[u8],
) -> Result<String, String> {
    let pk = identity_pubkey(index).ok_or("no identity")?;
    let parts: Vec<&str> = key_id.trim().split(':').collect();
    if parts.len() != 3 || parts[0] != provider {
        return Err(format!("key_id must have format {provider}:<tier>:<epoch>"));
    }
    let issuer = viso_core::poh::PohIssuer {
        key_id: key_id.trim(),
        provider: parts[0],
        tier: parts[1],
        epoch: parts[2],
        spki_der,
    };
    let (blinded_b64, pending) =
        viso_core::poh::blind_request(&mut rand::rngs::OsRng, &issuer, &pk.to_bytes())?;
    let cbor = viso_core::to_cbor(&pending)?;
    kv_store_confirmed(&poh_pending_key_for(index, provider), cbor).await?;
    POH_PENDING.write().insert((index, provider.to_string()), pending);

    let base = gatekeeper_url.trim().trim_end_matches('/');
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err("gatekeeper URL must start with http:// or https://".into());
    }
    Ok(format!(
        "{base}/{provider}?key_id={}&blinded={blinded_b64}",
        url_encode(issuer.key_id)
    ))
}

/// Unblind a `VISO-POH-V1:` token using the saved `PendingBlindState`, verify
/// against `POH_ISSUERS` (or `custom_issuer` if provided), persist the verified
/// attestation locally in `viso-delegate` before attempting Freenet publish,
/// publish the `poh:<provider>` slot, and clean up temporary delegate state.
pub async fn attach_poh(
    index: u32,
    provider: &str,
    token: String,
    custom_issuer: Option<(&str, &[u8])>,
) -> Result<(), String> {
    let prov_key = (index, provider.to_string());
    let pending = POH_PENDING
        .peek()
        .get(&prov_key)
        .cloned()
        .ok_or_else(|| "no pending verification found — click Connect in Step 1 first".to_string())?;
    let mut issuers: Vec<viso_core::poh::PohIssuer<'_>> = viso_core::poh::POH_ISSUERS.to_vec();
    if let Some((key_id, spki_der)) = custom_issuer {
        let parts: Vec<&str> = key_id.trim().split(':').collect();
        if parts.len() == 3 {
            issuers.push(viso_core::poh::PohIssuer {
                key_id: key_id.trim(),
                provider: parts[0],
                tier: parts[1],
                epoch: parts[2],
                spki_der,
            });
        }
    }
    let slot_bytes = viso_core::poh::finalize_attestation(&token, &pending, &issuers)?;
    kv_store_confirmed(&poh_staged_key_for(index, provider), slot_bytes.clone()).await?;
    POH_STAGED.write().insert(prov_key.clone(), slot_bytes.clone());
    // Also keep a persistent local backup in viso-delegate so "Remove badge" can be undone without re-minting in the same epoch.
    let _ = api::kv_request(WhoiamDelegateRequest::Store {
        key: poh_backup_key_for(index, provider),
        value: ByteBuf::from(slot_bytes.clone()),
    })
    .await;
    POH_BACKUP.write().insert(prov_key.clone(), slot_bytes.clone());
    let _ = api::kv_request(WhoiamDelegateRequest::Delete {
        key: poh_pending_key_for(index, provider),
    })
    .await;
    POH_PENDING.write().remove(&prov_key);

    let slot_name = viso_core::resources::poh_slot(provider);
    publish_slot(index, &slot_name, slot_bytes).await?;
    let _ = api::kv_request(WhoiamDelegateRequest::Delete {
        key: poh_staged_key_for(index, provider),
    })
    .await;
    POH_STAGED.write().remove(&prov_key);
    Ok(())
}

/// Retry publishing a locally-staged, already-verified `poh:<provider>` slot to Freenet.
pub async fn retry_publish_poh(index: u32, provider: &str) -> Result<(), String> {
    let prov_key = (index, provider.to_string());
    let slot_bytes = POH_STAGED
        .peek()
        .get(&prov_key)
        .cloned()
        .ok_or_else(|| "no staged PoH badge found".to_string())?;
    let _ = api::kv_request(WhoiamDelegateRequest::Store {
        key: poh_backup_key_for(index, provider),
        value: ByteBuf::from(slot_bytes.clone()),
    })
    .await;
    POH_BACKUP.write().insert(prov_key.clone(), slot_bytes.clone());
    let slot_name = viso_core::resources::poh_slot(provider);
    publish_slot(index, &slot_name, slot_bytes).await?;
    let _ = api::kv_request(WhoiamDelegateRequest::Delete {
        key: poh_staged_key_for(index, provider),
    })
    .await;
    POH_STAGED.write().remove(&prov_key);
    Ok(())
}

/// Discard a locally-staged `poh:<provider>` slot without publishing it.
pub async fn discard_poh_staged(index: u32, provider: &str) -> Result<(), String> {
    api::kv_request(WhoiamDelegateRequest::Delete {
        key: poh_staged_key_for(index, provider),
    })
    .await?;
    POH_STAGED.write().remove(&(index, provider.to_string()));
    Ok(())
}

/// Unpublish `poh:<provider>` from Freenet, first saving a local backup in `viso-delegate`
/// so the user can re-publish it without hitting the gatekeeper's 1-per-epoch nullifier limit.
pub async fn remove_poh(index: u32, provider: &str) -> Result<(), String> {
    let slot_name = viso_core::resources::poh_slot(provider);
    if let Some(pk) = identity_pubkey(index) {
        let existing = IDENTITY_STATES
            .peek()
            .get(&pk.to_bytes())
            .and_then(|s| s.as_ref())
            .and_then(|s| s.slots.get(&slot_name))
            .map(|slot| slot.bytes.clone())
            .filter(|b| !b.is_empty());
        if let Some(bytes) = existing {
            let _ = kv_store_confirmed(&poh_backup_key_for(index, provider), bytes.clone()).await;
            POH_BACKUP.write().insert((index, provider.to_string()), bytes);
        }
    }
    publish_slot(index, &slot_name, vec![]).await
}

/// Re-publish a previously backed-up `poh:<provider>` badge from `viso-delegate`.
pub async fn restore_poh_backup(index: u32, provider: &str) -> Result<(), String> {
    let prov_key = (index, provider.to_string());
    let slot_bytes = POH_BACKUP
        .peek()
        .get(&prov_key)
        .cloned()
        .ok_or_else(|| "no saved badge backup found in key store".to_string())?;
    let slot_name = viso_core::resources::poh_slot(provider);
    publish_slot(index, &slot_name, slot_bytes).await
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Hashes per `grind_step` call; calls repeat until GRIND_SLICE_MS passes.
const GRIND_CHUNK: u64 = 20_000;
/// Grind this long before yielding to the browser event loop. A time slice
/// instead of a fixed count: browsers throttle timers in background tabs
/// (to 1/s, later 1/min), so a small fixed chunk per tick nearly stops there.
const GRIND_SLICE_MS: u64 = 200;

/// Grind a nonce reaching `target_bits` for this persona, in chunks that
/// yield so the UI stays live, then publish it as the `ante` slot.
/// `progress` gets hashes tried so far; `cancelled` is polled per slice;
/// `found` fires once the nonce is found, before the (slower) publish.
/// Refuses to publish a level not above the current one (LWW would
/// otherwise let a cheaper proof replace a dearer one).
pub async fn raise_level(
    index: u32,
    target_bits: u32,
    mut progress: impl FnMut(u64),
    cancelled: impl Fn() -> bool,
    found: impl FnOnce(),
) -> Result<u32, String> {
    let current = persona_level(index).unwrap_or(0);
    if target_bits <= current {
        return Err(format!("already at {current} bits"));
    }
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let mut start = 0u64;
    let nonce = 'grind: loop {
        if cancelled() {
            return Err("cancelled".into());
        }
        let slice_end = keys::now_ms() + GRIND_SLICE_MS;
        while keys::now_ms() < slice_end {
            if let Some(n) = viso_ante::grind_step(&pk, start, GRIND_CHUNK, target_bits) {
                break 'grind n;
            }
            start += GRIND_CHUNK;
        }
        progress(start);
        crate::sleep_ms(0).await;
    };
    found();
    let bits = viso_ante::bits(&pk, nonce);
    publish_slot(index, viso_ante::SLOT_ANTE, viso_ante::make_slot(&sk, nonce, keys::now_ms())).await?;
    Ok(bits)
}

/// Destroy the PUBLIC identity first (signed permanent marker), wait until
/// the node confirms the marker landed, and only then forget it locally —
/// deleting local metadata on an unconfirmed push would leave the public
/// identity alive while the user believes it destroyed. The seed stays;
/// `next_index` (untouched here) retires the index forever.
pub async fn destroy_identity(index: u32) -> Result<(), String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let mut delta = IdentityStateV1::default();
    delta.destroyed = Some(sign_destroy(&sk, keys::now_ms()));
    let baseline = api::contract_acks(&pk);
    api::update_identity(&pk, &delta).await?;
    let pkb = pk.to_bytes();
    wait_until(
        move || {
            if api::contract_acks(&pk) > baseline {
                return true;
            }
            // Subscription echo: the destroyed marker merged into local state.
            IDENTITY_STATES
                .peek()
                .get(&pkb)
                .and_then(|e| e.as_ref())
                .is_some_and(|s| s.destroyed.is_some())
        },
        CONTRACT_ACK_TIMEOUT_MS,
        "destroying the public persona",
    )
    .await
    .map_err(|e| format!("{e} The persona was NOT removed locally."))?;

    let mut meta = META.read().clone();
    meta.identities.retain(|e| e.index != index);
    store_meta(&meta).await?;
    IDENTITY_STATES.write().remove(&pk.to_bytes());
    *VIEW.write() = View::Home;
    Ok(())
}

/// Connect challenge charset: URL-safe unreserved chars only, so callback
/// URLs build by plain concatenation with no re-encoding step to get wrong.
pub fn valid_challenge(c: &str) -> bool {
    (1..=256).contains(&c.len())
        && c.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '~' | '-'))
}

fn callback_url(return_url: &str, params: &str) -> String {
    if let Some((base, hash)) = return_url.split_once('#') {
        let sep = if base.contains('?') { '&' } else { '?' };
        format!("{base}{sep}{params}#{hash}")
    } else {
        let sep = if return_url.contains('?') { '&' } else { '?' };
        format!("{return_url}{sep}{params}")
    }
}

/// The signed approval callback URL: proof that this persona's key consented
/// to identify to `req.origin` for this challenge, at this time.
/// If `req.request_key` is true, Viso derives an app secret deterministically from the persona and app scope,
/// delegates `wd1.<app_pubkey>.<nonce>` in the signed proof, and returns
/// `#esk=<viso_epk_hex>.<ciphertext_hex>`: the secret sealed to `req.client_epk` (see [`seal_app_secret`]).
pub fn connect_ok_url(index: u32, req: &ConnectRequest, time_ms: u64) -> Result<String, String> {
    let sk = signing_key(index)?;
    let pk = sk.verifying_key();
    let hex = |b: &[u8]| data_encoding::HEXLOWER.encode(b);

    let (challenge_to_sign, fragment) = if req.request_key {
        let scope = viso_core::connect::app_scope_for(&req.actual_return_base, req.same_node)
            .ok_or("invalid callback URL for app key")?;
        let sec = viso_core::derive::app_secret(&sk, &scope);
        let app_sk = ed25519_dalek::SigningKey::from_bytes(&sec);
        let app_pk = app_sk.verifying_key();
        let nonce = req.challenge_nonce();
        let ch = format!("wd1.{}.{}", hex(app_pk.as_bytes()), nonce);
        let epk = req.client_epk.ok_or("key=v1 request without epk")?;
        let frag = format!("esk={}", seal_app_secret(&sec, &epk, ch.as_bytes()));
        (ch, Some(frag))
    } else {
        (req.challenge.clone(), None)
    };

    let sig = viso_core::connect::sign_connect(&sk, &req.return_base, &challenge_to_sign, time_ms);
    let mut url = callback_url(
        &req.return_url,
        &format!(
            "viso=ok&pk={}&sig={}&challenge={}&ts={time_ms}",
            hex(pk.as_bytes()),
            hex(&sig.to_bytes()),
            challenge_to_sign
        ),
    );
    if let Some(frag) = fragment {
        if url.contains('#') {
            url.push('&');
            url.push_str(&frag);
        } else {
            url.push('#');
            url.push_str(&frag);
        }
    }
    Ok(url)
}

/// Seal `secret` to the app's X25519 public key using only primitives WebCrypto
/// has (so browser apps need no crypto library): ephemeral-static ECDH,
/// HKDF-SHA256(salt = viso_epk || client_epk, info = [`SEAL_INFO`]) -> AES-256-GCM
/// key, all-zero 12-byte nonce (safe: the key is single-use, the ephemeral key is
/// fresh per call), the signed challenge (`wd1.<app key>.<nonce>`) as AAD, so the box only opens for this sign-in. Returns `<viso_epk_hex>.<ciphertext_hex>`
/// (ciphertext = 32-byte secret + 16-byte tag, the layout WebCrypto decrypts).
fn seal_app_secret(secret: &[u8; 32], client_epk: &[u8; 32], aad: &[u8]) -> String {
    use aes_gcm::{aead::{Aead, Payload}, Aes256Gcm, KeyInit};
    let esk = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let epk = x25519_dalek::PublicKey::from(&esk);
    let shared = esk.diffie_hellman(&x25519_dalek::PublicKey::from(*client_epk));
    let key = seal_key(shared.as_bytes(), epk.as_bytes(), client_epk);
    let ct = Aes256Gcm::new(&key.into())
        .encrypt(&[0u8; 12].into(), Payload { msg: secret.as_slice(), aad })
        .expect("aes-gcm encrypt");
    let hex = |b: &[u8]| data_encoding::HEXLOWER.encode(b);
    format!("{}.{}", hex(epk.as_bytes()), hex(&ct))
}

const SEAL_INFO: &[u8] = b"viso connect v1 app secret";

fn seal_key(shared: &[u8; 32], viso_epk: &[u8; 32], client_epk: &[u8; 32]) -> [u8; 32] {
    let salt = [viso_epk.as_slice(), client_epk.as_slice()].concat();
    let mut key = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared)
        .expand(SEAL_INFO, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

pub fn connect_denied_url(req: &ConnectRequest) -> String {
    callback_url(&req.return_url, "viso=denied")
}

/// Fetch (and subscribe to) every identity in meta — boot and post-restore.
/// The empty re-PUT first is the freebird resume pattern: it creates the
/// contract if it's missing (rotted off the network, or orphaned by a
/// deliberate wasm rotation) and is a merge no-op otherwise, so our own
/// identities self-heal on every boot.
pub async fn fetch_all_identities() {
    let entries = META.read().identities.clone();
    for e in entries {
        if let Some(pk) = identity_pubkey(e.index) {
            if let Err(err) = api::put_identity(&pk, &IdentityStateV1::default()).await {
                api::log(&format!("identity {} re-put failed: {err}", e.index));
            }
            if let Err(err) = api::fetch_identity(&pk).await {
                api::log(&format!("identity {} fetch failed: {err}", e.index));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{backup_text_for, callback_url, parse_backup, valid_challenge};

    const SEED: [u8; 32] = [0x5A; 32];

    #[test]
    fn challenge_nonce_forms() {
        use crate::state::challenge_nonce_of as n;
        assert_eq!((n("abc"), n("wd1.nonce"), n("wd1.key.nonce"), n("")), ("abc".into(), "nonce".into(), "nonce".into(), "auto".into()));
    }

    #[test]
    fn challenge_charset_enforced() {
        assert!(valid_challenge("abc123._~-"));
        assert!(!valid_challenge(""));
        assert!(!valid_challenge(&"x".repeat(257)));
        // Anything that could break URL concatenation or smuggle params.
        for bad in ["a&b", "a=b", "a b", "a#b", "a%41", "a/b", "ü"] {
            assert!(!valid_challenge(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn callback_url_separator() {
        assert_eq!(callback_url("https://x.com/cb", "viso=denied"), "https://x.com/cb?viso=denied");
        assert_eq!(callback_url("https://x.com/cb?a=1", "viso=denied"), "https://x.com/cb?a=1&viso=denied");
        assert_eq!(callback_url("https://x.com/cb#/mine", "viso=denied"), "https://x.com/cb?viso=denied#/mine");
        assert_eq!(callback_url("https://x.com/cb?a=1#/mine", "viso=denied"), "https://x.com/cb?a=1&viso=denied#/mine");
    }

    #[test]
    fn connect_ok_url_derives_key_when_requested() {
        use dioxus::prelude::*;
        fn test_app() -> Element {
            *crate::state::SEED_LOADED.write() = Some(Some(SEED));
            let req = crate::state::ConnectRequest {
                origin: "http://127.0.0.1:7509".into(),
                actual_return_base: "http://127.0.0.1:7509/v1/contract/web/OrtoApp/".into(),
                return_path: "/v1/contract/web/OrtoApp/".into(),
                same_node: true,
                return_base: "http://127.0.0.1:7509/v1/contract/web/OrtoApp/".into(),
                return_url: "http://127.0.0.1:7509/v1/contract/web/OrtoApp/".into(),
                challenge: "1234567890abcdef".into(),
                request_key: true,
                client_epk: Some(*x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([7u8; 32])).as_bytes()),
            };
            let url = super::connect_ok_url(0, &req, 1000).unwrap();
            assert!(url.contains("viso=ok"));
            assert!(url.contains("#esk="));
            assert!(!url.contains("sk="), "plaintext secret must not be in the url");
            assert!(url.contains("challenge=wd1."));

            // Foreign origin spoofing the same path must derive a completely different delegated key
            let foreign_req = crate::state::ConnectRequest {
                origin: "https://evil.example".into(),
                actual_return_base: "https://evil.example/v1/contract/web/OrtoApp/".into(),
                return_path: "/v1/contract/web/OrtoApp/".into(),
                same_node: false,
                return_base: "https://evil.example/v1/contract/web/OrtoApp/".into(),
                return_url: "https://evil.example/v1/contract/web/OrtoApp/".into(),
                challenge: "1234567890abcdef".into(),
                request_key: true,
                client_epk: req.client_epk,
            };
            let foreign_url = super::connect_ok_url(0, &foreign_req, 1000).unwrap();
            let app_pk_of = |u: &str| u.split("challenge=wd1.").nth(1).unwrap().split('.').next().unwrap().to_string();
            assert_ne!(app_pk_of(&url), app_pk_of(&foreign_url));
            VNode::empty()
        }
        let mut dom = VirtualDom::new(test_app);
        dom.rebuild_to_vec();
    }

    #[test]
    fn sealed_secret_round_trips_only_for_the_client() {
        use aes_gcm::{aead::{Aead, Payload}, Aes256Gcm, KeyInit};
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = [0x42u8; 32];
        let client = StaticSecret::from([7u8; 32]);
        let client_pub = *PublicKey::from(&client).as_bytes();
        let sealed = super::seal_app_secret(&secret, &client_pub, b"wd1.aa.bb");
        let (epk_hex, ct_hex) = sealed.split_once('.').unwrap();
        let epk: [u8; 32] = data_encoding::HEXLOWER.decode(epk_hex.as_bytes()).unwrap().try_into().unwrap();
        let ct = data_encoding::HEXLOWER.decode(ct_hex.as_bytes()).unwrap();
        let open = |sk: &StaticSecret, aad: &[u8]| {
            let shared = sk.diffie_hellman(&PublicKey::from(epk));
            let key = super::seal_key(shared.as_bytes(), &epk, &client_pub);
            Aes256Gcm::new(&key.into()).decrypt(&[0u8; 12].into(), Payload { msg: ct.as_slice(), aad })
        };
        assert_eq!(open(&client, b"wd1.aa.bb").unwrap(), secret);
        assert!(open(&StaticSecret::from([8u8; 32]), b"wd1.aa.bb").is_err());
        assert!(open(&client, b"wd1.aa.cc").is_err(), "a different challenge must not open the box");
    }

    /// Fixed vector for client implementers (see docs/dapp-integration.md).
    #[test]
    fn seal_key_known_answer() {
        let k = super::seal_key(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert_eq!(data_encoding::HEXLOWER.encode(&k), "19d4be8a0f28c60650e355bd8db0549ca0db302e5330c0c7353725981de879d2");
    }

    #[test]
    fn persona_secret_bytes_derives_correct_key() {
        use dioxus::prelude::*;
        fn test_app() -> Element {
            *crate::state::SEED_LOADED.write() = Some(Some(SEED));
            let sk_bytes = super::persona_secret_bytes(0).unwrap();
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
            assert_eq!(sk.verifying_key(), super::identity_pubkey(0).unwrap());
            VNode::empty()
        }
        let mut dom = VirtualDom::new(test_app);
        dom.rebuild_to_vec();
    }

    #[test]
    fn delegation_proof_signs_both_keys() {
        use dioxus::prelude::*;
        fn test_app() -> Element {
            *crate::state::SEED_LOADED.write() = Some(Some(SEED));
            let proof = super::sign_delegation_proof(0, 1, "  ", 1_794_781_500_000).unwrap();
            let verified = viso_core::delegation::verify_delegation(&proof).unwrap();
            assert_eq!(verified.from, super::identity_pubkey(0).unwrap());
            assert_eq!(verified.to, super::identity_pubkey(1).unwrap());
            assert_eq!(verified.scope, "*");
            assert!(super::sign_delegation_proof(0, 0, "*", 1000).is_err());
            VNode::empty()
        }
        let mut dom = VirtualDom::new(test_app);
        dom.rebuild_to_vec();
    }

    /// The pubkey cache must follow the seed: a stale key after an import
    /// would sign-in and publish as the previous seed's persona.
    #[test]
    fn identity_pubkey_cache_follows_seed() {
        use dioxus::prelude::*;
        use viso_core::derive::identity_signing_key;
        fn test_app() -> Element {
            for s in [SEED, [0x11; 32], SEED] {
                *crate::state::SEED_LOADED.write() = Some(Some(s));
                for i in [0, 1, 0] {
                    assert_eq!(
                        super::identity_pubkey(i).unwrap(),
                        identity_signing_key(&s, i).verifying_key()
                    );
                }
            }
            VNode::empty()
        }
        let mut dom = VirtualDom::new(test_app);
        dom.rebuild_to_vec();
    }

    /// The whole point of a backup: both encodings in the file must parse
    /// back to the exact seed. This is the restore path's data-loss guard.
    #[test]
    fn backup_round_trips_both_encodings() {
        let text = backup_text_for(&SEED).unwrap();
        let hex_line = text.lines().find(|l| l.len() == 64).unwrap();
        let words_line = text.lines().last().unwrap();
        assert_eq!(words_line.split_whitespace().count(), 24);
        assert_eq!(parse_backup(hex_line).unwrap(), SEED);
        assert_eq!(parse_backup(words_line).unwrap(), SEED);
    }

    #[test]
    fn hex_forgiving_of_case_and_whitespace() {
        let hex = data_encoding::HEXLOWER.encode(&SEED);
        assert_eq!(parse_backup(&hex.to_uppercase()).unwrap(), SEED);
        // As pasted from the backup file with a stray newline/indent.
        assert_eq!(parse_backup(&format!("  {}\n", hex)).unwrap(), SEED);
        // Whitespace INSIDE the hex (line-wrapped paste).
        let (a, b) = hex.split_at(32);
        assert_eq!(parse_backup(&format!("{a}\n{b}")).unwrap(), SEED);
    }

    #[test]
    fn wrong_sizes_rejected() {
        // 12-word phrase = 16-byte entropy: valid BIP39, wrong seed size.
        let twelve = bip39::Mnemonic::from_entropy(&[7u8; 16]).unwrap().to_string();
        assert!(parse_backup(&twelve).is_err());
        // Near-miss hex lengths fall through to the mnemonic parser and fail.
        let hex = data_encoding::HEXLOWER.encode(&SEED);
        assert!(parse_backup(&hex[..63]).is_err());
        assert!(parse_backup(&format!("{hex}0")).is_err());
        assert!(parse_backup("definitely not a backup").is_err());
    }
}
