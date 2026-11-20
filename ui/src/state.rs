//! Global UI state (Dioxus signals).

use std::collections::BTreeMap;

use dioxus::prelude::*;
use freenet_stdlib::client_api::WebApi;
use viso_core::delegate_api::IdentityMeta;
use viso_core::poh::PendingBlindState;
use viso_core::state::IdentityStateV1;

#[derive(Clone, PartialEq, Debug, Default)]
pub enum SyncStatus {
    #[default]
    Connecting,
    Connected,
    Error(String),
}

pub static WEB_API: GlobalSignal<Option<WebApi>> = Signal::global(|| None);
pub static SYNC_STATUS: GlobalSignal<SyncStatus> = Signal::global(SyncStatus::default);

/// Delegate's answer for the master seed:
/// None = not answered yet; Some(None) = no seed stored (onboard);
/// Some(Some(seed)) = ready.
pub static SEED_LOADED: GlobalSignal<Option<Option<[u8; 32]>>> = Signal::global(|| None);

/// Identity metadata (indices + labels), delegate-persisted.
pub static META: GlobalSignal<IdentityMeta> = Signal::global(IdentityMeta::default);
/// The delegate answered the meta Get (even if empty) — gate on this so we
/// never overwrite stored meta with an empty default.
pub static META_LOADED: GlobalSignal<bool> = Signal::global(|| false);

/// Published contract state per identity pubkey. None = requested, not yet
/// arrived (or the contract doesn't exist on the network yet).
pub static IDENTITY_STATES: GlobalSignal<BTreeMap<[u8; 32], Option<IdentityStateV1>>> =
    Signal::global(BTreeMap::new);

/// Pending Blind-RSA PoH blinding secrets persisted in `viso-delegate`
/// (`pohpending:<index>` or `pohpending:<provider>:<index>`) across the external OAuth round-trip.
pub static POH_PENDING: GlobalSignal<BTreeMap<(u32, String), PendingBlindState>> =
    Signal::global(BTreeMap::new);

/// Verified, unblinded `poh:<provider>` slot bytes staged in `viso-delegate`
/// (`pohstaged:<index>` or `pohstaged:<provider>:<index>`) so a Freenet publish timeout never loses an issued badge.
pub static POH_STAGED: GlobalSignal<BTreeMap<(u32, String), Vec<u8>>> =
    Signal::global(BTreeMap::new);

/// Most recent node-level contract request error `(timestamp_ms, message)` so
/// failed `Put`/`Update` calls fail fast with the real reason instead of
/// hanging until `CONTRACT_ACK_TIMEOUT_MS`.
pub static LAST_CONTRACT_ERR: GlobalSignal<Option<(u64, String)>> = Signal::global(|| None);

/// The seed answer will never arrive (watchdog timeout or the node is
/// swallowing delegate errors). Drives an explanatory error screen instead
/// of an eternal spinner.
pub static KEY_STORE_UNREACHABLE: GlobalSignal<bool> = Signal::global(|| false);

/// A validated `?connect=v1` bounce-through request from an external site
/// (parsed from the iframe URL at boot). While present, the app shows the
/// persona picker instead of the normal views.
#[derive(Clone, PartialEq, Debug)]
pub struct ConnectRequest {
    /// Origin of the callback URL — what the user is shown.
    pub origin: String,
    /// Actual `origin + pathname` of the callback URL before any canonical host swap.
    pub actual_return_base: String,
    /// Pathname of the callback URL — shown in the consent prompt alongside origin.
    pub return_path: String,
    /// True only when the callback origin matches Viso's own Freenet node origin.
    pub same_node: bool,
    /// origin+path of the callback URL (or canonical swap for same-node dApps) — what the proof is bound to.
    pub return_base: String,
    pub return_url: String,
    pub challenge: String,
    /// True if the app requested a deterministic derived app secret (`key=v1`).
    pub request_key: bool,
    /// The app's ephemeral X25519 public key (`epk`); the app secret is sealed
    /// to it so it never appears in the URL in the clear. Required with `key=v1`.
    pub client_epk: Option<[u8; 32]>,
}

/// The nonce of a challenge: the last `.`-separated part of `[wd1.<key>.]<nonce>`, or `auto` when empty.
pub fn challenge_nonce_of(challenge: &str) -> String {
    if challenge.is_empty() {
        return "auto".to_string();
    }
    match challenge.split_once('.') {
        Some((_, rest)) => rest.split_once('.').map_or(rest, |(_, nonce)| nonce).to_string(),
        None => challenge.to_string(),
    }
}

impl ConnectRequest {
    pub fn challenge_nonce(&self) -> String {
        challenge_nonce_of(&self.challenge)
    }
}

pub static CONNECT: GlobalSignal<Option<ConnectRequest>> =
    Signal::global(crate::views::connect_request_from_location);

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum View {
    #[default]
    Home,
    Identity(u32),
    Backup,
    Import,
}

pub static VIEW: GlobalSignal<View> = Signal::global(View::default);

pub fn seed() -> Option<[u8; 32]> {
    SEED_LOADED.read().clone().flatten()
}
