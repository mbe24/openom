#![doc = include_str!("../README.md")]

use serde::{Deserialize, Serialize};

/// Which keyring engine backs a tree. Bound immutably at provision and recorded in signed/pinned material
/// (so a hostile store can't flip a tree's interpretation); the app selects the concrete engine on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngineKind {
    Chain,
    Dag,
}

impl EngineKind {
    /// The canonical config/wire tag for this engine — the single source of truth every host boundary maps
    /// through (the wasm veneer's `engine` argument, the Tauri `OPENOM_KEYRING_ENGINE` override, the web
    /// `KEYRING_ENGINE` constant), so the tag strings can't drift apart. Paired with [`std::str::FromStr`].
    pub fn as_tag(self) -> &'static str {
        match self {
            EngineKind::Chain => "chain",
            EngineKind::Dag => "dag",
        }
    }
}

impl std::str::FromStr for EngineKind {
    type Err = UnknownEngine;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chain" => Ok(EngineKind::Chain),
            "dag" => Ok(EngineKind::Dag),
            other => Err(UnknownEngine(other.to_string())),
        }
    }
}

/// A tag string that named no known engine — carries the offending value for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownEngine(pub String);

impl std::fmt::Display for UnknownEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown keyring engine: {}", self.0)
    }
}

impl std::error::Error for UnknownEngine {}

/// The current [`MembershipEnvelope`] wire version. Bump on a breaking layout change; a reader that sees a
/// version it doesn't understand refuses rather than misparsing.
pub const MEMBERSHIP_ENVELOPE_VERSION: u32 = 1;

/// The **generic membership-update envelope** — the single wire both keyring engines emit, owned by
/// openom-keyring-api (a real protobuf message via `prost`, so it is efficient AND self-owned — the crate borrows no
/// openom proto). It is a thin frame: a `version`, the producing `engine` tag ([`EngineKind::as_tag`]), and
/// an OPAQUE `body` — the chain's signed `Keyring`, or a dag op — that only that engine parses. The op/
/// keyring content id is computed over the inner `body`, BEFORE this framing, so wrapping never changes it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MembershipEnvelope {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// The engine whose `body` this is — [`EngineKind::as_tag`] (`"chain"` / `"dag"`). A routing HINT: the
    /// authoritative engine is the tree's pinned selection, and the body is self-authenticating.
    #[prost(string, tag = "2")]
    pub engine: String,
    /// The engine-specific, opaque update bytes. openom-keyring-api never parses it.
    #[prost(bytes = "vec", tag = "3")]
    pub body: Vec<u8>,
}

impl MembershipEnvelope {
    /// Frame an engine's opaque update bytes at the current version.
    pub fn wrap(engine: EngineKind, body: Vec<u8>) -> Self {
        Self {
            version: MEMBERSHIP_ENVELOPE_VERSION,
            engine: engine.as_tag().to_string(),
            body,
        }
    }

    /// Encode to protobuf bytes (the blob/transport form).
    pub fn encode(&self) -> Vec<u8> {
        ::prost::Message::encode_to_vec(self)
    }

    /// Decode from protobuf bytes, refusing a future/unknown `version` (fail closed, never misparse).
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let env = <Self as ::prost::Message>::decode(bytes).map_err(|_| EnvelopeError::Malformed)?;
        if env.version != MEMBERSHIP_ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(env.version));
        }
        Ok(env)
    }

    /// The producing engine, parsed from the tag — [`EngineKind`], or an `UnknownEngine`.
    pub fn engine_kind(&self) -> Result<EngineKind, UnknownEngine> {
        self.engine.parse()
    }
}

/// Why a [`MembershipEnvelope`] wouldn't decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The bytes weren't a valid envelope message.
    Malformed,
    /// A `version` this build doesn't understand — refused rather than misparsed.
    UnsupportedVersion(u32),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::Malformed => write!(f, "malformed membership envelope"),
            EnvelopeError::UnsupportedVersion(v) => write!(f, "unsupported membership envelope version: {v}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// openom-keyring-api's own generic role convention (`i16`, **lower is stronger**): the Owner is the single
/// strongest role and a signer is CoOwner-or-stronger. A consumer maps its own role enum onto these — for
/// openom that's `openom-roles` (derived from the proto `MemberRole`), whose values MUST match. Defining
/// them here, rather than depending on `openom-roles`, keeps this seam openom-free (openom-roles pulls in
/// `openom-protocol`) so the crate — and every engine that binds its roles to these instead of to
/// openom-roles — is standalone-publishable (OPE-279). openom-roles' `keyeo_api_role_convention_matches_openom_roles`
/// drift-guard test pins these to the proto `MemberRole` values.
pub const ROLE_OWNER: i16 = 1;
pub const ROLE_CO_OWNER: i16 = 2;
pub const ROLE_MAINTAINER: i16 = 3;
pub const ROLE_EDITOR: i16 = 4;
pub const ROLE_VIEWER: i16 = 5;

/// One member of the resolved keyring, engine-agnostic. Both engines fold to this: chain from
/// `Keyring.members`, dag from the resolved `GroupState`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    pub member_id: String,
    /// A role in openom-keyring-api's convention ([`ROLE_OWNER`] = 1 … Viewer = 5); **lower is stronger**.
    pub role: i16,
    pub author_public_key: Vec<u8>,
    pub hpke_public_key: Vec<u8>,
}

impl MemberView {
    /// A **signer** (keyring-write authority) is a CoOwner or stronger — the single-axis mapping both
    /// engines use.
    pub fn is_signer(&self) -> bool {
        self.role <= ROLE_CO_OWNER
    }
    /// The unique Owner / founder.
    pub fn is_owner(&self) -> bool {
        self.role == ROLE_OWNER
    }
}

/// The resolved membership + roles of a keyring — the shared vocabulary consumed regardless of engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipView {
    /// Active members, **sorted by `member_id`** for a deterministic, engine-independent view.
    pub members: Vec<MemberView>,
    /// This admission established or advanced across a recovery re-founding — the signal the server's
    /// reset cooldown gates on. Chain: a verified reset; dag: a `ReFound` / `RotateRecoveryAuthority`
    /// admission (or the privileged-carve-out class).
    pub reset_boundary: bool,
}

impl MembershipView {
    /// Build a view from members, sorting for determinism (so two engines that resolve the same
    /// membership produce byte-identical views).
    pub fn new(mut members: Vec<MemberView>, reset_boundary: bool) -> Self {
        members.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        Self {
            members,
            reset_boundary,
        }
    }

    /// The signer subset (CoOwner or stronger) — what keyring-write authority checks and the server's
    /// ACL derivation care about.
    pub fn signers(&self) -> impl Iterator<Item = &MemberView> {
        self.members.iter().filter(|m| m.is_signer())
    }

    /// The unique Owner, if present.
    pub fn owner(&self) -> Option<&MemberView> {
        self.members.iter().find(|m| m.is_owner())
    }
}

/// The outcome of admitting one update against prior trust state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The engine-**opaque** trust state to persist (chain: the accepted head bytes; dag: the op
    /// closure). The anti-rollback floor lives INSIDE these bytes, never as a shared field (guardrail).
    pub state: Vec<u8>,
    pub view: MembershipView,
    /// `false` = the update was validly admitted but changed no membership — the DAG's honest no-op case
    /// (a signed op the resolver gives no effect) and idempotent re-serves. **Mandatory** so that
    /// "acceptance ⇒ change" is never baked into a consumer (e.g. the server always advancing a revision).
    pub changed: bool,
    /// The tree id read from the **verified** body — the value the server equality-checks against the tree
    /// it is operating on (the routing hint from the outer envelope is only that, a hint). Because it comes
    /// from the authenticated update, the server can trust it without parsing the keyring itself.
    pub tree_id: Vec<u8>,
    /// The canonical **position** of this update, derived from the verified body — the server's storage /
    /// CAS key and head-advance value (chain: the revision bytes; dag: the op id). The server keys ONLY on
    /// this, never on the unauthenticated outer-envelope hint, so no lie in the framing can steer storage.
    pub update_ref: Vec<u8>,
}

/// Why an update was refused — neutral vocabulary, neither chain's `ChainError` nor the DAG's op errors.
/// The full engine-specific detail can be kept as diagnostics behind this classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Undecodable or structurally invalid bytes.
    Malformed,
    /// A signature did not verify, or the author is unknown.
    Unauthenticated,
    /// Behind the trust state — a replay or a withheld hop (an anti-rollback refusal that is recoverable
    /// by re-fetching), distinct from a hostile [`VerifyError::Rollback`].
    Stale,
    /// Validly authenticated, but the author lacked the authority for this change.
    Unauthorized,
    /// A detected rollback / withholding against already-trusted state (chain: fatal; dag: advisory —
    /// structurally it can't regress, so this is a loud signal, not data loss).
    Rollback,
}

/// The **keyless** server-side verifier seam. Admit an update against prior trust state — no secrets, no
/// mutable state beyond what it is handed — and report the new opaque state + resolved view + whether it
/// changed. Chain and dag each implement it; the server (and the client's adoption path) bind only to
/// this. `admit` is the neutral "admit an update against prior state" verb — not chain's "accept/reject a
/// revision", not the DAG's "op / resolve" — so neither model leaks into the abstraction.
pub trait KeyringVerifier {
    /// Admit `update` against `prior_state` (`None` = first sight / bootstrap). Returns the new opaque
    /// trust state + resolved view + a `changed` flag, or a neutral refusal.
    fn admit(&self, prior_state: Option<&[u8]>, update: &[u8]) -> Result<Admitted, VerifyError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(id: &str, role: i16) -> MemberView {
        MemberView {
            member_id: id.to_string(),
            role,
            author_public_key: vec![role as u8],
            hpke_public_key: vec![role as u8],
        }
    }

    #[test]
    fn view_sorts_members_for_a_deterministic_engine_independent_shape() {
        // Two engines that resolve the same membership in different internal orders must produce the same
        // view — sorting by member_id is what makes MembershipView the shared contract.
        let a = MembershipView::new(vec![m("carol", 4), m("owner", 1), m("bob", 2)], false);
        let b = MembershipView::new(vec![m("bob", 2), m("carol", 4), m("owner", 1)], false);
        assert_eq!(a, b, "member order does not affect the resolved view");
        assert_eq!(
            a.members.iter().map(|m| m.member_id.as_str()).collect::<Vec<_>>(),
            vec!["bob", "carol", "owner"],
        );
    }

    #[test]
    fn signer_and_owner_classification_matches_the_role_axis() {
        let v = MembershipView::new(vec![m("owner", 1), m("bob", 2), m("dave", 3), m("ed", 4)], false);
        assert_eq!(v.owner().map(|o| o.member_id.as_str()), Some("owner"));
        // signers = Owner(1) + CoOwner(2); Maintainer(3)/Editor(4) are not.
        let signers: Vec<_> = v.signers().map(|s| s.member_id.clone()).collect();
        assert_eq!(signers, vec!["bob".to_string(), "owner".to_string()]);
    }

    #[test]
    fn engine_tag_round_trips_and_rejects_the_unknown() {
        // The one source of truth both host boundaries parse through: every engine's tag round-trips, and an
        // unknown tag is a typed error carrying the offending value — not a silent fallback.
        for k in [EngineKind::Chain, EngineKind::Dag] {
            assert_eq!(k.as_tag().parse::<EngineKind>().unwrap(), k);
        }
        assert_eq!("chain".parse::<EngineKind>().unwrap(), EngineKind::Chain);
        assert_eq!("dag".parse::<EngineKind>().unwrap(), EngineKind::Dag);
        assert_eq!(
            "mosaic".parse::<EngineKind>().unwrap_err(),
            UnknownEngine("mosaic".to_string())
        );
        assert_eq!("dag".parse::<EngineKind>().unwrap().as_tag(), "dag");
    }

    #[test]
    fn membership_envelope_round_trips_and_rejects_a_future_version() {
        let env = MembershipEnvelope::wrap(EngineKind::Dag, b"opaque-op-bytes".to_vec());
        let bytes = env.encode();
        let back = MembershipEnvelope::decode(&bytes).unwrap();
        assert_eq!(back, env);
        assert_eq!(back.engine_kind().unwrap(), EngineKind::Dag);
        assert_eq!(back.body, b"opaque-op-bytes");

        // A future version is refused (fail closed), never misparsed as the current layout.
        let future = MembershipEnvelope {
            version: MEMBERSHIP_ENVELOPE_VERSION + 1,
            engine: "dag".into(),
            body: vec![],
        };
        assert_eq!(
            MembershipEnvelope::decode(&future.encode()).unwrap_err(),
            EnvelopeError::UnsupportedVersion(MEMBERSHIP_ENVELOPE_VERSION + 1),
        );
    }

    #[test]
    fn membership_view_round_trips_through_serde() {
        let v = MembershipView::new(vec![m("owner", 1), m("bob", 2)], true);
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<MembershipView>(&json).unwrap(), v);
    }
}
