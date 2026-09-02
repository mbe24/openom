//! Core types: Resolver trait, GroupState, MembershipAction, MemberState.

use crate::roles::Role;
use crate::signature::SignatureScheme;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::marker::PhantomData;

pub trait OpId:
    Debug + Clone + Copy + Eq + std::hash::Hash + Ord + Send + Sync + serde::Serialize
{
}

pub trait MemberId:
    Debug + Clone + Eq + std::hash::Hash + Ord + Send + Sync + serde::Serialize
{
}

impl OpId for u64 {}
impl OpId for u32 {}
impl OpId for usize {}
impl OpId for [u8; 32] {}
impl MemberId for [u8; 32] {}
impl MemberId for String {}
impl MemberId for u64 {}
impl MemberId for u32 {}

/// An opaque group identifier — the group (openom: the tree) an op belongs to. A one-level newtype over
/// `Vec<u8>` (the OPE-211 house style, no generics): keyeo stays domain-free while the type is
/// **non-swappable** with the equally-`Vec<u8>`-shaped `sealing` payload it sits beside in constructors.
/// Bound into every op's signed + content-addressed bytes and enforced by the engine (an op whose group id
/// differs from the group being resolved is refused). Construct real ids with [`GroupId::new`]; use the
/// explicit [`GroupId::unscoped`] marker for keyeo's own single-group / test callers so an EMPTY group id is
/// always a conscious choice, never an accident.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct GroupId(pub Vec<u8>);

impl GroupId {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    /// The explicit "no group scope" marker — a single-group or test context. Distinct in intent from a
    /// forgotten binding: a caller writes `GroupId::unscoped()` on purpose.
    pub fn unscoped() -> Self {
        Self(Vec::new())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn is_unscoped(&self) -> bool {
        self.0.is_empty()
    }
}

pub trait SignedOp: Debug + Clone + Eq + std::hash::Hash + Ord {
    type S: SignatureScheme;
    type OpId: self::OpId;
    type MemberId: self::MemberId;
    type R: Role;
    fn id(&self) -> Self::OpId;
    fn parents(&self) -> &[Self::OpId];
    fn author(&self) -> &Self::MemberId;
    fn action(&self) -> &MembershipAction<Self::MemberId, Self::R, Self::S>;
    fn signature(&self) -> &<Self::S as SignatureScheme>::Signature;
    fn author_public_key(&self) -> &<Self::S as SignatureScheme>::PublicKey;
    /// An opaque application payload, folded into the signed + content-addressed bytes but never
    /// interpreted by keyeo (OPE-273). Defaults to empty for op types that carry none.
    fn sealing(&self) -> &[u8] {
        &[]
    }
    /// The group this op belongs to — an opaque, caller-assigned identifier (openom: the tree id), bound
    /// into the signed + content-addressed bytes ([`crate::canonical::canonical_encode`]) and enforced by
    /// the engine: an op whose `group_id` differs from the group being resolved is refused, never merged.
    /// **Required** (no default): a group binding that silently defaulted to empty would be a hole. Ops in a
    /// single-group / test context use the same value on both sides (commonly [`GroupId::unscoped`]), so
    /// the check is a no-op there and a hard guarantee once a caller assigns real group ids.
    fn group_id(&self) -> &GroupId;
}

// Not `derive(Serialize)`: these embed crypto byte-arrays (incl. `[u8; 64]` sigs, which serde won't
// serialize) — they get hand-written `CanonicalBytes` impls in `canonical` instead.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberInit<Id: MemberId, R: Role, S: SignatureScheme> {
    pub id: Id,
    pub role: R,
    pub author_public_key: <S as SignatureScheme>::PublicKey,
    pub hpke_public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MembershipAction<Id: MemberId, R: Role, S: SignatureScheme> {
    Create {
        initial_members: Vec<MemberInit<Id, R, S>>,
    },
    Add {
        member: Id,
        role: R,
        author_public_key: <S as SignatureScheme>::PublicKey,
        hpke_public_key: [u8; 32],
        member_proof: Option<<S as SignatureScheme>::Signature>,
    },
    Remove {
        member: Id,
    },
    ChangeRole {
        member: Id,
        new_role: R,
    },
    /// Propose a privileged change gated by multi-signer quorum (v2). `proposal_id` identifies it
    /// (Approve/Commit carry the same id); `target` is the wrapped action that takes effect once quorum
    /// is met. Structurally generic — the quorum machinery never inspects the target's contents.
    Propose {
        proposal_id: [u8; 32],
        target: Box<MembershipAction<Id, R, S>>,
    },
    /// A single signer's approval of a proposal — one op per approver (single-author, so strong-remove's
    /// per-author rules apply to it unchanged).
    Approve {
        proposal_id: [u8; 32],
    },
    /// Make a proposal's `target` take effect at this op's causal position, if quorum is met by then.
    Commit {
        proposal_id: [u8; 32],
    },
    /// Recovery re-founding (OPE-269): retarget `member`'s (openom: the Owner's) signing + HPKE keys and
    /// carry re-wrapped recovery material. Authorized NOT by ordinary membership authority but by the
    /// group's pinned **recovery authority** — the op is signed by the recovery key whose public half is
    /// [`GroupState::reset_authority`] (see `key_matches_registration`) — so a member who lost their
    /// device can re-establish control without a prior member's cooperation. It removes no one and touches
    /// no other member: a forward-chained delta, not a re-genesis (contrast `Create`). `era` is a monotone
    /// re-founding generation (1 + max era in the causal past). Any re-wrapped recovery material rides the
    /// op's opaque `sealing` envelope (which keyeo signs + content-addresses but never reads) — there is no
    /// per-action rewrap field.
    ReFound {
        member: Id,
        new_author_public_key: <S as SignatureScheme>::PublicKey,
        new_hpke_public_key: [u8; 32],
        era: u64,
    },
    /// Rotate the group's recovery authority (OPE-272): replace the pinned [`GroupState::reset_authority`]
    /// with `new_reset_authority`, authorized by the op being signed by the CURRENT recovery authority.
    /// This is the ONLY way to genuinely revoke a prior recovery-key holder: re-wrapping the RRK secret
    /// (change-passphrase) leaves the keypair unchanged, so anyone who ever unwrapped it keeps recovery
    /// power until a rotation mints a fresh keypair. Gating on the OLD authority means an attacker without
    /// the current secret cannot rotate it out from under the legitimate owner. Any re-wrapped recovery
    /// material rides the op's opaque `sealing` envelope, not a per-action field.
    RotateRecoveryAuthority {
        new_reset_authority: <S as SignatureScheme>::PublicKey,
    },
    /// Voluntary self-rekey (OPE-274): `member` retargets their OWN signing + HPKE keys, authorized by the
    /// op being signed by their CURRENT registered key — ordinary D3 authentication (contrast `ReFound`,
    /// which is gated on the recovery authority). openom uses it for change-passphrase, where the new keys
    /// derive from the new passphrase; the re-escrow rides the op's opaque `sealing` payload, so there is
    /// no per-action rewrap field. It removes no one and touches no other member — a forward delta, NOT a
    /// recovery: it does NOT trigger the reset-merge carve-out (it is not a re-founding).
    Retarget {
        member: Id,
        new_author_public_key: <S as SignatureScheme>::PublicKey,
        new_hpke_public_key: [u8; 32],
    },
    /// A membership-INERT carrier for a fresh sealing delta (openom's forward-secrecy reseal, OPE-282): it
    /// changes no member, signer, governance, or recovery authority — the payload rides the op's opaque
    /// `sealing` envelope, which keyeo never interprets. `apply_action` is a no-op; it is NOT privileged (it
    /// auto-merges, never voided by the reset-merge carve-out); and it is authorized for any active member
    /// (ordinary D3 — the author's current registered key signs it). The empty body carries no discretionary
    /// authority: what the sealing may legitimately contain is the domain layer's concern, not keyeo's.
    Reseal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberState<R: Role, S: SignatureScheme = crate::signature::Ed25519> {
    pub role: R,
    pub member_counter: u64,
    pub access_counter: u64,
    pub author_public_key: <S as SignatureScheme>::PublicKey,
    pub hpke_public_key: [u8; 32],
}

impl<R: Role, S: SignatureScheme> MemberState<R, S> {
    pub fn is_active(&self) -> bool {
        self.member_counter.is_multiple_of(2)
    }
    pub fn new(
        role: R,
        author_public_key: <S as SignatureScheme>::PublicKey,
        hpke_public_key: [u8; 32],
    ) -> Self {
        Self {
            role,
            member_counter: 0,
            access_counter: 0,
            author_public_key,
            hpke_public_key,
        }
    }
}

/// A per-member HPKE wrap of the epoch DEK, carried in the resolved `GroupState` (item 3). It is
/// public, replicated data: the wrapped DEK for the epoch that the state commits to. A member recovers
/// the DEK with their own HPKE secret (see `epoch::recover_epoch_dek`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DekWrap<Id: MemberId> {
    pub member: Id,
    pub hpke_public_key: [u8; 32],
    pub encapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupState<Id: MemberId, R: Role, S: SignatureScheme = crate::signature::Ed25519> {
    pub members: HashMap<Id, MemberState<R, S>>,
    /// Monotonic epoch, bumped by the engine when the resolved active membership changes (item 3).
    pub epoch: u64,
    /// Deterministic commitment to the active membership that produced the current epoch (item 4).
    pub history_commitment: [u8; 32],
    /// Per-active-member HPKE wraps of the current epoch DEK (item 3).
    pub dek_wraps: Vec<DekWrap<Id>>,
    /// The group's **recovery authority**: the public half of the key (openom: the RVK) that alone may
    /// authorize a [`MembershipAction::ReFound`]. Pinned at genesis (in openom, on the construction base
    /// via [`Self::with_reset_authority`]) and preserved across every op, so a recovery is verifiable by
    /// every replica against the authority the group was founded with. `None` = no recovery authority (a
    /// group that cannot be re-founded).
    pub reset_authority: Option<<S as SignatureScheme>::PublicKey>,
    /// This group's opaque identifier (openom: the tree id). Pinned at genesis (via [`Self::with_group_id`])
    /// and preserved across every op; the engine refuses to admit an op whose `group_id` differs from it, so
    /// an op minted for another group can never resolve into this one. Empty (`&[]`) = an unassigned group
    /// (keyeo's own tests, single-group callers) — then the match is vacuous, by design.
    pub group_id: GroupId,
    _phantom: PhantomData<S>,
}

impl<Id: MemberId, R: Role, S: SignatureScheme> GroupState<Id, R, S> {
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            epoch: 0,
            history_commitment: [0u8; 32],
            dek_wraps: Vec::new(),
            reset_authority: None,
            group_id: GroupId::unscoped(),
            _phantom: PhantomData,
        }
    }
}

impl<Id: MemberId, R: Role, S: SignatureScheme> Default for GroupState<Id, R, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Id: MemberId, R: Role, S: SignatureScheme> GroupState<Id, R, S> {
    pub fn create(group_id: GroupId, initial: &[MemberInit<Id, R, S>]) -> Self {
        let mut state = Self::new();
        state.group_id = group_id;
        for init in initial {
            state.members.insert(
                init.id.clone(),
                MemberState::new(
                    init.role.clone(),
                    init.author_public_key.clone(),
                    init.hpke_public_key,
                ),
            );
        }
        state
    }

    /// Attach a generated epoch (number, membership commitment, per-member DEK wraps) to the group.
    /// This is how the resolved state carries the current epoch's key material (item 3) — callers that
    /// rotate call `epoch::generate_epoch` and land the result here.
    pub fn with_epoch(&self, epoch: u64, commitment: [u8; 32], wraps: Vec<DekWrap<Id>>) -> Self {
        Self {
            members: self.members.clone(),
            epoch,
            history_commitment: commitment,
            dek_wraps: wraps,
            reset_authority: self.reset_authority.clone(),
            group_id: self.group_id.clone(),
            _phantom: PhantomData,
        }
    }

    /// Pin the group's [`group_id`](Self::group_id) — the opaque identifier every op in this group must
    /// carry. openom sets this on the engine's construction base (the genesis) to the tree id, so the engine
    /// refuses any op minted for a different tree from first sight, exactly as it trusts the genesis members.
    pub fn with_group_id(mut self, group_id: GroupId) -> Self {
        self.group_id = group_id;
        self
    }

    /// Pin the group's [`recovery authority`](Self::reset_authority) — the only key that may authorize a
    /// `ReFound`. openom sets this on the engine's construction base (the out-of-band-seeded genesis) so
    /// the RVK is trusted from first sight, exactly as the genesis membership is.
    pub fn with_reset_authority(mut self, reset_authority: Option<<S as SignatureScheme>::PublicKey>) -> Self {
        self.reset_authority = reset_authority;
        self
    }

    pub fn active_members(&self) -> Vec<(Id, R)> {
        let mut result: Vec<_> = self
            .members
            .iter()
            .filter(|(_, s)| s.is_active())
            .map(|(id, s)| (id.clone(), s.role.clone()))
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Active members with their HPKE public key — the input to `epoch::membership_commitment` and
    /// `epoch::generate_epoch` rotation wiring.
    pub fn active_with_keys(&self) -> Vec<(Id, R, [u8; 32])> {
        let result: Vec<_> = self
            .members
            .iter()
            .filter(|(_, s)| s.is_active())
            .map(|(id, s)| (id.clone(), s.role.clone(), s.hpke_public_key))
            .collect();
        result
    }

    pub fn has_access(&self, member: &Id, min_role: &R) -> bool {
        self.members
            .get(member)
            .map(|s| s.is_active() && s.role.grants_at_least(min_role))
            .unwrap_or(false)
    }
}

/// D3 (retarget-tolerant authentication): the op's carried author public key must equal the author's
/// **registered** key in `state` — the resolved state at the op's causal position.
///
/// Admission ([`crate::engine::Keyeo::authenticate`]) verifies an op's signature against its OWN carried
/// key, so a validly self-signed op is *always* admitted, even one signed under a key a later op has
/// since retargeted. This check — run at each op's fixed causal position, identically on every replica —
/// then decides whether that carried key was the member's registered key, i.e. whether the op carries
/// real authority. Splitting it this way keeps resolution replica-independent: a late op signed under a
/// since-rotated key resolves the same everywhere, instead of being admitted where the old key is still
/// current and rejected where it isn't (a BEC-convergence break).
///
/// Bootstrapping actions carry their own key by nature and are exempt: a `Create` (its members' keys ARE
/// the genesis) and a self-authored `Add` (a member (re)introducing themselves) — their key legitimacy
/// is judged by the action's own rule in [`crate::access::AccessControl`], not a prior registration.
pub(crate) fn key_matches_registration<Id, R, S, Op>(state: &GroupState<Id, R, S>, op: &Op) -> bool
where
    Id: MemberId,
    R: Role,
    S: SignatureScheme,
    Op: SignedOp<MemberId = Id, R = R, S = S>,
{
    match op.action() {
        MembershipAction::Create { .. } => true,
        MembershipAction::Add { member, .. } if member == op.author() => true,
        // The recovery-authorized ops — a re-founding (ReFound) and a rotation of the authority itself
        // (RotateRecoveryAuthority) — are authorized by the pinned recovery key, not a member
        // registration: valid only when signed by the group's CURRENT `reset_authority` (openom: the RVK).
        // This is the engine-side half of the "distinguish a legitimate recovery from a hostile one" gate —
        // a branch a replica can't verify against the founded-with (or currently-pinned) authority is
        // unauthorized, hence ignored, hence never merged. Rotating gated by the OLD authority is exactly
        // what lets it revoke a prior holder. (Domain shape — Owner target/author — is AccessControl's.)
        MembershipAction::ReFound { .. } | MembershipAction::RotateRecoveryAuthority { .. } => {
            state.reset_authority.as_ref() == Some(op.author_public_key())
        }
        _ => state
            .members
            .get(op.author())
            .map(|m| &m.author_public_key == op.author_public_key())
            .unwrap_or(false),
    }
}

use crate::blocklace::Graph;

pub trait Resolver<OId: OpId, R: Role, Op: SignedOp<R = R, S = S>, S: SignatureScheme> {
    type State: Default;
    type Error: Debug;
    fn rebuild_required(state: &Self::State, op: &Op, frontier: &HashSet<OId>) -> bool;
    fn process(
        state: Self::State,
        graph: &Graph<OId>,
        ops: &HashMap<OId, Op>,
        ac: &impl crate::access::AccessControl<Op::MemberId, R, S>,
        // The base state a causal replay starts from (the engine's construction genesis). An
        // authority-aware resolver needs it to compute each op's authorization at its causal position.
        genesis: &GroupState<Op::MemberId, R, S>,
    ) -> Result<Self::State, Self::Error>;

    /// Return the set of op IDs that should be ignored (filtered out) during state rebuild.
    /// Keyed on the real `OId` — not a `u64` projection — so it stays correct for wide,
    /// content-addressed ids (a 32-byte hash can't round-trip through `to_u64`).
    fn ignored(state: &Self::State) -> HashSet<OId>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipEvent<Id: MemberId> {
    MemberAdded { member: Id },
    MemberRemoved { member: Id },
    RoleChanged { member: Id },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyOutcome<Id: MemberId, OId: OpId> {
    Applied { events: Vec<MembershipEvent<Id>> },
    Buffered { missing_parents: Vec<OId> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error<Id: Debug + Clone> {
    BadSignature,
    UnknownAuthor { author: Id },
    Unauthorized { author: Id },
    InvalidAction(String),
    MissingParents(Vec<Id>),
    DagCycle,
    Crypto(String),
    /// The op branches from BEFORE the set merge horizon (some horizon op is not in its causal past) — a
    /// stale fork / equivocation-rollback vector past the compaction frontier, rejected rather than merged
    /// (OPE-270).
    StaleFork,
    /// The op's `group_id` does not match the group being resolved — an op minted for a different group
    /// (openom: a different tree). Refused at admission, never stored or merged.
    WrongGroup,
}

impl<Id: Debug + Clone> std::fmt::Display for Error<Id> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadSignature => write!(f, "bad signature"),
            Error::UnknownAuthor { author } => write!(f, "unknown author: {:?}", author),
            Error::Unauthorized { author } => write!(f, "unauthorized: {:?}", author),
            Error::InvalidAction(msg) => write!(f, "invalid action: {}", msg),
            Error::MissingParents(ids) => write!(f, "missing parents: {:?}", ids),
            Error::DagCycle => write!(f, "DAG cycle detected"),
            Error::Crypto(msg) => write!(f, "crypto: {}", msg),
            Error::StaleFork => write!(f, "op branches from before the merge horizon"),
            Error::WrongGroup => write!(f, "op belongs to a different group"),
        }
    }
}
