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
    _phantom: PhantomData<S>,
}

impl<Id: MemberId, R: Role, S: SignatureScheme> GroupState<Id, R, S> {
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            epoch: 0,
            history_commitment: [0u8; 32],
            dek_wraps: Vec::new(),
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
    pub fn create(initial: &[MemberInit<Id, R, S>]) -> Self {
        let mut state = Self::new();
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
            _phantom: PhantomData,
        }
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
        }
    }
}
