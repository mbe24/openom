//! Fit the DAG keyring to the `blobstore` seam (OPE-266).
//!
//! keyeo's DAG is a blocklace — content-addressed signed ops — so it syncs over a dumb blob store as
//! Merkle-DAG anti-entropy: each op is an immutable blob keyed by its id, and a replica pulls by fetching
//! ops it lacks and letting the engine's buffer/flush apply them in causal order. This module is the
//! **storage adapter only** — the recovery/anti-rollback semantic completion is a separate task.
//!
//! keyeo has no round-trippable op serialization of its own (its `SignatureScheme` uses `AsRef<[u8]>`,
//! not serde, because `[u8; 64]` sigs aren't serde-friendly), so we carry a concrete serde codec for the
//! openom [`KeyringOp`] here.
//!
//! Pull is list-based (fetch every op blob, apply the new ones): correct and simple, and it proves
//! convergence. A per-replica head pointer to avoid the O(all-objects) list is a later perf task.

use std::collections::HashSet;

use blobstore::{BlobError, BlobStore, Precondition};
use keyeo::MembershipAction;
use serde::{Deserialize, Serialize};

use crate::{KeyringAction, KeyringEngine, KeyringMemberInit, KeyringOp, KeyringRole};

const OP_PREFIX: &str = "op/";

/// A blob-sync failure.
#[derive(Debug)]
pub enum BlobSyncError {
    Store(BlobError),
    Decode(serde_json::Error),
    Malformed(&'static str),
    Engine(String),
}

impl From<BlobError> for BlobSyncError {
    fn from(e: BlobError) -> Self {
        BlobSyncError::Store(e)
    }
}

impl std::fmt::Display for BlobSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobSyncError::Store(e) => write!(f, "blob store: {e}"),
            BlobSyncError::Decode(e) => write!(f, "op decode: {e}"),
            BlobSyncError::Malformed(m) => write!(f, "malformed op blob: {m}"),
            BlobSyncError::Engine(m) => write!(f, "engine rejected op: {m}"),
        }
    }
}

impl std::error::Error for BlobSyncError {}

type Result<T> = std::result::Result<T, BlobSyncError>;

/// The outcome of a [`KeyringBlobSync::pull`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullReport {
    /// How many new ops were submitted to the engine this pull.
    pub submitted: usize,
    /// Op ids this replica had already applied that are ABSENT from the store's current listing — i.e. a
    /// rollback / withholding attempt (a content-addressed op set can only be regressed by *omission*;
    /// re-serving old ops is idempotent). This is the DAG's anti-rollback signal: monotonicity itself
    /// holds structurally (pull only ever adds to the engine, never removes), so the local op set — and
    /// everything resolved from it, including any recovery — is unaffected. A non-empty `withheld` is
    /// therefore a loud alarm about a stale or hostile store, NOT data loss. (A managed backend can also
    /// prevent this below the blob seam by refusing deletions; a BYO backend can only detect it, which is
    /// what this does. Cross-device frontier attestation + new-device first-sight are broader concerns
    /// than one replica's own history and are out of scope here.)
    pub withheld: Vec<[u8; 32]>,
}

/// One replica's blob sync for a keyring DAG: publishes locally-applied ops and pulls remote ones into
/// an engine. Tracks which op ids it has already submitted so pull is incremental.
pub struct KeyringBlobSync<S: BlobStore> {
    store: S,
    applied: HashSet<[u8; 32]>,
}

impl<S: BlobStore> KeyringBlobSync<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            applied: HashSet::new(),
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Publish a locally-applied op as an immutable content-addressed blob. Idempotent: a blob already
    /// present (another replica pushed the same op) is fine — the content is identical.
    pub fn push(&mut self, op: &KeyringOp) -> Result<()> {
        let key = op_key(&op.id);
        match self.store.put(&key, &encode_op(op), Precondition::IfAbsent) {
            Ok(_) | Err(BlobError::PreconditionFailed) => {}
            Err(e) => return Err(BlobSyncError::Store(e)),
        }
        self.applied.insert(op.id);
        Ok(())
    }

    /// Fetch every op blob not yet applied and hand it to `engine`; then flush so any op buffered awaiting
    /// its parents lands once they arrive. Idempotent. Also checks anti-rollback: any op this replica has
    /// already applied that the store no longer serves is reported in [`PullReport::withheld`] — the local
    /// op set is never regressed (pull only adds), so this is a detection signal, not data loss.
    pub fn pull(&mut self, engine: &mut KeyringEngine) -> Result<PullReport> {
        let keys = self.store.list(OP_PREFIX)?;
        let mut present: HashSet<[u8; 32]> = HashSet::with_capacity(keys.len());
        let mut submitted = 0;
        for (key, _etag) in keys {
            let (bytes, _) = self
                .store
                .get(&key)?
                .ok_or(BlobSyncError::Malformed("listed key vanished"))?;
            let op = decode_op(&bytes)?;
            if op_key(&op.id) != key {
                return Err(BlobSyncError::Malformed("op id does not match its blob key"));
            }
            present.insert(op.id);
            if self.applied.contains(&op.id) {
                continue;
            }
            let id = op.id;
            engine
                .apply(op)
                .map_err(|e| BlobSyncError::Engine(format!("{e:?}")))?;
            self.applied.insert(id);
            submitted += 1;
        }
        engine
            .flush()
            .map_err(|e| BlobSyncError::Engine(format!("{e:?}")))?;
        // Anti-rollback: everything we ever applied must still be served; a gap is a withholding attempt.
        let withheld: Vec<[u8; 32]> = self
            .applied
            .iter()
            .filter(|id| !present.contains(*id))
            .copied()
            .collect();
        Ok(PullReport { submitted, withheld })
    }
}

fn op_key(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(OP_PREFIX.len() + 64);
    s.push_str(OP_PREFIX);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---- concrete serde codec for KeyringOp (keyeo has none of its own) ----

#[derive(Serialize, Deserialize)]
struct OpDto {
    id: [u8; 32],
    /// The op's group id (openom: the tree id) — carried round-trip so the signature (which covers it)
    /// verifies after decode and the engine's group gate sees the authentic value. Defaulted (empty =
    /// unscoped) so single-group / test ops stay compact.
    #[serde(default)]
    group_id: Vec<u8>,
    parents: Vec<[u8; 32]>,
    author: String,
    action: ActionDto,
    signature: Vec<u8>, // [u8; 64] — Vec because serde has no [u8; 64] impl
    author_public_key: [u8; 32],
    /// The op's opaque sealing payload — carried round-trip so the signature (which covers it) still
    /// verifies after decode. Defaulted so ops that carry none stay compact. (OPE-273.)
    #[serde(default)]
    sealing: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum ActionDto {
    Create {
        initial_members: Vec<MemberInitDto>,
    },
    Add {
        member: String,
        role: KeyringRole,
        author_public_key: [u8; 32],
        hpke_public_key: [u8; 32],
        member_proof: Option<Vec<u8>>,
    },
    Remove {
        member: String,
    },
    ChangeRole {
        member: String,
        new_role: KeyringRole,
    },
    Propose {
        proposal_id: [u8; 32],
        target: Box<ActionDto>,
    },
    Approve {
        proposal_id: [u8; 32],
    },
    Commit {
        proposal_id: [u8; 32],
    },
    ReFound {
        member: String,
        new_author_public_key: [u8; 32],
        new_hpke_public_key: [u8; 32],
        era: u64,
    },
    RotateRecoveryAuthority {
        new_reset_authority: [u8; 32],
    },
    Retarget {
        member: String,
        new_author_public_key: [u8; 32],
        new_hpke_public_key: [u8; 32],
    },
    Reseal,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MemberInitDto {
    id: String,
    role: KeyringRole,
    author_public_key: [u8; 32],
    hpke_public_key: [u8; 32],
}

pub(crate) fn encode_op(op: &KeyringOp) -> Vec<u8> {
    let dto = OpDto {
        id: op.id,
        group_id: op.group_id.0.clone(),
        parents: op.parents.clone(),
        author: op.author.clone(),
        action: action_to_dto(&op.action),
        signature: op.signature.to_vec(),
        author_public_key: op.author_public_key,
        sealing: op.sealing.clone(),
    };
    serde_json::to_vec(&dto).expect("op DTO serialization is infallible")
}

pub(crate) fn decode_op(bytes: &[u8]) -> Result<KeyringOp> {
    let dto: OpDto = serde_json::from_slice(bytes).map_err(BlobSyncError::Decode)?;
    let mut op = keyeo::Op::new(
        dto.id,
        keyeo::GroupId::new(dto.group_id),
        dto.parents,
        dto.author,
        dto_to_action(&dto.action)?,
        sig64(&dto.signature)?,
        dto.author_public_key,
    );
    op.sealing = dto.sealing;
    Ok(op)
}

fn sig64(v: &[u8]) -> Result<[u8; 64]> {
    v.try_into().map_err(|_| BlobSyncError::Malformed("signature is not 64 bytes"))
}

fn action_to_dto(a: &KeyringAction) -> ActionDto {
    match a {
        MembershipAction::Create { initial_members } => ActionDto::Create {
            initial_members: initial_members.iter().map(minit_to_dto).collect(),
        },
        MembershipAction::Add {
            member,
            role,
            author_public_key,
            hpke_public_key,
            member_proof,
        } => ActionDto::Add {
            member: member.clone(),
            role: *role,
            author_public_key: *author_public_key,
            hpke_public_key: *hpke_public_key,
            member_proof: member_proof.as_ref().map(|s| s.to_vec()),
        },
        MembershipAction::Remove { member } => ActionDto::Remove { member: member.clone() },
        MembershipAction::ChangeRole { member, new_role } => ActionDto::ChangeRole {
            member: member.clone(),
            new_role: *new_role,
        },
        MembershipAction::Propose { proposal_id, target } => ActionDto::Propose {
            proposal_id: *proposal_id,
            target: Box::new(action_to_dto(target)),
        },
        MembershipAction::Approve { proposal_id } => ActionDto::Approve { proposal_id: *proposal_id },
        MembershipAction::Commit { proposal_id } => ActionDto::Commit { proposal_id: *proposal_id },
        MembershipAction::ReFound {
            member,
            new_author_public_key,
            new_hpke_public_key,
            era,
        } => ActionDto::ReFound {
            member: member.clone(),
            new_author_public_key: *new_author_public_key,
            new_hpke_public_key: *new_hpke_public_key,
            era: *era,
        },
        MembershipAction::RotateRecoveryAuthority {
            new_reset_authority,
        } => ActionDto::RotateRecoveryAuthority {
            new_reset_authority: *new_reset_authority,
        },
        MembershipAction::Retarget {
            member,
            new_author_public_key,
            new_hpke_public_key,
        } => ActionDto::Retarget {
            member: member.clone(),
            new_author_public_key: *new_author_public_key,
            new_hpke_public_key: *new_hpke_public_key,
        },
        MembershipAction::Reseal => ActionDto::Reseal,
    }
}

fn dto_to_action(d: &ActionDto) -> Result<KeyringAction> {
    Ok(match d {
        ActionDto::Create { initial_members } => MembershipAction::Create {
            initial_members: initial_members
                .iter()
                .map(dto_to_minit)
                .collect::<Result<Vec<_>>>()?,
        },
        ActionDto::Add {
            member,
            role,
            author_public_key,
            hpke_public_key,
            member_proof,
        } => MembershipAction::Add {
            member: member.clone(),
            role: *role,
            author_public_key: *author_public_key,
            hpke_public_key: *hpke_public_key,
            member_proof: member_proof.as_ref().map(|v| sig64(v)).transpose()?,
        },
        ActionDto::Remove { member } => MembershipAction::Remove { member: member.clone() },
        ActionDto::ChangeRole { member, new_role } => MembershipAction::ChangeRole {
            member: member.clone(),
            new_role: *new_role,
        },
        ActionDto::Propose { proposal_id, target } => MembershipAction::Propose {
            proposal_id: *proposal_id,
            target: Box::new(dto_to_action(target)?),
        },
        ActionDto::Approve { proposal_id } => MembershipAction::Approve { proposal_id: *proposal_id },
        ActionDto::Commit { proposal_id } => MembershipAction::Commit { proposal_id: *proposal_id },
        ActionDto::ReFound {
            member,
            new_author_public_key,
            new_hpke_public_key,
            era,
        } => MembershipAction::ReFound {
            member: member.clone(),
            new_author_public_key: *new_author_public_key,
            new_hpke_public_key: *new_hpke_public_key,
            era: *era,
        },
        ActionDto::RotateRecoveryAuthority {
            new_reset_authority,
        } => MembershipAction::RotateRecoveryAuthority {
            new_reset_authority: *new_reset_authority,
        },
        ActionDto::Retarget {
            member,
            new_author_public_key,
            new_hpke_public_key,
        } => MembershipAction::Retarget {
            member: member.clone(),
            new_author_public_key: *new_author_public_key,
            new_hpke_public_key: *new_hpke_public_key,
        },
        ActionDto::Reseal => MembershipAction::Reseal,
    })
}

pub(crate) fn minit_to_dto(m: &KeyringMemberInit) -> MemberInitDto {
    MemberInitDto {
        id: m.id.clone(),
        role: m.role,
        author_public_key: m.author_public_key,
        hpke_public_key: m.hpke_public_key,
    }
}

pub(crate) fn dto_to_minit(d: &MemberInitDto) -> Result<KeyringMemberInit> {
    Ok(KeyringMemberInit {
        id: d.id.clone(),
        role: d.role,
        author_public_key: d.author_public_key,
        hpke_public_key: d.hpke_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sign_op, KeyringAccess, KeyringState};
    use blobstore::{BlobStore, MemoryBlob, Precondition};
    use keyeo::{Keyeo, StrongRemove};
    use std::sync::Arc;

    fn sk(seed: u8) -> edsign::SigningKey {
        edsign::SigningKey::from_seed(&[seed; 32])
    }
    fn vk(seed: u8) -> [u8; 32] {
        sk(seed).verifying_key().to_bytes()
    }
    fn minit(id: &str, role: KeyringRole, seed: u8) -> KeyringMemberInit {
        KeyringMemberInit {
            id: id.to_string(),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
        }
    }
    fn engine(members: &[KeyringMemberInit]) -> KeyringEngine {
        Keyeo::new(KeyringState::create(keyeo::GroupId::unscoped(), members), KeyringAccess, StrongRemove)
    }
    fn add(member: &str, role: KeyringRole, seed: u8) -> KeyringAction {
        MembershipAction::Add {
            member: member.to_string(),
            role,
            author_public_key: vk(seed),
            hpke_public_key: [seed; 32],
            member_proof: None,
        }
    }
    fn members(k: &KeyringEngine) -> Vec<String> {
        let mut m: Vec<String> = k.state().active_members().into_iter().map(|(id, _)| id).collect();
        m.sort();
        m
    }
    fn create(members: &[KeyringMemberInit]) -> KeyringAction {
        MembershipAction::Create {
            initial_members: members.to_vec(),
        }
    }

    #[test]
    fn op_codec_roundtrips() {
        let op = sign_op([2; 32], vec![[1; 32]], "founder", add("bob", KeyringRole::CO_OWNER, 2), &sk(1));
        let back = decode_op(&encode_op(&op)).unwrap();
        assert_eq!(op.id, back.id);
        assert_eq!(op.parents, back.parents);
        assert_eq!(op.author, back.author);
        assert_eq!(op.signature, back.signature);
        assert_eq!(op.author_public_key, back.author_public_key);
        // and it survives a Create (nested member list) + a Propose (recursive target)
        let gm = vec![minit("founder", KeyringRole::OWNER, 1)];
        let g = sign_op([1; 32], vec![], "founder", create(&gm), &sk(1));
        assert_eq!(decode_op(&encode_op(&g)).unwrap().id, g.id);
        let p = sign_op(
            [3; 32],
            vec![[1; 32]],
            "founder",
            MembershipAction::Propose {
                proposal_id: [7; 32],
                target: Box::new(add("x", KeyringRole::EDITOR, 9)),
            },
            &sk(1),
        );
        assert_eq!(decode_op(&encode_op(&p)).unwrap().id, p.id);
        // and a ReFound (retargets keys + an opaque rewrap blob) round-trips field-for-field
        let rf = sign_op(
            [4; 32],
            vec![[1; 32]],
            "founder",
            MembershipAction::ReFound {
                member: "founder".into(),
                new_author_public_key: vk(7),
                new_hpke_public_key: [7u8; 32],
                era: 3,
            },
            &sk(1),
        );
        let rf_back = decode_op(&encode_op(&rf)).unwrap();
        assert_eq!(rf_back.id, rf.id);
        assert_eq!(rf_back.action, rf.action, "ReFound survives the wire codec field-for-field");
        // and a recovery-authority rotation
        let rot = sign_op(
            [5; 32],
            vec![[1; 32]],
            "founder",
            MembershipAction::RotateRecoveryAuthority {
                new_reset_authority: vk(8),
            },
            &sk(1),
        );
        assert_eq!(
            decode_op(&encode_op(&rot)).unwrap().action,
            rot.action,
            "RotateRecoveryAuthority survives the wire codec"
        );
    }

    #[test]
    fn two_replicas_converge_over_blob() {
        let store = Arc::new(MemoryBlob::new());
        let gm = vec![minit("founder", KeyringRole::OWNER, 1)];
        let (mut ea, mut eb) = (engine(&gm), engine(&gm));
        let mut sa = KeyringBlobSync::new(store.clone());
        let mut sb = KeyringBlobSync::new(store.clone());

        let g = sign_op([1; 32], vec![], "founder", create(&gm), &sk(1));
        ea.apply(g.clone()).unwrap();
        sa.push(&g).unwrap();
        let ab = sign_op([2; 32], vec![[1; 32]], "founder", add("bob", KeyringRole::CO_OWNER, 2), &sk(1));
        ea.apply(ab.clone()).unwrap();
        sa.push(&ab).unwrap();

        sb.pull(&mut eb).unwrap();
        assert_eq!(members(&ea), members(&eb), "B converges to A over the blob store");
        assert!(members(&eb).contains(&"bob".to_string()));
    }

    #[test]
    fn a_fork_converges_and_both_survive() {
        // Genesis {founder, bob, carol}. bob adds dave on A while carol adds erin on B — concurrent ops
        // (both children of genesis) by DIFFERENT authors → a fork that merges (a node with two tips).
        let store = Arc::new(MemoryBlob::new());
        let gm = vec![
            minit("founder", KeyringRole::OWNER, 1),
            minit("bob", KeyringRole::CO_OWNER, 2),
            minit("carol", KeyringRole::CO_OWNER, 3),
        ];
        let (mut ea, mut eb) = (engine(&gm), engine(&gm));
        let mut sa = KeyringBlobSync::new(store.clone());
        let mut sb = KeyringBlobSync::new(store.clone());

        let g = sign_op([1; 32], vec![], "founder", create(&gm), &sk(1));
        for (e, s) in [(&mut ea, &mut sa), (&mut eb, &mut sb)] {
            e.apply(g.clone()).unwrap();
            s.push(&g).unwrap();
        }

        let dave = sign_op([2; 32], vec![[1; 32]], "bob", add("dave", KeyringRole::EDITOR, 4), &sk(2));
        ea.apply(dave.clone()).unwrap();
        sa.push(&dave).unwrap();
        let erin = sign_op([3; 32], vec![[1; 32]], "carol", add("erin", KeyringRole::EDITOR, 5), &sk(3));
        eb.apply(erin.clone()).unwrap();
        sb.push(&erin).unwrap();

        sa.pull(&mut ea).unwrap(); // A learns erin
        sb.pull(&mut eb).unwrap(); // B learns dave
        assert_eq!(members(&ea), members(&eb), "both replicas converge after the fork");
        let m = members(&ea);
        assert!(m.contains(&"dave".to_string()) && m.contains(&"erin".to_string()));
    }

    #[test]
    fn pull_detects_a_withheld_op_without_losing_local_state() {
        // Anti-rollback (OPE-269): a content-addressed op set can only be regressed by omission. A pull
        // reports any already-applied op the store no longer serves, and — because pull only ever adds to
        // the engine — the local resolved state is unaffected by the rollback attempt.
        let store = Arc::new(MemoryBlob::new());
        let gm = vec![minit("founder", KeyringRole::OWNER, 1)];
        let (mut ea, mut eb) = (engine(&gm), engine(&gm));
        let mut sa = KeyringBlobSync::new(store.clone());
        let mut sb = KeyringBlobSync::new(store.clone());

        let g = sign_op([1; 32], vec![], "founder", create(&gm), &sk(1));
        let ab = sign_op([2; 32], vec![[1; 32]], "founder", add("bob", KeyringRole::CO_OWNER, 2), &sk(1));
        ea.apply(g.clone()).unwrap();
        sa.push(&g).unwrap();
        ea.apply(ab.clone()).unwrap();
        sa.push(&ab).unwrap();

        // B pulls both — a complete listing withholds nothing.
        let clean = sb.pull(&mut eb).unwrap();
        assert!(clean.withheld.is_empty(), "a complete listing withholds nothing");
        assert!(members(&eb).contains(&"bob".to_string()));

        // The store drops the genesis op — a rollback attempt.
        store.delete(&op_key(&g.id), Precondition::Any).unwrap();
        let rolled = sb.pull(&mut eb).unwrap();
        assert_eq!(rolled.withheld, vec![g.id], "the dropped op is flagged as withheld");
        assert!(
            members(&eb).contains(&"bob".to_string()),
            "the local resolved state is unaffected — monotonicity holds, this is detection not loss"
        );
    }

    #[test]
    fn converges_over_the_local_fs_backend() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(blobstore::FsBlob::new(dir.path()));
        let gm = vec![minit("founder", KeyringRole::OWNER, 1)];
        let (mut ea, mut eb) = (engine(&gm), engine(&gm));
        let mut sa = KeyringBlobSync::new(store.clone());
        let mut sb = KeyringBlobSync::new(store.clone());

        let g = sign_op([1; 32], vec![], "founder", create(&gm), &sk(1));
        ea.apply(g.clone()).unwrap();
        sa.push(&g).unwrap();
        let ab = sign_op([2; 32], vec![[1; 32]], "founder", add("bob", KeyringRole::CO_OWNER, 2), &sk(1));
        ea.apply(ab.clone()).unwrap();
        sa.push(&ab).unwrap();

        sb.pull(&mut eb).unwrap();
        assert_eq!(members(&ea), members(&eb), "converges over FsBlob");
    }
}
