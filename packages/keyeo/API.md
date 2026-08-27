# keyeo API Reference

## Overview

`keyeo` is a decentralised group membership and access control library. It provides:
- A signed-operation DAG with pluggable concurrency resolution (LamportTiebreak / StrongRemove)
- Ed25519 signature verification bound to stored keys (no forgeable author fields)
- Pluggable access control (DefaultAccessControl with configurable min_role, or DynAccessControl)
- Pluggable signature schemes (Ed25519 default, custom via `SignatureScheme` trait)

## Design principles

1. **Library owns authentication** — signature verification is internal, not delegated to the caller.
2. **Authorization is a policy trait** — `AccessControl` separates "who is this?" from "are they allowed?"
3. **Domain-agnostic** — no built-in role model. Define your own `Role` (Owner/Writer/Reader or anything else).
4. **OpId ≠ MemberId** — operation identifiers (DAG nodes) are cheap `Copy` types; member identifiers have no `Copy` bound.

## Quick start

```rust
use keyeo::*;

// 1. Define your role model
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
enum MyRole { Admin, Editor, Viewer }
impl Role for MyRole {
    fn grants_at_least(&self, other: &Self) -> bool {
        use MyRole::*;
        match (self, other) { (Admin, _) => true, (Editor, Editor|Viewer) => true, (Viewer, Viewer) => true, _ => false }
    }
}

// 2. Define your op type
struct MyOp { /* ... */ }
impl SignedOp for MyOp {
    type S = Ed25519;
    type OpId = u64;
    type MemberId = [u8; 32];
    type R = MyRole;
    // ...
}

// 3. Create state and engine
let state = GroupState::<[u8; 32], MyRole, Ed25519>::create(&[
    MemberInit { id: alice_id, role: MyRole::Admin, author_public_key: [..; 32], hpke_public_key: [..; 32] },
]);
let mut k = Keyeo::new(state, DefaultAccessControl::new(MyRole::Admin), LamportTiebreak);
let outcome = k.apply(my_op)?;
```

use std::collections::HashSet;


## Concrete `Op` struct

Most callers don't need to implement `SignedOp` — the library provides a ready-made `Op<OId, MId, R, S>`:

```rust
pub struct Op<OId: OpId, MId: MemberId, R: Role, S: SignatureScheme = Ed25519> {
    pub id: OId,
    pub parents: Vec<OId>,
    pub author: MId,
    pub action: MembershipAction<MId, R, S>,
    pub signature: S::Signature,
    pub canonical: Vec<u8>,
    pub author_public_key: S::PublicKey,
}
```

Identity, equality, hashing, and ordering are defined by `id` alone — so `Op` works with any `Role` without requiring `R: Ord`.

```rust
// Construct with the positional helper:
let op = Op::new(id, parents, author, action, signature, canonical, author_public_key);
// Or set the public fields directly.
```

Implement `SignedOp` on your own type only when you need a custom backing representation — e.g. an op stored inside a Loro doc whose `canonical_bytes` borrow from the CRDT without copying, a foreign op type you are bridging, or an op carrying extra domain fields.

## Core traits

### `SignatureScheme`

```rust
pub trait SignatureScheme: Debug + Clone + PartialEq + Eq + Send + Sync {
    type PublicKey: Debug + Clone + Eq + Hash + Ord + Send + Sync;
    type Signature: Debug + Clone + Eq + Hash + Ord + Send + Sync;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<(), SigError>;
}
```

Default: `Ed25519` (struct-level default on `MemberState`, `GroupState`).

### `SignedOp`

```rust
pub trait SignedOp: Debug + Clone + Eq + Hash + Ord {
    type S: SignatureScheme;
    type OpId: OpId;
    type MemberId: MemberId;
    type R: Role;
    fn id(&self) -> Self::OpId;
    fn parents(&self) -> &[Self::OpId];
    fn author(&self) -> &Self::MemberId;
    fn action(&self) -> &MembershipAction<Self::MemberId, Self::R, Self::S>;
    fn signature(&self) -> &<Self::S as SignatureScheme>::Signature;
    fn canonical_bytes(&self) -> &[u8];
    fn author_public_key(&self) -> &<Self::S as SignatureScheme>::PublicKey;
}
```

### `Role`

```rust
pub trait Role: Clone + Debug + Eq + Hash + Send + Sync {
    fn grants_at_least(&self, other: &Self) -> bool;
}
```

### `AccessControl`

```rust
pub trait AccessControl<Id: MemberId, R: Role, S: SignatureScheme>: Send + Sync {
    fn is_authorized(&self, state: &GroupState<Id, R, S>, author: &Id, action: &MembershipAction<Id, R, S>) -> bool;
}
```

Default: `DefaultAccessControl<R>` (requires a min_role constructor arg). Multi-tenant: `DynAccessControl` (closure-based).

### `Resolver`

```rust
pub trait Resolver<OId: OpId, R: Role, Op: SignedOp<R = R, S = S>, S: SignatureScheme> {
    type State: Default;
    type Error: Debug;
    fn rebuild_required(state: &Self::State, op: &Op, heads: &HashSet<OId>) -> bool;
    fn process(state: Self::State, graph: &Graph<OId>, ops: &HashMap<OId, Op>, ac: &impl AccessControl<Op::MemberId, R, S>)
        -> Result<Self::State, Self::Error>;
    fn ignored(state: &Self::State) -> HashSet<u64>;
}
```

Built-in: `LamportTiebreak` (fast), `StrongRemove` (correct, currently a basic stub).

## Concrete types

### `MembershipAction`

```rust
pub enum MembershipAction<Id: MemberId, R: Role, S: SignatureScheme> {
    Create { initial_members: Vec<MemberInit<Id, R, S>> },
    Add { member: Id, role: R, author_public_key: S::PublicKey, hpke_public_key: [u8; 32], member_proof: Option<S::Signature> },
    Remove { member: Id },
    ChangeRole { member: Id, new_role: R },
}
```

### `MemberInit`

```rust
pub struct MemberInit<Id: MemberId, R: Role, S: SignatureScheme = Ed25519> {
    pub id: Id, pub role: R, pub author_public_key: S::PublicKey, pub hpke_public_key: [u8; 32],
}
```

### `MemberState`

```rust
pub struct MemberState<R: Role, S: SignatureScheme = Ed25519> {
    pub role: R, pub member_counter: u64, pub access_counter: u64,
    pub author_public_key: S::PublicKey, pub hpke_public_key: [u8; 32],
}
```

### `GroupState`

```rust
pub struct GroupState<Id: Eq + Hash, R: Role, S: SignatureScheme = Ed25519> {
    pub members: HashMap<Id, MemberState<R, S>>,
}
```

### `Keyeo` engine

```rust
pub struct Keyeo<Op, AC, RS> { /* ... */ }

impl<Op, AC, RS> Keyeo<Op, AC, RS> {
    pub fn new(state: GroupState<Op::MemberId, Op::R, Op::S>, access: AC, resolver: RS) -> Self;
    pub fn apply(&mut self, op: Op) -> Result<ApplyOutcome<Op::MemberId>, Error<Op::MemberId>>;
    pub fn flush(&mut self) -> Result<Vec<MembershipEvent<Op::MemberId>>, Error<Op::MemberId>>;
    pub fn state(&self) -> &GroupState<Op::MemberId, Op::R, Op::S>;
    pub fn events(&mut self) -> Vec<MembershipEvent<Op::MemberId>>;
    pub fn pending_count(&self) -> usize;
}
```

### `ApplyOutcome`

```rust
pub enum ApplyOutcome<Id: MemberId> {
    Applied { events: Vec<MembershipEvent<Id>> },
    Buffered { missing_parents: Vec<Id> },
}
```

### `Error`

```rust
pub enum Error<Id: Debug + Clone> {
    BadSignature, UnknownAuthor { author: Id }, Unauthorized { author: Id },
    InvalidAction(String), MissingParents(Vec<Id>), DagCycle, Crypto(String),
}
```

## Type aliases and free functions

```rust
pub type StandardKeyeo<Op, R, RS = LamportTiebreak> = Keyeo<Op, DefaultAccessControl<R>, RS>;

/// Convenience helper for the common case (Ed25519 + LamportTiebreak).
pub fn keyeo<Op, R, MId>(state: GroupState<MId, R>, min_role: R) -> Keyeo<Op, DefaultAccessControl<R>, LamportTiebreak>;
```