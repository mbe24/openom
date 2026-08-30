//! Keyeo engine.

use crate::access::{AccessControl, DefaultAccessControl};
use crate::dag::graph::Graph;
use crate::dag::lamport::apply_action;
use crate::dag::resolver::{
    ApplyOutcome, Error, GroupState, MemberId, MembershipAction, MembershipEvent, Resolver,
    SignedOp,
};
use crate::epoch::{membership_commitment, reconcile_epochs, Epoch};
use crate::quorum::{Individual, QuorumPolicy};
use crate::roles::Role;
use crate::signature::SignatureScheme;
use std::collections::{HashMap, HashSet};

type ApplyResult<Op> = Result<
    ApplyOutcome<
        <Op as crate::dag::resolver::SignedOp>::MemberId,
        <Op as crate::dag::resolver::SignedOp>::OpId,
    >,
    Error<<Op as crate::dag::resolver::SignedOp>::MemberId>,
>;

type ForgeResult<Op> = Result<
    GroupState<
        <Op as crate::dag::resolver::SignedOp>::MemberId,
        <Op as crate::dag::resolver::SignedOp>::R,
        <Op as crate::dag::resolver::SignedOp>::S,
    >,
    Error<<Op as crate::dag::resolver::SignedOp>::MemberId>,
>;

pub struct Keyeo<Op, AC, RS, QP = Individual>
where
    Op: SignedOp,
    AC: AccessControl<Op::MemberId, Op::R, Op::S>,
    RS: Resolver<Op::OpId, Op::R, Op, Op::S>,
    QP: QuorumPolicy<Op::MemberId, Op::R, Op::S>,
{
    state: GroupState<Op::MemberId, Op::R, Op::S>,
    /// The base the causal rebuild replays onto — the state the engine was constructed with. A
    /// `Create` op in the DAG resets it; without one, this seeded genesis is the base (so rebuild
    /// never discards the members the caller started from).
    genesis: GroupState<Op::MemberId, Op::R, Op::S>,
    graph: Graph<Op::OpId>,
    ops: HashMap<Op::OpId, Op>,
    pending: Vec<Op>,
    access: AC,
    _resolver: RS,
    resolver_state: RS::State,
    events: Vec<MembershipEvent<Op::MemberId>>,
    max_pending: usize,
    /// Replicated epoch-artifact candidates (authored into the DAG). Reced on membership change. The
    /// engine reconciles them — filtered to the resolved active membership (strong-remove: a removed
    /// author's concurrent epoch is discarded) and tie-broken deterministically — to the single
    /// winning epoch, whose wraps are attached to the group state.
    replica_epochs: Vec<Epoch<Op::OpId, Op::MemberId, Op::S>>,
    genesis_epoch: u64,
    /// The multi-signer quorum policy (v2). `Individual` (the default) means no change needs quorum.
    quorum: QP,
}

impl<Op, AC, RS> Keyeo<Op, AC, RS, Individual>
where
    Op: SignedOp,
    AC: AccessControl<Op::MemberId, Op::R, Op::S>,
    RS: Resolver<Op::OpId, Op::R, Op, Op::S>,
{
    /// Construct with **Individual** governance — a single authorized action stands on its own, no quorum.
    pub fn new(state: GroupState<Op::MemberId, Op::R, Op::S>, access: AC, resolver: RS) -> Self {
        Self::with_quorum(state, access, resolver, Individual)
    }
}

impl<Op, AC, RS, QP> Keyeo<Op, AC, RS, QP>
where
    Op: SignedOp,
    AC: AccessControl<Op::MemberId, Op::R, Op::S>,
    RS: Resolver<Op::OpId, Op::R, Op, Op::S>,
    QP: QuorumPolicy<Op::MemberId, Op::R, Op::S>,
{
    /// Construct with a custom [`QuorumPolicy`] — v2 multi-signer (founder-or-unanimity) governance.
    pub fn with_quorum(
        state: GroupState<Op::MemberId, Op::R, Op::S>,
        access: AC,
        resolver: RS,
        quorum: QP,
    ) -> Self {
        Self {
            genesis: state.clone(),
            state,
            graph: Graph::new(),
            ops: HashMap::new(),
            pending: Vec::new(),
            access,
            _resolver: resolver,
            resolver_state: RS::State::default(),
            events: Vec::new(),
            max_pending: 1024,
            replica_epochs: Vec::new(),
            genesis_epoch: 0,
            quorum,
        }
    }

    fn authenticate(&self, op: &Op) -> Result<(), Error<Op::MemberId>> {
        let pk = match op.action() {
            MembershipAction::Create { initial_members } => {
                let author = op.author();
                let init = initial_members
                    .iter()
                    .find(|m| &m.id == author)
                    .ok_or_else(|| Error::UnknownAuthor {
                        author: author.clone(),
                    })?;
                &init.author_public_key
            }
            MembershipAction::Add { member, .. } if member == op.author() => op.author_public_key(),
            _ => {
                let author = op.author();
                self.state
                    .members
                    .get(author)
                    .map(|m| &m.author_public_key)
                    .ok_or_else(|| Error::UnknownAuthor {
                        author: author.clone(),
                    })?
            }
        };
        // Recompute the canonical encoding from the op's OWN fields and verify the
        // signature over THAT — never trust a caller-supplied `canonical` blob.
        // This binds the signature to (id, parents, author, action), so a valid
        // (canonical, signature) pair can't be replayed onto a different action.
        let canonical = crate::canonical::canonical_encode(op.parents(), op.author(), op.action());
        <Op::S as SignatureScheme>::verify(pk, &canonical, op.signature())
            .map_err(|_| Error::BadSignature)
    }

    pub fn apply(&mut self, op: Op) -> ApplyResult<Op> {
        // 1. Parents present? Otherwise buffer (bounded).
        let mut missing = Vec::new();
        for parent in op.parents() {
            if !self.ops.contains_key(parent) {
                missing.push(*parent);
            }
        }
        if !missing.is_empty() {
            if self.pending.len() >= self.max_pending {
                return Err(Error::InvalidAction("pending buffer full".into()));
            }
            self.pending.push(op);
            return Ok(ApplyOutcome::Buffered {
                missing_parents: missing,
            });
        }

        // 2. Authenticate — signature + known author. Authorization is deliberately NOT decided
        //    here: in a sequencer-free DAG a validly signed op may have been authorized in its own
        //    causal context even if a concurrent op has since changed the local view, so we cannot
        //    reject it up front (that made mutual/concurrent actions order-dependent). We admit it
        //    and let the resolver + causal rebuild decide its effect (admit-then-resolve).
        self.authenticate(&op)?;

        // 3. Admit to the DAG.
        let op_id = op.id();
        for parent in op.parents() {
            self.graph.add_edge(*parent, op_id);
        }
        self.ops.insert(op_id, op);

        // 4. Recompute the authoritative state: run the resolver (ignore-set) and rebuild in causal
        //    order, authorizing each op at its causal position. Events are the diff of the resolved
        //    active membership — an op that was admitted but is unauthorized/superseded simply
        //    produces no event.
        let before = self.state.active_members();
        self.resolver_state = RS::process(
            std::mem::take(&mut self.resolver_state),
            &self.graph,
            &self.ops,
            &self.access,
            &self.genesis,
        )
        .map_err(|e| Error::InvalidAction(format!("resolver: {:?}", e)))?;
        self.rebuild_state()?;
        let after = self.state.active_members();

        let events = diff_events(&before, &after);
        self.events.extend(events.clone());
        Ok(ApplyOutcome::Applied { events })
    }

    /// Flush pending ops — repeatedly try until no more can be applied.
    pub fn flush(&mut self) -> Result<Vec<MembershipEvent<Op::MemberId>>, Error<Op::MemberId>> {
        let mut all_events = Vec::new();
        loop {
            let mut applied_any = false;
            let mut remaining = Vec::new();
            for op in std::mem::take(&mut self.pending) {
                match self.apply(op.clone()) {
                    Ok(ApplyOutcome::Applied { events }) => {
                        all_events.extend(events);
                        applied_any = true;
                    }
                    Ok(ApplyOutcome::Buffered { .. }) => remaining.push(op),
                    Err(e) => return Err(e),
                }
            }
            self.pending = remaining;
            if !applied_any {
                break;
            }
        }
        Ok(all_events)
    }

    pub fn state(&self) -> &GroupState<Op::MemberId, Op::R, Op::S> {
        &self.state
    }
    pub fn events(&mut self) -> Vec<MembershipEvent<Op::MemberId>> {
        std::mem::take(&mut self.events)
    }

    /// Rebuild state from scratch by applying all non-ignored ops in causal
    /// (topological) order, so the resolver's ignore decisions take effect.
    ///
    /// Ordering is a real topological sort over the op DAG (Kahn's algorithm),
    /// with OpId as a deterministic tiebreak among concurrent ops — NOT a plain
    /// OpId sort, which would misorder ops whenever OpIds aren't causally
    /// monotonic (e.g. content-hash or (peer,counter) ids). Apply errors are
    /// surfaced, not swallowed: in correct causal order an error is a genuine
    /// conflict (or a resolver bug), never something to silently drop.
    fn rebuild_state(&mut self) -> Result<(), Error<Op::MemberId>> {
        let ignored = RS::ignored(&self.resolver_state);
        let order = self.topo_order()?;

        // Replay non-ignored ops in causal order, re-authorizing each at its causal position: the
        // state built so far IS the resolved state the op depends on, so authority is checked here
        // (not only at local apply time, where a concurrently-invalidated grant could still be seen).
        // An op the resolver dropped can leave a later op inconsistent (e.g. removing a member whose
        // add was ignored); in resolved causal order that is benign, so skip it rather than fail.
        let mut new_state = self.genesis.clone();
        for op_id in &order {
            if ignored.contains(op_id) {
                continue;
            }
            let Some(op) = self.ops.get(op_id) else {
                continue;
            };
            // A Commit doesn't apply *itself* — it applies its proposal's TARGET, at this position, iff
            // the committer is authorized AND quorum has been met (Individual governance never meets
            // quorum, so this is inert by default). See `quorum_target`.
            if let MembershipAction::Commit { proposal_id } = op.action() {
                let pid = *proposal_id;
                if self
                    .access
                    .is_authorized(&new_state, op.author(), op.action())
                {
                    let mut visiting = HashSet::new();
                    visiting.insert(*op_id);
                    if let Some(target) = self.quorum_target(*op_id, &pid, &ignored, &mut visiting) {
                        if let Ok((s, _events)) = apply_action(new_state.clone(), &target) {
                            new_state = s;
                        }
                    }
                }
                continue;
            }
            if !self
                .access
                .is_authorized(&new_state, op.author(), op.action())
            {
                continue;
            }
            if let Ok((s, _events)) = apply_action(new_state.clone(), op.action()) {
                new_state = s;
            }
        }
        // Rotate (or stabilize) the epoch for the resolved membership: derive its commitment, and
        // either reuse the cached epoch (stable membership -> no churn) or mint a fresh one (the
        // membership changed -> rotate the DEK to the new active set). Wired into the DAG's rebuild
        // path, so the epoch the group settles on is a function of the resolved membership, and a
        // peer that resolves the same membership converges to the same commitment.
        self.state = self.forge_epoch(&new_state)?;
        Ok(())
    }

    /// Kahn's topological sort over all admitted ops, with `OpId` as a deterministic tiebreak among
    /// concurrent ops — a real topo sort, NOT a plain OpId sort (which misorders whenever OpIds aren't
    /// causally monotonic, e.g. content-hash ids). Errors as `DagCycle` if the ops don't form a DAG.
    fn topo_order(&self) -> Result<Vec<Op::OpId>, Error<Op::MemberId>> {
        let mut indegree: HashMap<Op::OpId, usize> = HashMap::new();
        let mut children: HashMap<Op::OpId, Vec<Op::OpId>> = HashMap::new();
        for (id, op) in &self.ops {
            indegree.entry(*id).or_insert(0);
            for p in op.parents() {
                if self.ops.contains_key(p) {
                    *indegree.entry(*id).or_insert(0) += 1;
                    children.entry(*p).or_default().push(*id);
                }
            }
        }
        let mut ready: std::collections::BTreeSet<Op::OpId> = indegree
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(id, _)| *id)
            .collect();
        let mut order: Vec<Op::OpId> = Vec::with_capacity(self.ops.len());
        while let Some(&next) = ready.iter().next() {
            ready.remove(&next);
            order.push(next);
            if let Some(cs) = children.get(&next) {
                for c in cs {
                    if let Some(d) = indegree.get_mut(c) {
                        *d -= 1;
                        if *d == 0 {
                            ready.insert(*c);
                        }
                    }
                }
            }
        }
        if order.len() != self.ops.len() {
            return Err(Error::DagCycle);
        }
        Ok(order)
    }

    /// The resolved membership of every surviving op that is **not causally after** `pivot` — the pivot's
    /// causal past PLUS everything concurrent with it. Folded in topological order, resolving any `Commit`
    /// in that set via [`Self::quorum_target`]. `visiting` guards cyclic concurrent commits: a re-entered
    /// commit is treated as not-yet-applied (fail-closed, so a pathological cycle can't inflate authority).
    ///
    /// This is the state a proposal's *denominator* is measured against: because inclusion is a **causal**
    /// test (`has_path`), not a topo-order position, a signer added concurrently with the proposal still
    /// counts — the proposal can't be backdated onto a branch where the signer set was smaller.
    fn resolved_state_excluding_after(
        &self,
        pivot: Op::OpId,
        ignored: &HashSet<Op::OpId>,
        visiting: &mut HashSet<Op::OpId>,
    ) -> GroupState<Op::MemberId, Op::R, Op::S> {
        let Ok(order) = self.topo_order() else {
            return self.genesis.clone();
        };
        let mut state = self.genesis.clone();
        for op_id in &order {
            if ignored.contains(op_id) || self.graph.has_path(pivot, *op_id) {
                continue; // ignored, or causally AFTER the pivot -> not part of its denominator
            }
            let Some(op) = self.ops.get(op_id) else {
                continue;
            };
            if let MembershipAction::Commit { proposal_id } = op.action() {
                let pid = *proposal_id;
                if self.access.is_authorized(&state, op.author(), op.action())
                    && visiting.insert(*op_id)
                {
                    if let Some(target) = self.quorum_target(*op_id, &pid, ignored, visiting) {
                        if let Ok((s, _)) = apply_action(state.clone(), &target) {
                            state = s;
                        }
                    }
                    visiting.remove(op_id);
                }
                continue;
            }
            if !self.access.is_authorized(&state, op.author(), op.action()) {
                continue;
            }
            if let Ok((s, _)) = apply_action(state.clone(), op.action()) {
                state = s;
            }
        }
        state
    }

    /// For a `Commit` at `commit_id` referencing `proposal_id`, return the proposal's target action iff
    /// quorum is met. Finds the surviving `Propose` for that id in the Commit's causal past, asks the
    /// [`QuorumPolicy`] who's eligible + what's required, tallies the DISTINCT eligible approvers (the
    /// proposer approves implicitly + every surviving `Approve` in the Commit's ancestry), and checks the
    /// requirement — fail-closed.
    ///
    /// The **denominator** (eligible set + requirement) is measured at the *Propose's* causal position via
    /// [`Self::resolved_state_excluding_after`], NOT the Commit's — so it's tiebreak-independent and a
    /// concurrently-added signer can't be excluded by DAG-shape/OpId grinding (the backdating defence). The
    /// **numerator** (approvals) is measured in the Commit's causal past, where the approvals actually are.
    ///
    /// Coupling note (for the unified-engine question): this is generic over `State` — it reads only the
    /// op DAG (`ops`/`graph`) and delegates every membership judgement to `self.quorum`. It never reads
    /// roles. Its one coupling is matching the `MembershipAction::{Propose,Approve,Commit}` variants,
    /// which on a generalized engine become a `QuorumOp` trait — an op-type coupling, not a state leak.
    fn quorum_target(
        &self,
        commit_id: Op::OpId,
        proposal_id: &[u8; 32],
        ignored: &HashSet<Op::OpId>,
        visiting: &mut HashSet<Op::OpId>,
    ) -> Option<MembershipAction<Op::MemberId, Op::R, Op::S>> {
        // The surviving Propose for this id, causally before the Commit.
        let (propose_id, target) = self.ops.iter().find_map(|(id, op)| match op.action() {
            MembershipAction::Propose { proposal_id: pid, target }
                if pid == proposal_id && !ignored.contains(id) && self.graph.has_path(*id, commit_id) =>
            {
                Some((*id, (**target).clone()))
            }
            _ => None,
        })?;
        let proposer = self.ops.get(&propose_id)?.author().clone();

        // Denominator at the Propose's causal position (see the doc comment): who is a signer, and what
        // quorum is required, as of everything not causally after the proposal.
        let state = self.resolved_state_excluding_after(propose_id, ignored, visiting);

        let eligible = self.quorum.eligible(&state, &target);
        // A proposal by a non-eligible member is void (only a signer may propose).
        if !eligible.contains(&proposer) {
            return None;
        }
        let requirement = self.quorum.requirement(&state, &target);

        // Distinct eligible approvers: the proposer approves implicitly + every surviving `Approve` for
        // this proposal in the Commit's causal past.
        let mut approvers: HashSet<Op::MemberId> = HashSet::new();
        approvers.insert(proposer);
        for (id, op) in &self.ops {
            if let MembershipAction::Approve { proposal_id: pid } = op.action() {
                if pid == proposal_id && !ignored.contains(id) && self.graph.has_path(*id, commit_id) {
                    let a = op.author().clone();
                    if eligible.contains(&a) {
                        approvers.insert(a);
                    }
                }
            }
        }

        requirement.satisfied_by(&approvers).then_some(target)
    }

    /// Attach the correct epoch key material to a resolved state. The commitment is derived from the
    /// active membership (deterministic under arrival order). Candidates are filtered by the resolved
    /// membership — a concurrent epoch authored by a member no longer active is discarded (the
    /// strong-remove semantic: an eviction invalidates its author's concurrent rotations) — and the
    /// survivors are reconciled deterministically to a single winner. That winner's wraps are the
    /// group's current key material: every replica that has replicated the same candidates resolves
    /// to the same DEK.
    fn forge_epoch(&mut self, state: &GroupState<Op::MemberId, Op::R, Op::S>) -> ForgeResult<Op>
    where
        Op::MemberId: MemberId,
    {
        let active = state.active_with_keys();
        if active.is_empty() {
            return Ok(state.clone()); // nothing to wrap to
        }
        let active_ids: std::collections::HashSet<&Op::MemberId> =
            active.iter().map(|(id, _, _)| id).collect();
        let active_id_vec: Vec<Op::MemberId> = active.iter().map(|(id, _, _)| id.clone()).collect();
        let commitment = membership_commitment(&active);

        // Candidate epochs must, against the RESOLVED membership:
        //   - be for this membership (same commitment) and authored by a still-active member;
        //   - carry the author's *registered* key, not a self-asserted one (G-E2 anti-spoof) — an
        //     ingest-time signature check (G-E1) only proves the artifact matches its own claimed key,
        //     so authority is decided here, where we know each member's registered key;
        //   - wrap the DEK to exactly the active set (G-E3) — no locked-out member, no ghost wrap to a
        //     non-member.
        // A removed member's concurrent epoch is filtered out by the active-author check (the
        // strong-remove semantic: an eviction invalidates its author's concurrent rotations).
        let candidates: Vec<Epoch<Op::OpId, Op::MemberId, Op::S>> = self
            .replica_epochs
            .iter()
            .filter(|e| {
                e.commitment == commitment
                    && active_ids.contains(&e.author)
                    && state
                        .members
                        .get(&e.author)
                        .map(|m| m.author_public_key == e.author_public_key)
                        .unwrap_or(false)
                    && crate::epoch::wraps_complete(&e.wraps, &active_id_vec)
            })
            .cloned()
            .collect();

        match reconcile_epochs(&candidates) {
            Some(winner) => {
                Ok(state
                    .clone()
                    .with_epoch(winner.epoch, winner.commitment, winner.wraps.clone()))
            }
            None => {
                // No replicated epoch covers this membership yet (e.g. a caller that never authors
                // epochs): fall back to a stable genesis epoch with no wraps rather than failing.
                Ok(state
                    .clone()
                    .with_epoch(self.genesis_epoch, commitment, Vec::new()))
            }
        }
    }

    /// Add an authored epoch artifact to the replicated candidate set. Callers author an `Epoch`
    /// (via `Epoch::author`) when the membership rotates and hand it here to the engine; replicas
    /// reconcile the accumulated candidates on rebuild.
    ///
    /// Ingest verifies the epoch's **author signature** over its canonical content (goal G-E1):
    /// a bad-signature artifact is rejected with [`Error::BadSignature`] and never enters the
    /// candidate set, so it can't win reconciliation. Authority — that this key is the author
    /// member's *registered* key (G-E2) and that the wraps are complete (G-E3) — is enforced later,
    /// against the resolved membership, in `forge_epoch`. Accepting a new candidate re-runs the
    /// resolver so the group re-forges its epoch immediately.
    pub fn apply_epoch(
        &mut self,
        epoch: Epoch<Op::OpId, Op::MemberId, Op::S>,
    ) -> Result<(), Error<Op::MemberId>> {
        if !crate::epoch::verify_epoch::<Op::OpId, Op::MemberId, Op::S>(&epoch) {
            return Err(Error::BadSignature);
        }
        if !self.replica_epochs.iter().any(|e| e.id == epoch.id) {
            self.replica_epochs.push(epoch);
            self.rebuild_state()?;
        }
        Ok(())
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Membership events for one `apply` = the diff between the resolved active set before and after.
/// An op that was admitted but is unauthorized or superseded yields no event.
fn diff_events<Id: MemberId, R: Role>(
    before: &[(Id, R)],
    after: &[(Id, R)],
) -> Vec<MembershipEvent<Id>> {
    let bmap: std::collections::HashMap<&Id, &R> = before.iter().map(|(i, r)| (i, r)).collect();
    let amap: std::collections::HashMap<&Id, &R> = after.iter().map(|(i, r)| (i, r)).collect();
    let mut events = Vec::new();
    for (id, role) in after {
        match bmap.get(id) {
            None => events.push(MembershipEvent::MemberAdded { member: id.clone() }),
            Some(prev) if *prev != role => {
                events.push(MembershipEvent::RoleChanged { member: id.clone() })
            }
            _ => {}
        }
    }
    for (id, _) in before {
        if !amap.contains_key(id) {
            events.push(MembershipEvent::MemberRemoved { member: id.clone() });
        }
    }
    events
}

pub type StandardKeyeo<Op, R, RS = crate::dag::strong_remove::StrongRemove> =
    Keyeo<Op, DefaultAccessControl<R>, RS>;

pub fn keyeo<Op, R, MId>(
    state: GroupState<MId, R>,
    min_role: R,
) -> Keyeo<Op, DefaultAccessControl<R>, crate::dag::strong_remove::StrongRemove>
where
    Op: SignedOp<MemberId = MId, R = R, S = crate::signature::Ed25519>,
    R: Role,
    MId: crate::dag::resolver::MemberId,
{
    Keyeo::new(
        state,
        DefaultAccessControl::new(min_role),
        crate::dag::strong_remove::StrongRemove,
    )
}
