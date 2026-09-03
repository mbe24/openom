//! Keyeo engine.

use crate::access::{AccessControl, DefaultAccessControl};
use crate::blocklace::Graph;
use crate::dag::lamport::apply_action;
use crate::dag::resolver::{
    ApplyOutcome, Error, GroupState, MemberId, MembershipAction, MembershipEvent, Resolver,
    SignedOp,
};
use crate::epoch::{membership_commitment, reconcile_epochs, Epoch};
use crate::quorum::{Individual, QuorumPolicy};
use crate::Role;
use crate::SignatureScheme;
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
    /// The bounded fork-merge horizon (OPE-270): a stable compaction frontier below which the DAG will no
    /// longer accept a fork. Empty = no horizon (accept everything, the default). Set it to the frontier a
    /// compaction anchors to; thereafter an op that does not descend from it is rejected as a `StaleFork`.
    merge_horizon: Vec<Op::OpId>,
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
            merge_horizon: Vec::new(),
        }
    }

    /// Set the bounded fork-merge horizon to a stable frontier (OPE-270). After this, `apply` rejects any
    /// op that branches from before the frontier — one whose causal past does not include every horizon op
    /// — as a [`Error::StaleFork`], rather than merging it or buffering it forever. Anchored to the
    /// compaction frontier, this is the anti-rollback hygiene that stops a fork off pruned history from
    /// re-entering after the group has moved past it. Pass an empty frontier to clear the horizon.
    pub fn set_merge_horizon(&mut self, frontier: Vec<Op::OpId>) {
        self.merge_horizon = frontier;
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
            // The recovery-authorized ops (ReFound, RotateRecoveryAuthority) are self-certifying against
            // their carried key (the recovery key), like a Create: the signer is the recovery authority,
            // not the op's `author` member, so there is no registered member key to look up. Whether that
            // carried key IS the group's pinned recovery authority is decided in resolution
            // (`key_matches_registration`), replica-independently.
            MembershipAction::ReFound { .. } | MembershipAction::RotateRecoveryAuthority { .. } => {
                op.author_public_key()
            }
            _ => {
                // The author must be a known member — but verify against the op's OWN carried key, NOT
                // the member's currently-registered key (D3, retarget-tolerant authentication). A validly
                // self-signed op is admitted regardless of any later key retarget; whether the carried key
                // was the member's REGISTERED key at the op's causal position is decided in resolution
                // (`key_matches_registration`), so a late op signed under a since-rotated key resolves
                // identically on every replica instead of being admitted on some and rejected on others.
                let author = op.author();
                if !self.state.members.contains_key(author) {
                    return Err(Error::UnknownAuthor {
                        author: author.clone(),
                    });
                }
                op.author_public_key()
            }
        };
        // Recompute the canonical encoding from the op's OWN fields and verify the
        // signature over THAT — never trust a caller-supplied `canonical` blob.
        // This binds the signature to (id, parents, author, action), so a valid
        // (canonical, signature) pair can't be replayed onto a different action.
        let canonical = crate::canonical::canonical_encode(
            op.group_id(),
            op.parents(),
            op.author(),
            op.action(),
            op.sealing(),
        );
        <Op::S as SignatureScheme>::verify(pk, &canonical, op.signature())
            .map_err(|_| Error::BadSignature)
    }

    pub fn apply(&mut self, op: Op) -> ApplyResult<Op> {
        // 0. Group binding (first-class, resolver-enforced): refuse an op minted for a different group
        //    OUTRIGHT — never buffer or store it. The `group_id` is bound into the op's signed +
        //    content-addressed bytes, so this is a guarantee (an op for group A can never resolve into
        //    group B), not the incidental "foreign parents don't resolve". Checked against the immutable
        //    construction genesis, whose group_id is pinned at first sight. Vacuous when both are empty
        //    (keyeo's single-group / test callers), a hard gate once a caller assigns real group ids.
        if op.group_id() != &self.genesis.group_id {
            return Err(Error::WrongGroup);
        }

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

        // 2b. Bounded fork-merge horizon (OPE-270): once a stable frontier is set, every new op must
        //     build ON it — its causal past must include every horizon op. An op that branches from
        //     before the horizon (some horizon op is not an ancestor of any of its parents) is a stale
        //     fork / equivocation-rollback vector past the compaction frontier, and is rejected here
        //     rather than merged. Parents are already present (step 1), so ancestry is checkable now;
        //     a re-applied op already in the DAG is exempt (idempotent).
        if !self.merge_horizon.is_empty() && !self.ops.contains_key(&op.id()) {
            let descends = self.merge_horizon.iter().all(|h| {
                op.parents().iter().any(|p| p == h || self.graph.has_path(*h, *p))
            });
            if !descends {
                return Err(Error::StaleFork);
            }
        }

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

    /// The core resolution walk: apply all non-ignored ops in causal (topological) order, re-authorizing
    /// each at its causal position, and return BOTH the resolved membership state AND the ids of the ops
    /// that were **effective** (applied with effect), in topo order. Shared by [`Self::rebuild_state`] and
    /// [`Self::effective_ops`] so the resolution and the effectiveness report can never diverge.
    ///
    /// Ordering is a real topological sort over the op DAG (Kahn's algorithm), with OpId as a deterministic
    /// tiebreak among concurrent ops — NOT a plain OpId sort, which would misorder ops whenever OpIds
    /// aren't causally monotonic (e.g. content-hash or (peer,counter) ids). Authority is checked against
    /// the state built so far (the resolved state the op depends on), not only at local apply time where a
    /// concurrently-invalidated grant could still be seen. An op the resolver dropped can leave a later op
    /// inconsistent (e.g. removing a member whose add was ignored); in resolved causal order that is benign,
    /// so it is skipped (and reported as ineffective), never a failure.
    #[allow(clippy::type_complexity)]
    fn resolve_walk(
        &self,
    ) -> Result<(GroupState<Op::MemberId, Op::R, Op::S>, Vec<Op::OpId>), Error<Op::MemberId>> {
        let ignored = RS::ignored(&self.resolver_state);
        let order = self.topo_order()?;
        let mut new_state = self.genesis.clone();
        let mut effective = Vec::new();
        for op_id in &order {
            if ignored.contains(op_id) {
                continue;
            }
            let Some(op) = self.ops.get(op_id) else {
                continue;
            };
            // A Commit doesn't apply *itself* — it applies its proposal's TARGET, at this position, iff
            // the committer is authorized AND quorum has been met (Individual governance never meets
            // quorum, so this is inert by default). See `quorum_target`. It is effective iff its target
            // applied.
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
                            effective.push(*op_id);
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
                effective.push(*op_id);
            }
        }
        Ok((new_state, effective))
    }

    /// Rebuild state from scratch (via [`Self::resolve_walk`]), then rotate (or stabilize) the epoch for the
    /// resolved membership — so the epoch the group settles on is a function of the resolved membership and
    /// a peer that resolves the same membership converges to the same commitment.
    fn rebuild_state(&mut self) -> Result<(), Error<Op::MemberId>> {
        let (new_state, _effective) = self.resolve_walk()?;
        self.state = self.forge_epoch(&new_state)?;
        Ok(())
    }

    /// The op ids that were **effective** — applied with effect in the resolved state (not ignored /
    /// carve-out-voided, authorized at their causal position, and for a `Commit` its quorum met) — in
    /// resolved topological order. openom's sealing fold uses this so the sealing of a voided or
    /// ineffective op never applies, and so it folds in the same order the membership resolves. (OPE-273.)
    pub fn effective_ops(&self) -> Vec<Op::OpId> {
        self.resolve_walk().map(|(_, e)| e).unwrap_or_default()
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
        // Group gate: an epoch authored for a different group is refused before it can enter the candidate
        // set. Its `group_id` is part of the signed bytes (verified just above), so this checks an authentic
        // value — closing the cross-group DEK-transplant vector (two groups with an identical active
        // membership share a membership_commitment; the group gate is what keeps A's epoch out of B).
        if epoch.group_id != self.genesis.group_id {
            return Err(Error::WrongGroup);
        }
        // Structural: an epoch's parents must be ops this engine holds. `forge_epoch` tie-breaks candidates
        // by `parents.len()`, so an unchecked/forged parent set could steer reconciliation; requiring
        // parents ⊆ ops removes that lever.
        if !epoch.parents.iter().all(|p| self.ops.contains_key(p)) {
            return Err(Error::InvalidAction("epoch parents not in the DAG".into()));
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

    /// Whether the admitted op `op_id`'s author was authorized at its CAUSAL POSITION — see
    /// `dag::strong_remove::op_authorized_at_position`. `Some(false)` marks a
    /// permanently-ineffective op a transport may safely refuse (anti-spam); `Some(true)` an op that had
    /// authority at its position (it may still have lost a concurrent race, and that op must be kept).
    pub fn authorized_at_position(&self, op_id: &Op::OpId) -> Option<bool> {
        crate::dag::strong_remove::op_authorized_at_position(
            &self.genesis,
            &self.graph,
            &self.ops,
            &self.access,
            op_id,
        )
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
    Op: SignedOp<MemberId = MId, R = R, S = crate::Ed25519>,
    R: Role,
    MId: crate::dag::resolver::MemberId,
{
    Keyeo::new(
        state,
        DefaultAccessControl::new(min_role),
        crate::dag::strong_remove::StrongRemove,
    )
}
