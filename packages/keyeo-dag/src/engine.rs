//! Keyeo engine.

use crate::access::{AccessControl, DefaultAccessControl};
use crate::blocklace::Graph;
use crate::dag::lamport::apply_action;
use crate::dag::resolver::{
    ApplyOutcome, Error, GroupState, MemberId, MembershipAction, MembershipEvent, Resolver,
    SignedOp,
};
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
    /// The multi-signer quorum policy (v2). `Individual` (the default) means no change needs quorum.
    quorum: QP,
    /// The bounded fork-merge horizon (OPE-270): a stable compaction frontier below which the DAG will no
    /// longer accept a fork. Empty = no horizon (accept everything, the default). Set it to the frontier a
    /// compaction anchors to; thereafter an op that does not descend from it is rejected as a `StaleFork`.
    merge_horizon: Vec<Op::OpId>,
    /// An adopted checkpoint's frontier op-ids (empty for a normal engine). Present-but-not-replayed causal
    /// roots: `apply`'s parent-presence check treats them as satisfied so retained ops attach instead of
    /// buffering, but they are absent from `ops`, so the resolver never replays them — their effect is already
    /// baked into the base state. Seeded by [`Self::adopt`].
    base_frontier: HashSet<Op::OpId>,
    /// Absolute lamport depths of the adopted checkpoint's frontier ops — threaded to the resolver's depth
    /// tiebreak (via [`crate::dag::resolver::Resolver::seed_base`]) and to position-authorization queries, so
    /// the retained tail resolves as it would on a full-history replica. Empty for a normal engine.
    base_depths: HashMap<Op::OpId, usize>,
    /// Whether the group had EVER been shared as of the adopted checkpoint. Carried because the founding/
    /// sharing `Add` is pruned below the cut, so [`Self::has_been_shared`]'s effective-Add scan over `ops`
    /// can't see it (it would wrongly regress to `false` on a compacted replica). OR'd into the result.
    /// `false` for a normal engine.
    base_has_been_shared: bool,
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
            quorum,
            merge_horizon: Vec::new(),
            base_frontier: HashSet::new(),
            base_depths: HashMap::new(),
            base_has_been_shared: false,
        }
    }

    /// Construct from an ADOPTED CHECKPOINT: `base_state` is the resolved membership at a pruned frontier,
    /// `base_frontier_depths` maps each frontier op-id to its absolute lamport depth, and `has_been_shared` is
    /// the checkpoint's carried shared-marker (the founding/sharing `Add` is pruned, so it must be supplied —
    /// see [`Self::has_been_shared`]). The frontier ops are seeded as present-but-not-replayed causal roots —
    /// `apply` accepts retained ops that parent on them (instead of buffering), the resolver never replays them
    /// (their effect is already in `base_state`), and the depth seed keeps the strong-remove tiebreak matching
    /// a full-history replica. The frontier is also set as the merge horizon (OPE-270), so a fork branching
    /// from BELOW the cut is refused as a `StaleFork`.
    ///
    /// SAFETY: the caller must supply a DOMINATING cut — every retained op descends from every frontier tip
    /// (the same condition [`Compaction::compact`](keyeo_core::Compaction::compact) enforces at author time).
    ///
    /// NOTE: this preserves MEMBERSHIP + the shared-marker, matching openom's members-only checkpoint. The
    /// keyring's DEK material rides the op's opaque `sealing` envelope (folded by the consumer), not
    /// `GroupState`, so nothing epoch-related needs seeding here.
    pub fn adopt(
        base_state: GroupState<Op::MemberId, Op::R, Op::S>,
        base_frontier_depths: HashMap<Op::OpId, usize>,
        has_been_shared: bool,
        access: AC,
        resolver: RS,
        quorum: QP,
    ) -> Self {
        let base_frontier: HashSet<Op::OpId> = base_frontier_depths.keys().copied().collect();
        let mut graph = Graph::new();
        for id in &base_frontier {
            graph.add_node(*id); // a causal root — retained ops attach here, its ancestry is pruned
        }
        let resolver_state = RS::seed_base(RS::State::default(), base_frontier_depths.clone());
        Self {
            genesis: base_state.clone(),
            state: base_state,
            graph,
            ops: HashMap::new(),
            pending: Vec::new(),
            access,
            _resolver: resolver,
            resolver_state,
            events: Vec::new(),
            max_pending: 1024,
            quorum,
            merge_horizon: base_frontier.iter().copied().collect(),
            base_frontier,
            base_depths: base_frontier_depths,
            base_has_been_shared: has_been_shared,
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

    /// Apply one op: verify it, bind its group, and fold it (buffering it if its causal parents are absent).
    ///
    /// # Errors
    /// Returns [`Error`] if the op is bound to a different group, has a bad signature, or is otherwise
    /// invalid or unauthorized for its causal position.
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

        // 1. Parents present? Otherwise buffer (bounded). A parent that is an adopted checkpoint's frontier op
        //    counts as PRESENT (present-but-not-replayed): retained ops attach to it even though its pruned
        //    ancestry is gone, so they must not buffer forever waiting for an op that will never arrive.
        let mut missing = Vec::new();
        for parent in op.parents() {
            if !self.ops.contains_key(parent) && !self.base_frontier.contains(parent) {
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

        // 2b. Bounded fork-merge horizon (OPE-270): once a stable frontier is set, a new op must build ON the
        //     frontier — descend from AT LEAST ONE horizon tip. An op that descends from NO tip branches from
        //     BELOW the frontier (a stale fork / equivocation-rollback past the compaction cut) and is
        //     rejected. `.any()` (not `.all()`): a MULTI-tip frontier (an adopted checkpoint over concurrent
        //     tips) must still allow an op that continues just ONE branch — requiring descent from EVERY tip
        //     would force an immediate merge and wrongly reject legitimate concurrent authorship. A genuinely
        //     pruned-history fork can't reach here anyway: its parent is absent, so step 1 buffers it. Parents
        //     are present (step 1), so ancestry is checkable; a re-applied op already in the DAG is exempt.
        if !self.merge_horizon.is_empty() && !self.ops.contains_key(&op.id()) {
            let descends = self.merge_horizon.iter().any(|h| {
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
        .map_err(|e| Error::InvalidAction(format!("resolver: {e:?}")))?;
        self.rebuild_state()?;
        let after = self.state.active_members();

        let events = diff_events(&before, &after);
        self.events.extend(events.clone());
        Ok(ApplyOutcome::Applied { events })
    }

    /// Flush pending ops — repeatedly try until no more can be applied.
    ///
    /// # Errors
    /// Returns [`Error`] if applying a now-eligible pending op fails.
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

    pub const fn state(&self) -> &GroupState<Op::MemberId, Op::R, Op::S> {
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
    /// Ordering is a real topological sort over the op DAG (Kahn's algorithm), with `OpId` as a deterministic
    /// tiebreak among concurrent ops — NOT a plain `OpId` sort, which would misorder ops whenever `OpIds`
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

    /// Rebuild state from scratch (via [`Self::resolve_walk`]) — the resolved membership a peer converges to.
    fn rebuild_state(&mut self) -> Result<(), Error<Op::MemberId>> {
        let (new_state, _effective) = self.resolve_walk()?;
        self.state = new_state;
        Ok(())
    }

    /// The op ids that were **effective** — applied with effect in the resolved state (not ignored /
    /// carve-out-voided, authorized at their causal position, and for a `Commit` its quorum met) — in
    /// resolved topological order. openom's sealing fold uses this so the sealing of a voided or
    /// ineffective op never applies, and so it folds in the same order the membership resolves. (OPE-273.)
    pub fn effective_ops(&self) -> Vec<Op::OpId> {
        self.resolve_walk().map(|(_, e)| e).unwrap_or_default()
    }

    /// The absolute lamport depth of every op — the engine's OWN `compute_depths` (`1 + max(parent depths)`),
    /// so a checkpoint author records the exact values the strong-remove tiebreak uses (not a reimplementation
    /// that could drift). A frontier tip's depth is purely ancestral, so it is identical whether computed here
    /// (over the whole op set) or over just the pre-cut ops — the property `Keyeo::adopt`'s `frontier_depths`
    /// seed relies on.
    pub fn op_depths(&self) -> HashMap<Op::OpId, usize> {
        crate::dag::strong_remove::compute_depths(&self.ops, &self.base_depths)
    }

    /// Whether this group HAS EVER been shared beyond its founder — i.e. any EFFECTIVE `Add` op exists.
    /// MONOTONIC: an effective Add stays effective after the member is removed (a `Remove` is a separate
    /// op, it doesn't un-effect the Add), so this never regresses to false. This is the dag's analog of the
    /// chain's `first_shared_revision != 0`: the gate for attributed writes. Scan-backed while nothing is
    /// pruned; a compaction checkpoint carries the marker (in the `Compacted` decision) so it survives pruning.
    /// (Assumes
    /// a solo genesis — openom's `Create` always has one initial member; a co-founder genesis would need the
    /// Create's `initial_members.len() > 1` folded in too.)
    pub fn has_been_shared(&self) -> bool {
        // OR in the adopted checkpoint's carried marker: the founding/sharing `Add` may be pruned below the
        // cut, so the effective-Add scan over `ops` alone would wrongly regress a shared group to `false`.
        self.base_has_been_shared
            || self.effective_ops().iter().any(|id| {
                matches!(self.ops.get(id).map(super::dag::resolver::SignedOp::action), Some(MembershipAction::Add { .. }))
            })
    }

    /// Kahn's topological sort over all admitted ops, with `OpId` as a deterministic tiebreak among
    /// concurrent ops — a real topo sort, NOT a plain `OpId` sort (which misorders whenever `OpIds` aren't
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

    pub const fn pending_count(&self) -> usize {
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
            &self.base_depths,
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
                events.push(MembershipEvent::RoleChanged { member: id.clone() });
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

/// A zero-cost borrowing VIEW of a `Keyeo`'s retained state.
///
/// EXACTLY the inputs compaction reads (the op set,
/// the causal graph, the resolved state, and the `has_been_shared` marker) and nothing else (not the
/// access-control / quorum / resolver the engine also carries).
///
/// [`Keyeo::retained`] produces it and the
/// [`keyeo_core::Compaction`] impl operates on it, so the `State` type is precisely the mechanism's inputs —
/// the op-DAG is borrowed, never duplicated, and compaction can't reach engine machinery it has no business in.
pub struct Retained<'a, Op: SignedOp> {
    ops: &'a HashMap<Op::OpId, Op>,
    graph: &'a Graph<Op::OpId>,
    state: &'a GroupState<Op::MemberId, Op::R, Op::S>,
    has_been_shared: bool,
}

impl<Op, AC, RS, QP> Keyeo<Op, AC, RS, QP>
where
    Op: SignedOp,
    AC: AccessControl<Op::MemberId, Op::R, Op::S>,
    RS: Resolver<Op::OpId, Op::R, Op, Op::S>,
    QP: QuorumPolicy<Op::MemberId, Op::R, Op::S>,
{
    /// A zero-cost borrowing view of the retained state, for the [`keyeo_core::Compaction`] impl on
    /// [`Retained`]. Borrows the engine's own fields — no copy of the op-DAG.
    pub fn retained(&self) -> Retained<'_, Op> {
        Retained {
            ops: &self.ops,
            graph: &self.graph,
            state: &self.state,
            has_been_shared: self.has_been_shared(),
        }
    }
}

/// Compaction ([`keyeo_core::Compaction`]) for the dag engine, over the [`Retained`] view: decide a
/// checkpoint + the prunable op set. This is the DECISION only — pure, no signing (the trait carries no key)
/// and no mutation. The caller authors its own signed checkpoint from the returned
/// `(frontier, state, has_been_shared)` and drops the returned `prune` ops from its store.
impl<Op: SignedOp> keyeo_core::Compaction for Retained<'_, Op> {
    type State = Self;
    type Cut = crate::gc::Frontier<Op::OpId>;
    type Output = Option<crate::gc::Compacted<Op::OpId, Op::MemberId, Op::R, Op::S>>;

    fn compact(
        state: &Self::State,
        stable: &Self::Cut,
        plan: keyeo_core::RetentionPlan,
    ) -> Result<Self::Output, keyeo_core::CompactionError> {
        use std::collections::HashSet;
        // The policy decides WHETHER to checkpoint (op/byte count); the stable frontier decides HOW FAR we may
        // prune. keep_last (retain a recent tail past the checkpoint, a verification convenience) would only
        // ever KEEP MORE than pruning to the frontier does, so honouring it is a later optimization — pruning to
        // the stable frontier is the safe maximum.
        let _keep_last = match plan {
            keyeo_core::RetentionPlan::KeepAll => return Ok(None),
            keyeo_core::RetentionPlan::Snapshot { keep_last } => keep_last,
        };

        // An empty frontier is not a valid cut: the dominance guard below would vacuously accept it (`all()`
        // over no tips is true), and a checkpoint authored from it would seed an EMPTY merge horizon on adopt,
        // silently disabling anti-rollback (OPE-270). Reject explicitly rather than pass the guard by accident.
        if stable.ops.is_empty() {
            return Err(keyeo_core::CompactionError(
                "empty frontier: a checkpoint must anchor at a non-empty cut".into(),
            ));
        }

        let tips: HashSet<Op::OpId> = stable.ops.iter().copied().collect();

        // The cut must be DOMINATING: every op is either AT/BELOW the frontier (a tip, or an ancestor of some
        // tip) or STRICTLY ABOVE it (descends from EVERY tip). An op CONCURRENT with the frontier — descending
        // from some tips but not all, or from none — is fatal: it would be retained while an op below the
        // frontier that is concurrent with IT gets pruned, so that pruned op's effect (e.g. a strong-remove
        // that should void the retained op, or a reset-merge carve-out) is silently lost on a compacted replica
        // — a membership / sealing split-brain vs a full-history replica. Reject rather than prune unsafely: the
        // caller must supply a COMPLETE cut across all concurrent branches (walk the frontier down until every
        // retained op descends from it). A single-branch tip in a forked DAG is not a valid cut.
        let below_or_at = |o: &Op::OpId| stable.ops.iter().any(|t| t == o || state.graph.has_path(*o, *t));
        let above_all = |o: &Op::OpId| stable.ops.iter().all(|t| state.graph.has_path(*t, *o));
        if let Some(bad) = state.ops.keys().find(|o| !below_or_at(o) && !above_all(o)) {
            return Err(keyeo_core::CompactionError(format!(
                "non-dominating cut: op {bad:?} is concurrent with the frontier — supply a complete cut across \
                 all concurrent tips (every retained op must descend from every tip)"
            )));
        }

        // subsumed = at or below the frontier (a tip, or a causal ancestor of some tip): every peer that has
        // synced past the whole frontier holds these, so a checkpoint can stand in for them.
        let subsumed = |x: &Op::OpId| {
            tips.contains(x) || stable.ops.iter().any(|t| state.graph.has_path(*x, *t))
        };
        let all: Vec<Op::OpId> = state.ops.keys().copied().collect();
        // Ops NOT subsumed (concurrent with / above the frontier) are still needed by a lagging peer. So are the
        // ancestors they reach WITHOUT crossing the frontier: those are un-checkpointed history a retained op
        // still hangs off (e.g. a fork branching off below the frontier). Ancestors a retained op reaches only
        // THROUGH a frontier tip are shielded — the tip is the anchor, and the checkpoint subsumes below it —
        // so they stay prunable. Walk parents from each un-subsumed op, stopping at the tips, to collect `keep`.
        let mut keep: HashSet<Op::OpId> = HashSet::new();
        let mut stack: Vec<Op::OpId> = all.iter().copied().filter(|x| !subsumed(x)).collect();
        while let Some(x) = stack.pop() {
            if let Some(op) = state.ops.get(&x) {
                for p in op.parents() {
                    if tips.contains(p) {
                        continue; // the frontier shields everything below this tip
                    }
                    if keep.insert(*p) {
                        stack.push(*p);
                    }
                }
            }
        }
        let prune: Vec<Op::OpId> = all
            .iter()
            .copied()
            // keep the frontier tips themselves — the anchor the retained tail attaches to
            .filter(|x| !tips.contains(x))
            // strictly below the frontier: an ancestor of some tip
            .filter(|x| stable.ops.iter().any(|t| state.graph.has_path(*x, *t)))
            // not still needed by a retained op via a frontier-avoiding path (would orphan it)
            .filter(|x| !keep.contains(x))
            .collect();

        Ok(Some(crate::gc::Compacted {
            frontier: stable.ops.clone(),
            state: state.state.clone(),
            has_been_shared: state.has_been_shared,
            prune,
        }))
    }
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

#[cfg(test)]
mod compaction_tests {
    use super::*;
    use crate::dag::resolver::{GroupId, GroupState, MemberInit, MembershipAction};
    use crate::gc::Frontier;
    use crate::op::Op;
    use crate::{ContentId, Ed25519};
    use keyeo_core::{Compaction, RetentionPlan};

    #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
    struct TRole;
    impl Role for TRole {
        fn grants_at_least(&self, _: &Self) -> bool {
            true
        }
    }

    type TOp = Op<ContentId, [u8; 32], TRole, Ed25519>;
    type TKeyeo = Keyeo<TOp, DefaultAccessControl<TRole>, crate::dag::strong_remove::StrongRemove>;

    /// Build the DAG `a → b → c` with a fork `a → d` (d concurrent with b/c), all authored by the one genesis
    /// member (membership-inert Reseal ops, just to shape the graph). Returns the engine + the four op ids.
    fn dag() -> (TKeyeo, ContentId, ContentId, ContentId, ContentId) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let me = [3u8; 32];
        let gid = GroupId(b"tree".to_vec());
        let genesis = GroupState::create(
            gid.clone(),
            &[MemberInit {
                id: me,
                role: TRole,
                author_public_key: sk.verifying_key().to_bytes(),
                hpke_public_key: [0u8; 32],
            }],
        );
        let mut k: TKeyeo = keyeo::<TOp, TRole, [u8; 32]>(genesis, TRole);
        // A unique `sealing` tag per op so ops with the same parents (b and d both branch off a) don't collapse
        // to one content id.
        let mk = |tag: u8, parents: Vec<ContentId>| {
            Op::content_addressed(gid.clone(), parents, me, MembershipAction::Reseal, vec![tag], &sk)
        };
        let a = mk(0, vec![]);
        let b = mk(1, vec![a.id]);
        let c = mk(2, vec![b.id]);
        let d = mk(3, vec![a.id]); // fork off a, concurrent with b/c
        let (aid, bid, cid, did) = (a.id, b.id, c.id, d.id);
        for op in [a, b, c, d] {
            let _ = k.apply(op);
        }
        let _ = k.flush();
        assert_eq!(k.effective_ops().len(), 4, "all four ops applied");
        (k, aid, bid, cid, did)
    }

    #[test]
    fn keep_all_is_a_noop() {
        let (k, ..) = dag();
        let out = <Retained<'_, TOp> as Compaction>::compact(&k.retained(), &Frontier { ops: vec![] }, RetentionPlan::KeepAll).unwrap();
        assert!(out.is_none(), "KeepAll prunes nothing and authors no checkpoint");
    }

    #[test]
    fn rejects_an_empty_frontier_under_snapshot() {
        // An empty frontier would vacuously pass the dominance guard and, if authored + adopted, seed an empty
        // merge horizon that silently disables anti-rollback. It must be an explicit error.
        let (k, ..) = dag();
        let err = <Retained<'_, TOp> as Compaction>::compact(
            &k.retained(),
            &Frontier { ops: vec![] },
            RetentionPlan::Snapshot { keep_last: 0 },
        )
        .unwrap_err();
        assert!(err.0.contains("empty frontier"), "an empty frontier is rejected: {}", err.0);
    }

    #[test]
    fn rejects_a_partial_cut_that_leaves_a_concurrent_fork() {
        let (k, _a, _b, c, _d) = dag();

        // Frontier {c} is a SINGLE branch tip while d is a concurrent, un-captured fork. Pruning below c (b)
        // while retaining d — which is concurrent with b — would silently drop b's effect on a compacted
        // replica (if b were a strong-remove voiding d, that voiding is lost). The cut is non-dominating and
        // must be REFUSED, not pruned around. (This is the Fable review counterexample.)
        let err = <Retained<'_, TOp> as Compaction>::compact(
            &k.retained(),
            &Frontier { ops: vec![c] },
            RetentionPlan::Snapshot { keep_last: 0 },
        )
        .unwrap_err();
        assert!(err.0.contains("non-dominating"), "a partial cut leaving a concurrent fork is rejected: {}", err.0);
    }

    #[test]
    fn accepts_a_complete_cut_across_all_tips_and_prunes_below_it() {
        let (k, a, b, c, d) = dag();

        // Frontier {c, d} captures BOTH concurrent tips — a complete cut. Now a and b are below the whole
        // frontier and nothing retained is concurrent with them, so both prune; the tips c, d are the anchors.
        let out = <Retained<'_, TOp> as Compaction>::compact(
            &k.retained(),
            &Frontier { ops: vec![c, d] },
            RetentionPlan::Snapshot { keep_last: 0 },
        )
        .unwrap()
        .unwrap();
        assert_eq!(out.prune.len(), 2, "a and b are below the complete cut");
        assert!(out.prune.contains(&a) && out.prune.contains(&b), "both ancestors prune");
        assert!(!out.prune.contains(&c) && !out.prune.contains(&d), "the frontier tips are the anchors, never pruned");
    }
}
