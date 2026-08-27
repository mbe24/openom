//! StrongRemove resolver — a fixpoint over the op DAG that decides which ops to ignore.
//!
//! Three interacting rules, iterated to a fixpoint (the ignore set only grows, so it converges):
//!
//! 1. **Concurrent strong-remove.** A valid `Remove(M)` op `R` invalidates every op authored by `M`
//!    that is *concurrent* with `R` — so a member being removed cannot smuggle in ops during the
//!    concurrency window (e.g. adding an accomplice). Ops by `M` that causally precede `R` stay
//!    valid; ops after a valid removal are handled by rule 3 (the author is no longer present).
//! 2. **Mutual-remove tiebreak.** If `A` removes `B` and `B` concurrently removes `A`, both removes
//!    would invalidate each other. We process removes in a deterministic order — smaller
//!    `(lamport_depth, op_id)` first — so exactly one wins: the winner's remove stands and
//!    invalidates the loser's counter-remove. (A founder priority could layer on top later.)
//! 3. **Presence / accomplice cascade.** An op is invalid unless its author is *active* in the op's
//!    own causal ancestry — i.e. replaying that member's valid `Add`/`Remove` events that happen
//!    before the op (genesis members start active) leaves them active. So an accomplice whose only
//!    `Add` was itself invalidated (rule 1) is never present, and all their ops fall — transitively.
//! 4. **Remove wins over a concurrent re-add.** An `Add(M)` *concurrent* with a *surviving*
//!    `Remove(M)` is suppressed — an eviction wins the race against a re-add that does not causally
//!    follow it, so the outcome is decided by causality, not the Kahn/id ordering "lottery". An
//!    `Add(M)` that causally *follows* the `Remove(M)` is a legitimate re-onboarding and stands.
//!
//! Rules 1-3 are monotone and reach an inner fixpoint; rule 4 then suppresses re-adds against the
//! resolved survivor set and re-runs the inner fixpoint (a suppressed re-add can't re-establish its
//! member), all iterated to an outer fixpoint. Rule 4 gates on a *surviving* remove precisely so a
//! remove that rules 1-3 dropped cannot suppress anything.

use std::collections::{HashMap, HashSet};

use crate::access::AccessControl;
use crate::dag::graph::Graph;
use crate::dag::lamport::apply_action;
use crate::dag::resolver::{GroupState, MembershipAction, OpId, Resolver, SignedOp};
use crate::roles::Role;
use crate::signature::SignatureScheme;

/// Tracks which operations to ignore during rebuild. Keyed on the real `OId`.
#[derive(Clone, Debug)]
pub struct StrongRemoveState<OId: OpId> {
    pub ignore: HashSet<OId>,
}

impl<OId: OpId> Default for StrongRemoveState<OId> {
    fn default() -> Self {
        Self {
            ignore: HashSet::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct StrongRemove;

impl<OId: OpId, R: Role, S: SignatureScheme, Op: SignedOp<OpId = OId, R = R, S = S>>
    Resolver<OId, R, Op, S> for StrongRemove
{
    type State = StrongRemoveState<OId>;
    type Error = String;

    fn rebuild_required(_state: &Self::State, _op: &Op, current_heads: &HashSet<OId>) -> bool {
        current_heads.len() > 1
    }

    fn process(
        mut state: Self::State,
        graph: &Graph<OId>,
        ops: &HashMap<OId, Op>,
        ac: &impl AccessControl<Op::MemberId, R, S>,
        genesis_state: &GroupState<Op::MemberId, R, S>,
    ) -> Result<Self::State, Self::Error> {
        let depth = compute_depths(ops);
        let genesis = genesis_members(ops);

        // Authorization at each op's CAUSAL POSITION: fold the op's authorized ancestors onto the base
        // state and ask `AccessControl`. Well-founded over the ancestor DAG — it does NOT depend on the
        // concurrent strong-remove fixpoint below (a concurrent remove is not in an op's causal past, so
        // it can't retroactively unauthorize), which is what keeps this non-circular. An unauthorized op
        // is decided once here and then neither applies nor exerts invalidation.
        let authorized = authorized_map(genesis_state, graph, ops, ac, &depth);

        // Removes ordered by the deterministic tiebreak (rule 2), stable across replicas — but ONLY
        // authorized removes carry invalidation power. An unauthorized `Remove` (author lacks the role)
        // must not suppress the removee's concurrent, authorized ops (the authority-blind hole, OPE-258).
        let mut removes: Vec<(OId, Op::MemberId)> = ops
            .iter()
            .filter_map(|(id, op)| match op.action() {
                MembershipAction::Remove { member }
                    if authorized.get(id).copied().unwrap_or(false) =>
                {
                    Some((*id, member.clone()))
                }
                _ => None,
            })
            .collect();
        removes.sort_by_key(|(id, _)| (*depth.get(id).unwrap_or(&0), *id));

        // Seed the ignore set with every unauthorized op: it neither applies nor invalidates, and (via
        // rule 3, which skips ignored Add/Remove events) it establishes no presence for its members.
        let mut invalid: HashSet<OId> = ops
            .keys()
            .copied()
            .filter(|id| !authorized.get(id).copied().unwrap_or(false))
            .collect();
        loop {
            // Inner fixpoint: rules 1+2+3 iterated until stable (all monotone — the ignore set only
            // grows — so this converges). Any rule-4 suppressions from a previous outer pass are
            // already in `invalid` and cascade correctly through rule 3 here.
            loop {
                let mut changed = false;

                // Rule 1 + 2: a valid remove invalidates the removed member's concurrent ops; because
                // removes are processed in tiebreak order, a mutual remove leaves exactly one winner.
                for (r, m) in &removes {
                    if invalid.contains(r) {
                        continue;
                    }
                    for (o, op) in ops {
                        if o == r || invalid.contains(o) {
                            continue;
                        }
                        if op.author() == m && graph.is_concurrent(*o, *r) && invalid.insert(*o) {
                            changed = true;
                        }
                    }
                }

                // Rule 3: drop any op whose author is not active in the op's causal ancestry.
                for (o, op) in ops {
                    if invalid.contains(o) {
                        continue;
                    }
                    if !author_active_before(
                        op.author(),
                        *o,
                        ops,
                        graph,
                        &depth,
                        &genesis,
                        &invalid,
                    ) && invalid.insert(*o)
                    {
                        changed = true;
                    }
                }

                if !changed {
                    break;
                }
            }

            // Rule 4 (remove-wins-over-concurrent-re-add). An `Add(M)` that is *concurrent* with a
            // *surviving* `Remove(M)` is suppressed, so an eviction wins the race against a re-add
            // that doesn't causally follow it — the outcome no longer depends on the Kahn/id tiebreak
            // ("lottery"). An `Add(M)` that causally *follows* a `Remove(M)` is a legitimate
            // re-onboarding and is left alone (it isn't concurrent). Gating on `!invalid.contains(r)`
            // is why this runs *after* the rules-1-3 inner fixpoint: a `Remove` dropped by rule 1/3
            // (e.g. its author was concurrently strong-removed) must not suppress anything — reading a
            // raw "is there any Remove(M)" from the op set instead of the resolved survivor set would
            // be the bug. Suppressions feed back into rule 3 on the next outer pass (a suppressed
            // re-add can't re-establish its member), and because they only grow the ignore set the
            // outer loop also converges.
            let mut suppressed = false;
            for (a, op) in ops {
                if invalid.contains(a) {
                    continue;
                }
                let MembershipAction::Add { member, .. } = op.action() else {
                    continue;
                };
                let concurrent_surviving_remove = removes.iter().any(|(r, m)| {
                    m == member && !invalid.contains(r) && graph.is_concurrent(*a, *r)
                });
                if concurrent_surviving_remove && invalid.insert(*a) {
                    suppressed = true;
                }
            }
            if !suppressed {
                break;
            }
        }

        state.ignore = invalid;
        Ok(state)
    }

    fn ignored(state: &Self::State) -> HashSet<OId> {
        state.ignore.clone()
    }
}

/// Authorization at every op's causal position, keyed on op id. `authorized[o]` = whether `o`'s author
/// was permitted (by `AccessControl`) to perform `o`'s action given the state resolved from `o`'s causal
/// PAST — its authorized ancestors folded onto `genesis`. Well-founded over the ancestor DAG and
/// independent of the concurrent strong-remove fixpoint, so it is computed once, up front.
fn authorized_map<OId, R, S, Op>(
    genesis: &GroupState<Op::MemberId, R, S>,
    graph: &Graph<OId>,
    ops: &HashMap<OId, Op>,
    ac: &impl AccessControl<Op::MemberId, R, S>,
    depth: &HashMap<OId, usize>,
) -> HashMap<OId, bool>
where
    OId: OpId,
    R: Role,
    S: SignatureScheme,
    Op: SignedOp<OpId = OId, R = R, S = S>,
{
    let mut memo: HashMap<OId, bool> = HashMap::new();
    let mut on_stack: HashSet<OId> = HashSet::new();
    for &id in ops.keys() {
        authorized_at(id, genesis, graph, ops, ac, depth, &mut memo, &mut on_stack);
    }
    memo
}

/// Memoized: is `id`'s author authorized at `id`'s causal position? Folds `id`'s authorized ancestors
/// (topological, by `(depth, id)`) onto `genesis`, then asks `AccessControl`. Recurses only into strict
/// ancestors, so it terminates on any DAG (the `on_stack` guard degrades a stray cycle to `false`).
#[allow(clippy::too_many_arguments)]
fn authorized_at<OId, R, S, Op>(
    id: OId,
    genesis: &GroupState<Op::MemberId, R, S>,
    graph: &Graph<OId>,
    ops: &HashMap<OId, Op>,
    ac: &impl AccessControl<Op::MemberId, R, S>,
    depth: &HashMap<OId, usize>,
    memo: &mut HashMap<OId, bool>,
    on_stack: &mut HashSet<OId>,
) -> bool
where
    OId: OpId,
    R: Role,
    S: SignatureScheme,
    Op: SignedOp<OpId = OId, R = R, S = S>,
{
    if let Some(&a) = memo.get(&id) {
        return a;
    }
    if !on_stack.insert(id) {
        return false; // cycle guard (never in a DAG)
    }
    // Fold the authorized ancestors of `id` in topological order to reconstruct the state `id` saw.
    let mut ancestors: Vec<OId> = ops
        .keys()
        .copied()
        .filter(|&a| graph.has_path(a, id))
        .collect();
    ancestors.sort_by_key(|a| (*depth.get(a).unwrap_or(&0), *a));
    let mut state = genesis.clone();
    for a in ancestors {
        if authorized_at(a, genesis, graph, ops, ac, depth, memo, on_stack) {
            if let Ok((next, _)) = apply_action(state.clone(), ops[&a].action()) {
                state = next;
            }
        }
    }
    let op = &ops[&id];
    let result = ac.is_authorized(&state, op.author(), op.action());
    on_stack.remove(&id);
    memo.insert(id, result);
    result
}

/// Lamport depth of every op: 0 at a root, else 1 + max parent depth. Used only as a deterministic
/// tiebreak, so an unexpected cycle degrading to 0 is harmless.
fn compute_depths<OId: OpId, Op: SignedOp<OpId = OId>>(
    ops: &HashMap<OId, Op>,
) -> HashMap<OId, usize> {
    fn go<OId: OpId, Op: SignedOp<OpId = OId>>(
        id: OId,
        ops: &HashMap<OId, Op>,
        memo: &mut HashMap<OId, usize>,
        on_stack: &mut HashSet<OId>,
    ) -> usize {
        if let Some(&d) = memo.get(&id) {
            return d;
        }
        if !on_stack.insert(id) {
            return 0; // cycle guard (shouldn't happen in a DAG)
        }
        let d = match ops.get(&id) {
            None => 0,
            Some(op) => op
                .parents()
                .iter()
                .filter(|p| ops.contains_key(p))
                .map(|p| 1 + go(*p, ops, memo, on_stack))
                .max()
                .unwrap_or(0),
        };
        on_stack.remove(&id);
        memo.insert(id, d);
        d
    }
    let mut memo = HashMap::new();
    let mut on_stack = HashSet::new();
    for id in ops.keys() {
        go(*id, ops, &mut memo, &mut on_stack);
    }
    memo
}

/// Members present at genesis (from the `Create` op's initial members).
fn genesis_members<OId: OpId, Op: SignedOp<OpId = OId>>(
    ops: &HashMap<OId, Op>,
) -> HashSet<Op::MemberId> {
    let mut g = HashSet::new();
    for op in ops.values() {
        if let MembershipAction::Create { initial_members } = op.action() {
            for m in initial_members {
                g.insert(m.id.clone());
            }
        }
    }
    g
}

/// Is `author` an active member in `target`'s causal ancestry? Replay the author's valid
/// `Add`/`Remove` events that happen-before `target`, in depth order; genesis members start active.
#[allow(clippy::too_many_arguments)]
fn author_active_before<OId: OpId, Op: SignedOp<OpId = OId>>(
    author: &Op::MemberId,
    target: OId,
    ops: &HashMap<OId, Op>,
    graph: &Graph<OId>,
    depth: &HashMap<OId, usize>,
    genesis: &HashSet<Op::MemberId>,
    invalid: &HashSet<OId>,
) -> bool {
    let mut events: Vec<(usize, bool)> = Vec::new(); // (depth, is_add)
    for (id, op) in ops {
        if *id == target || invalid.contains(id) {
            continue;
        }
        let (member, is_add) = match op.action() {
            MembershipAction::Add { member, .. } => (member, true),
            MembershipAction::Remove { member } => (member, false),
            _ => continue,
        };
        if member == author && graph.has_path(*id, target) {
            events.push((*depth.get(id).unwrap_or(&0), is_add));
        }
    }
    events.sort_by_key(|(d, _)| *d);
    // A member with no `Add` op anywhere in the DAG was seeded at construction (constructor genesis,
    // not a `Create` op), so start them active. A member who *does* have an `Add` op starts inactive
    // and only becomes active via a *valid* one — which is what makes an invalidated (accomplice) add
    // fail to establish its member, cascading transitively.
    let has_add_op = ops
        .values()
        .any(|op| matches!(op.action(), MembershipAction::Add { member, .. } if member == author));
    let mut active = genesis.contains(author) || !has_add_op;
    for (_, is_add) in events {
        active = is_add;
    }
    active
}
