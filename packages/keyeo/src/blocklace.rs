//! The **blocklace** — keyeo's authenticated-DAG data structure.
//!
//! A blocklace (Shapiro; Keidar, Naor, Poupko & Shapiro, *"Cordial Miners"*, DISC 2023) is the
//! partially-ordered counterpart of a totally-ordered blockchain: each **block** is a signed payload
//! plus a set of hash pointers to previously-created blocks, so the blocks induce a DAG (a cryptographic
//! hash can't close a cycle). keyeo's [`SignedOp`] *is* a blocklace block — `id + parents + author +
//! action + signature` — and [`Graph`] is the induced hash-pointer DAG over block ids.
//!
//! Vocabulary (from the paper) and where it lives here:
//! - **observe** (`b ⪰ b'`): there is a path of pointers from `b` to `b'` — [`Graph::has_path`]. "Observe"
//!   is the causal-ancestry / happens-before relation the resolver reasons over.
//! - **tip**: a block no other block observes (no successor) — [`Graph::heads`].
//! - **concurrent**: two blocks with no path either way — [`Graph::is_concurrent`].
//! - **equivocation**: a *concurrent pair by the same author* — a Byzantine block-pair that observes
//!   neither the other. Author identity isn't part of the topology, so equivocation is judged one layer
//!   up, where blocks carry authors (see `StrongRemove`); the topology only supplies "concurrent".
//!
//! keyeo departs from Cordial Miners on one axis **on purpose**: it does not run the consensus ordering
//! (the τ function / waves / leader blocks / supermajority ratification that totally-orders the
//! blocklace). openom is convergent *without* consensus — Byzantine eventual consistency — so this
//! blocklace is resolved by an authority-aware [`crate::Resolver`] to a converged set, never totally
//! ordered. The shared idea we do take is the structure itself and its equivocation-tolerance: the DAG
//! may *contain* equivocations; resolution excludes them rather than a reliable-broadcast layer
//! preventing them.

use petgraph::graphmap::DiGraphMap;
use petgraph::visit::{Dfs, Reversed};
use std::collections::HashSet;

// The block abstraction and its content-addressed id are re-exported into the blocklace namespace so
// `blocklace::{SignedOp, content_id}` reads coherently; their definitions live with the resolver/content
// modules they're intertwined with.
pub use crate::content::{content_id, verify_content_id, ContentId};
pub use crate::dag::resolver::SignedOp;

/// The hash-pointer DAG induced by a blocklace — vertices are block ids, an edge `parent → child` is a
/// child's hash pointer to a parent. Generic over the id type (a content hash, in openom's keyring).
#[derive(Clone, Debug)]
pub struct Graph<Op: Ord + std::hash::Hash> {
    pub inner: DiGraphMap<Op, ()>,
}

impl<Op: Ord + std::hash::Hash + Copy> Graph<Op> {
    pub fn new() -> Self {
        Self {
            inner: DiGraphMap::new(),
        }
    }

    /// Add an edge from parent to child (a child's hash pointer to a parent block).
    pub fn add_edge(&mut self, parent: Op, child: Op) {
        self.inner.add_edge(parent, child, ());
    }

    /// Get all nodes.
    pub fn nodes(&self) -> Vec<Op> {
        self.inner.nodes().collect()
    }

    /// The **tips** — blocks with no successor (no incoming pointer from a later block).
    pub fn heads(&self) -> HashSet<Op> {
        let mut heads: HashSet<Op> = self.inner.nodes().collect();
        for edge in self.inner.all_edges() {
            heads.remove(&edge.0);
        }
        heads
    }

    /// Whether `from` **observes** `to` (`from ⪰ to`): a path of pointers exists from `from` to `to`.
    /// This is the causal-ancestry relation the resolver reasons over.
    pub fn has_path(&self, from: Op, to: Op) -> bool {
        from != to && petgraph::algo::has_path_connecting(&self.inner, from, to, None)
    }

    /// Whether two blocks are **concurrent** — neither observes the other. A concurrent pair by the same
    /// author is an equivocation (author identity is judged one layer up, not in the topology).
    pub fn is_concurrent(&self, a: Op, b: Op) -> bool {
        a != b && !self.has_path(a, b) && !self.has_path(b, a)
    }

    /// Find all concurrent bubbles in the graph.
    ///
    /// A bubble is a set of operations that share some concurrency relationship.
    /// Multiple bubbles can exist in the same graph.
    pub fn concurrent_bubbles(&self) -> Vec<HashSet<Op>> {
        fn concurrent_bubble<Op: Ord + std::hash::Hash + Copy>(
            graph: &Graph<Op>,
            target: Op,
            processed: &mut HashSet<Op>,
        ) -> HashSet<Op> {
            let mut bubble = HashSet::new();
            bubble.insert(target);

            let concurrent = graph.concurrent_operations(target);
            for op in concurrent {
                if processed.insert(op) {
                    bubble.extend(concurrent_bubble(graph, op, processed).iter());
                }
            }
            bubble
        }

        let mut processed: HashSet<Op> = HashSet::new();
        let mut bubbles = Vec::new();

        for target in self.inner.nodes() {
            if processed.insert(target) {
                let bubble = concurrent_bubble(self, target, &mut processed);
                if bubble.len() > 1 {
                    bubbles.push(bubble);
                }
            }
        }
        bubbles
    }

    /// Return operations concurrent with the given target.
    fn concurrent_operations(&self, target: Op) -> HashSet<Op> {
        // Collect all successors (reachable via forward edges)
        let mut successors = HashSet::new();
        let mut dfs = Dfs::new(&self.inner, target);
        while let Some(nx) = dfs.next(&self.inner) {
            successors.insert(nx);
        }

        // Collect all predecessors (reachable via reverse edges)
        let mut predecessors = HashSet::new();
        let reversed = Reversed(&self.inner);
        let mut dfs_rev = Dfs::new(&reversed, target);
        while let Some(nx) = dfs_rev.next(&reversed) {
            predecessors.insert(nx);
        }

        let relatives: HashSet<_> = successors.union(&predecessors).cloned().collect();
        self.inner
            .nodes()
            .filter(|n| !relatives.contains(n))
            .collect()
    }

    /// Split a bubble into (concurrent, predecessors, successors) relative to target.
    pub fn split_bubble(
        &self,
        bubble: &HashSet<Op>,
        target: Op,
    ) -> (HashSet<Op>, HashSet<Op>, Vec<Op>) {
        let mut concurrent = bubble.clone();
        let mut successors = Vec::new();
        let mut dfs = Dfs::new(&self.inner, target);
        while let Some(id) = dfs.next(&self.inner) {
            concurrent.remove(&id);
            successors.push(id);
        }

        let mut predecessors = HashSet::new();
        let reversed = Reversed(&self.inner);
        let mut dfs_rev = Dfs::new(&reversed, target);
        while let Some(id) = dfs_rev.next(&reversed) {
            concurrent.remove(&id);
            predecessors.insert(id);
        }

        (concurrent, predecessors, successors)
    }
}

impl<Op: Ord + std::hash::Hash + Copy> Default for Graph<Op> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_chain_no_concurrency() {
        let mut g = Graph::new();
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g.add_edge(3, 4);
        assert!(g.concurrent_bubbles().is_empty());
    }

    #[test]
    fn test_single_bubble() {
        let mut g = Graph::new();
        g.add_edge(1, 2);
        g.add_edge(1, 3);
        g.add_edge(2, 4);
        g.add_edge(3, 4);
        let bubbles = g.concurrent_bubbles();
        assert_eq!(bubbles.len(), 1);
        let expected: HashSet<i32> = [2, 3].into_iter().collect();
        assert_eq!(bubbles[0], expected);
    }

    #[test]
    fn test_has_path_and_concurrent() {
        let mut g = Graph::new();
        g.add_edge(1, 2);
        g.add_edge(1, 3);
        g.add_edge(2, 4);
        g.add_edge(3, 4);
        assert!(g.is_concurrent(2, 3));
        assert!(!g.is_concurrent(1, 2));
        assert!(g.has_path(1, 4));
        assert!(!g.has_path(4, 1));
    }

    #[test]
    fn block_bytes_are_payload_agnostic() {
        // The block-bytes layer (`canonical_encode`) is generic over the payload via `CanonicalBytes`:
        // here a toy payload — no MembershipAction, no roles, no keys — proves a blocklace block's signed
        // bytes are defined independently of what it carries, and testable without membership scaffolding.
        use crate::canonical::{canonical_encode, CanonicalBytes};
        struct Payload(u8);
        impl CanonicalBytes for Payload {
            fn write_canonical(&self, out: &mut Vec<u8>) {
                out.push(self.0);
            }
        }
        let (parents, author) = ([1u64, 2u64], [9u8; 32]);
        let a = canonical_encode(&parents, &author, &Payload(7));
        assert_eq!(a, canonical_encode(&parents, &author, &Payload(7)), "deterministic");
        assert_ne!(a, canonical_encode(&parents, &author, &Payload(8)), "the payload binds");
        assert_ne!(a, canonical_encode(&[1u64], &author, &Payload(7)), "parents bind");
    }
}
