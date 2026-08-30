//! Graph operations for concurrent operation detection.
//!
//! Adapted from p2panda-auth's graph module (MIT/Apache-2.0).
//! Provides DFS-based concurrent bubble detection and authority graph cycle detection.

use petgraph::graphmap::DiGraphMap;
use petgraph::visit::{Dfs, Reversed};
use std::collections::HashSet;

/// A directed graph of operations.
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

    /// Add an edge from parent to child.
    pub fn add_edge(&mut self, parent: Op, child: Op) {
        self.inner.add_edge(parent, child, ());
    }

    /// Get all nodes.
    pub fn nodes(&self) -> Vec<Op> {
        self.inner.nodes().collect()
    }

    /// Get the heads (nodes with no outgoing edges).
    pub fn heads(&self) -> HashSet<Op> {
        let mut heads: HashSet<Op> = self.inner.nodes().collect();
        for edge in self.inner.all_edges() {
            heads.remove(&edge.0);
        }
        heads
    }

    /// Check if a path exists from `from` to `to`.
    pub fn has_path(&self, from: Op, to: Op) -> bool {
        from != to && petgraph::algo::has_path_connecting(&self.inner, from, to, None)
    }

    /// Check if two ops are concurrent (no path in either direction).
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
}
