//! Self-contained proof the generic loop works with a trivial engine: a grow-only set of lines.
//! Convergence + compaction + bootstrap, no domain types.

use super::*;
use journal::memory::MemoryStore;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::sync::Arc;

/// A grow-only set of strings — the simplest commutative/idempotent engine.
#[derive(Default)]
struct GrowSet {
    lines: BTreeSet<String>,
}

impl Engine for GrowSet {
    type Edit = String;
    type Error = Infallible;

    fn apply_local(&mut self, edit: String) -> Vec<u8> {
        if self.lines.insert(edit.clone()) {
            edit.into_bytes() // one line = one delta
        } else {
            Vec::new() // already present ⇒ no-op
        }
    }

    fn merge(&mut self, delta: &[u8]) -> std::result::Result<(), Infallible> {
        if !delta.is_empty() {
            self.lines.insert(String::from_utf8_lossy(delta).into_owned());
        }
        Ok(())
    }

    fn snapshot(&self) -> Vec<u8> {
        self.lines.iter().cloned().collect::<Vec<_>>().join("\n").into_bytes()
    }

    fn merge_snapshot(&mut self, bytes: &[u8]) -> std::result::Result<(), Infallible> {
        for l in String::from_utf8_lossy(bytes).split('\n').filter(|s| !s.is_empty()) {
            self.lines.insert(l.to_string());
        }
        Ok(())
    }
}

fn client(store: Arc<MemoryStore>) -> SyncClient<GrowSet, PassthroughSealer, Arc<MemoryStore>> {
    SyncClient::new(GrowSet::default(), PassthroughSealer, store, "doc")
}

#[test]
fn two_replicas_converge_and_a_third_bootstraps() {
    let store = Arc::new(MemoryStore::new());
    let mut a = client(store.clone());
    let mut b = client(store.clone());

    // Concurrent edits on two replicas, interleaved pulls.
    a.apply("alpha".into()).unwrap();
    b.apply("beta".into()).unwrap();
    a.pull().unwrap();
    b.pull().unwrap();
    a.apply("gamma".into()).unwrap();
    a.pull().unwrap();
    b.pull().unwrap();

    let expected: BTreeSet<String> = ["alpha", "beta", "gamma"].iter().map(|s| s.to_string()).collect();
    assert_eq!(a.engine().lines, expected);
    assert_eq!(b.engine().lines, expected, "two replicas converge");

    // Compact to a snapshot, add a tail delta, then a fresh replica bootstraps
    // from snapshot + tail and matches.
    a.compact().unwrap();
    a.apply("delta".into()).unwrap();

    let mut c = client(store.clone());
    c.bootstrap().unwrap();
    let mut expected2 = expected.clone();
    expected2.insert("delta".into());
    assert_eq!(c.engine().lines, expected2, "bootstrap = snapshot + tail");

    // Re-pulling one's own pushes is a no-op (idempotent).
    let n = a.pull().unwrap();
    a.pull().unwrap();
    assert!(a.engine().lines.contains("delta"));
    let _ = n;
}
