//! A backend-agnostic conformance suite. Every [`BlobStore`](crate::BlobStore) impl must pass it —
//! downstream backends (Google Drive, R2, …) call [`run`] to prove they honour the contract.

use crate::{BlobError, BlobStore, Precondition};

/// Run the full suite against fresh stores from `make` (called once per sub-check, each returning a
/// fresh, empty store). Panics on the first violation — it's a test harness.
pub fn run<S: BlobStore>(make: impl Fn() -> S) {
    get_missing_is_none(&make());
    put_then_get_roundtrips(&make());
    if_absent_creates_then_conflicts(&make());
    if_match_cas(&make());
    list_by_prefix(&make());
    delete_semantics(&make());
    idempotent_put_same_etag(&make());
}

fn get_missing_is_none<S: BlobStore>(s: &S) {
    assert!(s.get("nope").unwrap().is_none(), "get of a missing key is None");
}

fn put_then_get_roundtrips<S: BlobStore>(s: &S) {
    let e = s.put("k", b"hello", Precondition::Any).unwrap();
    let (bytes, e2) = s.get("k").unwrap().expect("present after put");
    assert_eq!(bytes, b"hello", "get returns the put bytes");
    assert_eq!(e, e2, "put's etag matches get's");
}

fn if_absent_creates_then_conflicts<S: BlobStore>(s: &S) {
    s.put("k", b"v1", Precondition::IfAbsent).unwrap();
    let err = s.put("k", b"v2", Precondition::IfAbsent).unwrap_err();
    assert!(matches!(err, BlobError::PreconditionFailed), "IfAbsent on an existing key conflicts");
    assert_eq!(s.get("k").unwrap().unwrap().0, b"v1", "the conflicting write did not land");
}

fn if_match_cas<S: BlobStore>(s: &S) {
    let e1 = s.put("k", b"v1", Precondition::Any).unwrap();
    let stale = s.put("k", b"v2", Precondition::IfMatch("stale".into())).unwrap_err();
    assert!(matches!(stale, BlobError::PreconditionFailed), "a stale etag conflicts");
    let e2 = s.put("k", b"v2", Precondition::IfMatch(e1.clone())).unwrap();
    assert_ne!(e1, e2, "a changed value has a new etag");
    let now_stale = s.put("k", b"v3", Precondition::IfMatch(e1)).unwrap_err();
    assert!(matches!(now_stale, BlobError::PreconditionFailed), "the old etag is now stale");
}

fn list_by_prefix<S: BlobStore>(s: &S) {
    s.put("a/1", b"x", Precondition::Any).unwrap();
    s.put("a/2", b"y", Precondition::Any).unwrap();
    s.put("b/1", b"z", Precondition::Any).unwrap();
    let mut a: Vec<String> = s.list("a/").unwrap().into_iter().map(|(k, _)| k).collect();
    a.sort();
    assert_eq!(a, vec!["a/1".to_string(), "a/2".to_string()], "list returns only the prefix");
    assert_eq!(s.list("").unwrap().len(), 3, "the empty prefix lists everything");
}

fn delete_semantics<S: BlobStore>(s: &S) {
    let e = s.put("k", b"v", Precondition::Any).unwrap();
    let stale = s.delete("k", Precondition::IfMatch("stale".into())).unwrap_err();
    assert!(matches!(stale, BlobError::PreconditionFailed), "a stale IfMatch delete conflicts");
    s.delete("k", Precondition::IfMatch(e)).unwrap();
    assert!(s.get("k").unwrap().is_none(), "a matched delete removes the key");
    s.delete("k", Precondition::Any).unwrap(); // idempotent: deleting an absent key is Ok
}

fn idempotent_put_same_etag<S: BlobStore>(s: &S) {
    let e1 = s.put("k", b"same", Precondition::Any).unwrap();
    let e2 = s.put("k", b"same", Precondition::Any).unwrap();
    assert_eq!(e1, e2, "identical content yields the same etag");
}
