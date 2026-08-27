//! Konformitäts-Suite: dieselben Fälle laufen gegen jede Implementierung.
//! Genau das macht den späteren Wechsel auf Datei, Server oder S3 sicher.

use super::memory::MemoryStore;
#[cfg(feature = "sqlite")]
use super::sqlite::SqliteStore;
use super::*;

fn update(n: u64) -> Update {
    format!("op-{n}").into_bytes()
}

fn suite(store: &dyn DocStore) {
    let doc = "tree-1";

    // leerer Store
    assert!(store.read_snapshot(doc).unwrap().is_none());
    let (updates, cursor) = store.read_updates(doc, None).unwrap();
    assert!(updates.is_empty());
    assert_eq!(cursor, 0);

    // anhängen und ab Cursor lesen
    store.append(doc, &[update(1), update(2)]).unwrap();
    let (updates, cursor) = store.read_updates(doc, None).unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0], b"op-1");
    store.append(doc, &[update(3)]).unwrap();
    let (tail, _) = store.read_updates(doc, Some(cursor)).unwrap();
    assert_eq!(tail.len(), 1, "nur Updates nach dem Cursor");

    // erster Snapshot erwartet None als Version
    let v1 = store.put_snapshot(doc, b"snap-1", None).unwrap();
    let snap = store.read_snapshot(doc).unwrap().unwrap();
    assert_eq!(snap.bytes, b"snap-1");
    assert_eq!(snap.version, v1);

    // Compare-and-swap: falsche Erwartung wird abgelehnt
    let err = store.put_snapshot(doc, b"snap-x", None).unwrap_err();
    assert!(
        matches!(err, StoreError::Conflict { .. }),
        "stale write must fail"
    );
    let err = store
        .put_snapshot(doc, b"snap-x", Some("nope"))
        .unwrap_err();
    assert!(matches!(err, StoreError::Conflict { .. }));

    // mit der richtigen Version geht es
    let v2 = store.put_snapshot(doc, b"snap-2", Some(&v1)).unwrap();
    assert_ne!(v1, v2);
    assert_eq!(store.read_snapshot(doc).unwrap().unwrap().bytes, b"snap-2");

    // löschen
    store.delete(doc).unwrap();
    assert!(store.read_snapshot(doc).unwrap().is_none());
}

#[test]
fn memory_store_conforms() {
    suite(&MemoryStore::new());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_conforms() {
    suite(&SqliteStore::in_memory().unwrap());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_open_survives_a_reopen() {
    // A durable, file-backed store must return committed data after being dropped and reopened —
    // the property in_memory can't have and the whole point of `open(path)`.
    let path = std::env::temp_dir().join(format!("journal-durable-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let store = SqliteStore::open(&path).unwrap();
        store
            .append("d", &[b"one".to_vec(), b"two".to_vec()])
            .unwrap();
        store.put_snapshot("d", b"snap", None).unwrap();
    } // dropped: connection closed
    {
        let store = SqliteStore::open(&path).unwrap();
        let (updates, cursor) = store.read_updates("d", None).unwrap();
        assert_eq!(updates, vec![b"one".to_vec(), b"two".to_vec()]);
        assert_eq!(cursor, 2);
        assert_eq!(store.read_snapshot("d").unwrap().unwrap().bytes, b"snap");
    }
    // WAL leaves -wal/-shm siblings; clean them all up.
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(path.with_extension(format!("sqlite{suffix}")));
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn stores_agree_on_conflict_semantics() {
    let mem = MemoryStore::new();
    let sql = SqliteStore::in_memory().unwrap();
    for s in [&mem as &dyn DocStore, &sql as &dyn DocStore] {
        let v = s.put_snapshot("d", b"a", None).unwrap();
        assert!(s.put_snapshot("d", b"b", None).is_err());
        assert!(s.put_snapshot("d", b"b", Some(&v)).is_ok());
    }
}
