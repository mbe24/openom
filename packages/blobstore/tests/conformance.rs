//! Run the backend-agnostic conformance suite against both reference impls.

use blobstore::{conformance, FsBlob, MemoryBlob};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn memory_blob_conforms() {
    conformance::run(MemoryBlob::new);
}

#[test]
fn fs_blob_conforms() {
    // The suite makes several fresh stores via the factory; give each its own empty subdir.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().to_path_buf();
    let n = AtomicUsize::new(0);
    conformance::run(|| FsBlob::new(base.join(format!("store-{}", n.fetch_add(1, Ordering::SeqCst)))));
}
