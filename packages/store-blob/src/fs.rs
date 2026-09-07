//! A local-filesystem [`BlobStore`] rooted at a directory. A reference dumb backend, and the durable
//! local option.
//!
//! Keys map to files under the root, with `/` as the path separator (nested dirs created on `put`). The
//! CAS check-then-write is **not** cross-process atomic — that's fine for a single-process dev/reference
//! backend; a real backend (R2/Drive) enforces the precondition atomically server-side.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{check_pre, etag_of, BlobError, BlobStore, Etag, Precondition, Result};

/// Local-filesystem blob store rooted at `root`.
pub struct FsBlob {
    root: PathBuf,
}

impl FsBlob {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Map a `/`-separated key to a path under the root, rejecting traversal and absolute/odd keys.
    fn path_for(&self, key: &str) -> Result<PathBuf> {
        let bad = key.is_empty()
            || key.starts_with('/')
            || key.contains('\\')
            || key
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..");
        if bad {
            return Err(BlobError::Backend(format!("invalid key: {key:?}")));
        }
        Ok(self.root.join(key))
    }
}

fn io<E: std::fmt::Display>(e: E) -> BlobError {
    BlobError::Backend(e.to_string())
}

fn read_opt(p: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(p) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(e)),
    }
}

impl BlobStore for FsBlob {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Etag)>> {
        let p = self.path_for(key)?;
        Ok(read_opt(&p)?.map(|b| {
            let e = etag_of(&b);
            (b, e)
        }))
    }

    fn put(&self, key: &str, bytes: &[u8], pre: Precondition) -> Result<Etag> {
        let p = self.path_for(key)?;
        check_pre(&pre, read_opt(&p)?.as_deref())?;
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(io)?;
        }
        fs::write(&p, bytes).map_err(io)?;
        Ok(etag_of(bytes))
    }

    fn list(&self, prefix: &str) -> Result<Vec<(String, Etag)>> {
        let mut out = Vec::new();
        walk(&self.root, &self.root, &mut out)?;
        out.retain(|(k, _)| k.starts_with(prefix));
        Ok(out)
    }

    fn delete(&self, key: &str, pre: Precondition) -> Result<()> {
        let p = self.path_for(key)?;
        check_pre(&pre, read_opt(&p)?.as_deref())?;
        match fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e)),
        }
    }
}

/// Recursively collect `(key, etag)` for every file under `dir`, keys relative to `root` with `/` seps.
fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Etag)>) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io(e)),
    };
    for entry in entries {
        let path = entry.map_err(io)?.path();
        if path.is_dir() {
            walk(root, &path, out)?;
        } else {
            let rel = path.strip_prefix(root).map_err(io)?;
            let key = rel.to_string_lossy().replace('\\', "/");
            let bytes = fs::read(&path).map_err(io)?;
            out.push((key, etag_of(&bytes)));
        }
    }
    Ok(())
}
