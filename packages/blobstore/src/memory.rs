//! An in-memory [`BlobStore`] — a `Mutex<HashMap>`. For tests and single-process use.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::{check_pre, etag_of, BlobStore, Etag, Precondition, Result};

/// In-memory blob store. Not durable; the CAS is process-local (a real backend enforces it server-side).
#[derive(Default)]
pub struct MemoryBlob {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryBlob {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlobStore for MemoryBlob {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, Etag)>> {
        let map = self.map.lock().unwrap();
        Ok(map.get(key).map(|b| (b.clone(), etag_of(b))))
    }

    fn put(&self, key: &str, bytes: &[u8], pre: Precondition) -> Result<Etag> {
        let mut map = self.map.lock().unwrap();
        check_pre(&pre, map.get(key).map(|b| b.as_slice()))?;
        map.insert(key.to_string(), bytes.to_vec());
        Ok(etag_of(bytes))
    }

    fn list(&self, prefix: &str) -> Result<Vec<(String, Etag)>> {
        let map = self.map.lock().unwrap();
        Ok(map
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, b)| (k.clone(), etag_of(b)))
            .collect())
    }

    fn delete(&self, key: &str, pre: Precondition) -> Result<()> {
        let mut map = self.map.lock().unwrap();
        check_pre(&pre, map.get(key).map(|b| b.as_slice()))?;
        map.remove(key);
        Ok(())
    }
}
