use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
struct Doc {
    snapshot: Option<Snapshot>,
    log: Vec<Update>,
    counter: u64,
}

#[derive(Default)]
pub struct MemoryStore {
    docs: Mutex<HashMap<String, Doc>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DocStore for MemoryStore {
    fn caps(&self) -> Caps {
        Caps { remote: false, conditional_writes: true, durable: false, max_blob_bytes: u64::MAX }
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.docs.lock().unwrap().keys().cloned().collect())
    }

    fn read_snapshot(&self, doc: &str) -> Result<Option<Snapshot>> {
        Ok(self.docs.lock().unwrap().get(doc).and_then(|d| d.snapshot.clone()))
    }

    fn read_updates(&self, doc: &str, since: Option<u64>) -> Result<(Vec<Update>, u64)> {
        let docs = self.docs.lock().unwrap();
        let Some(d) = docs.get(doc) else { return Ok((vec![], 0)) };
        let from = since.unwrap_or(0) as usize;
        Ok((d.log.iter().skip(from).cloned().collect(), d.counter))
    }

    fn append(&self, doc: &str, updates: &[Update]) -> Result<u64> {
        let mut docs = self.docs.lock().unwrap();
        let d = docs.entry(doc.to_string()).or_default();
        d.log.extend_from_slice(updates);
        d.counter = d.log.len() as u64;
        Ok(d.counter)
    }

    fn put_snapshot(&self, doc: &str, bytes: &[u8], expected: Option<&str>) -> Result<String> {
        let mut docs = self.docs.lock().unwrap();
        let d = docs.entry(doc.to_string()).or_default();
        let found = d.snapshot.as_ref().map(|s| s.version.clone());
        if found.as_deref() != expected {
            return Err(StoreError::Conflict { expected: expected.map(String::from), found });
        }
        let version = format!("v{}", d.counter + 1);
        d.counter += 1;
        d.snapshot = Some(Snapshot { bytes: bytes.to_vec(), version: version.clone() });
        Ok(version)
    }

    fn delete(&self, doc: &str) -> Result<()> {
        self.docs.lock().unwrap().remove(doc);
        Ok(())
    }
}
