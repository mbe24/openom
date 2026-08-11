//! Server. Noch ein Geruest — hier entsteht die S3-Implementierung von
//! `DocStore` und der FaaS-Einstiegspunkt.
//!
//! Der Punkt dieses Crates ist, dass es **denselben** Trait erfuellt wie
//! `MemoryStore` und `SqliteStore`. Damit laeuft die Konformitaetssuite aus
//! `openom-store` unveraendert dagegen: man sieht am Testlauf, ob S3 sich wie
//! SQLite verhaelt, statt es im Betrieb herauszufinden.
//!
//! Die CAS-Semantik uebersetzt sich direkt: `expected` wird zu `If-Match` mit
//! dem ETag des Snapshots.

pub use openom_store::{Caps, DocStore, Snapshot, StoreError, Update};

/// Platzhalter, bis die S3-Anbindung steht.
pub struct S3Store {
    pub bucket: String,
    pub prefix: String,
}
