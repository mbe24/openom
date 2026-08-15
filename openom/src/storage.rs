//! Blob store — S3 request signing (`rusty-s3`) + reqwest transport.
//!
//! Two access patterns live here (see `SERVER-DATA-FORMAT.md` §12):
//!   - **Proxy** — tiny tree envelopes: the server PUT/GETs the bytes itself so the
//!     CAS pointer swap and the Postgres metadata write stay one atomic request
//!     ([`put_object`], [`get_object`], [`head_object`]).
//!   - **Presign** — large, immutable media blobs: the server hands the client a
//!     short-TTL signed URL so the bytes go client↔R2 directly, out of Lambda
//!     ([`presign_put`], [`presign_get`]).
//!
//! `rusty-s3` only *builds and signs* requests — no async runtime, no OpenSSL — and
//! reqwest (rustls) sends them. The same code talks to MinIO (dev) and Cloudflare R2
//! (prod). One concrete store, not a trait: both backends speak the same S3 API, so
//! a trait would be a speculative abstraction over a single impl.
//!
//! **Upload integrity is enforced at the PUT**, not at read: the caller passes the
//! SHA-256 of the exact bytes being stored, and we sign it into the request as
//! `x-amz-checksum-sha256`; the backend rejects a mismatched body with a 4xx
//! (verified against MinIO — see the `checksum_enforced_by_backend` test). This is
//! distinct from `Header.ciphertext_hash`, which covers only the inner ciphertext
//! and is re-checked reader-side (§12); the S3 checksum covers the whole object body.

use std::time::Duration;

use base64::Engine as _;
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use sha2::{Digest, Sha256};
use url::Url;

use crate::config::Config;

/// A signed-request builder + HTTP client bound to one bucket.
#[derive(Clone)]
pub struct S3Store {
    bucket: Bucket,
    /// Used by `copy_object` to build `x-amz-copy-source` (media path, M3).
    #[allow(dead_code)]
    bucket_name: String,
    credentials: Credentials,
    http: reqwest::Client,
}

/// How long a server-driven (proxy) signed URL stays valid. Short: the server
/// redeems it in the same request. Client-facing presign TTLs are passed per call.
const PROXY_TTL: Duration = Duration::from_secs(30);

/// The S3 header carrying a base64 SHA-256 the backend enforces on PUT.
const CHECKSUM_HEADER: &str = "x-amz-checksum-sha256";

/// What a HEAD surfaces without a download (§12 graceful-absence: `None` = gone).
#[derive(Debug, Clone)]
#[allow(dead_code)] // media confirm path (M3)
pub struct ObjectHead {
    pub size: u64,
    pub etag: Option<String>,
}

/// A presigned upload URL plus the headers the client MUST echo verbatim — the
/// signed `x-amz-checksum-sha256` among them, or the signature won't match.
#[derive(Debug, Clone)]
#[allow(dead_code)] // media upload path (M3); also built by the checksum test
pub struct PresignedUpload {
    pub url: String,
    pub required_headers: Vec<(String, String)>,
}

impl S3Store {
    pub fn from_config(config: &Config) -> Result<Self, StorageError> {
        let endpoint: Url = config.s3_endpoint.parse()?;
        // Path-style (`host/bucket/key`) — MinIO's default and what R2 accepts;
        // virtual-host style needs per-bucket DNS we don't control in dev.
        let bucket = Bucket::new(
            endpoint,
            UrlStyle::Path,
            config.s3_bucket.clone(),
            config.s3_region.clone(),
        )?;
        let credentials =
            Credentials::new(config.s3_access_key.clone(), config.s3_secret_key.clone());
        Ok(Self {
            bucket,
            bucket_name: config.s3_bucket.clone(),
            credentials,
            http: reqwest::Client::new(),
        })
    }

    /// Idempotently create the bucket (dev bootstrap; in prod the bucket is
    /// provisioned out of band). A 409 "already owns it" is success.
    pub async fn ensure_bucket(&self) -> Result<(), StorageError> {
        let url = self.bucket.create_bucket(&self.credentials).sign(PROXY_TTL);
        let resp = self.http.put(url).send().await?;
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::CONFLICT {
            Ok(())
        } else {
            Err(self.backend_err("create_bucket", resp).await)
        }
    }

    /// Proxy PUT of `body` at `key` (tree envelopes). The backend enforces the
    /// SHA-256 of the exact bytes, so a corrupted write is rejected here, not later.
    pub async fn put_object(&self, key: &str, body: Vec<u8>) -> Result<(), StorageError> {
        let checksum = sha256_b64(&body);
        let mut action = self.bucket.put_object(Some(&self.credentials), key);
        action.headers_mut().insert(CHECKSUM_HEADER, checksum.clone());
        let url = action.sign(PROXY_TTL);
        let resp = self
            .http
            .put(url)
            .header(CHECKSUM_HEADER, checksum)
            .body(body)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(self.backend_err("put_object", resp).await)
        }
    }

    /// Proxy GET. `None` if the object is absent (§12 graceful-404).
    pub async fn get_object(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(PROXY_TTL);
        let resp = self.http.get(url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(self.backend_err("get_object", resp).await);
        }
        Ok(Some(resp.bytes().await?.to_vec()))
    }

    /// Delete `key`. Absent-is-success (delete is idempotent; §12 graceful-absence).
    /// Used by the tree path to GC an object orphaned by a lost snapshot CAS.
    pub async fn delete_object(&self, key: &str) -> Result<(), StorageError> {
        let url = self
            .bucket
            .delete_object(Some(&self.credentials), key)
            .sign(PROXY_TTL);
        let resp = self.http.delete(url).send().await?;
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(self.backend_err("delete_object", resp).await)
        }
    }

    /// Build a `StorageError::Backend` from a failed response, including the body
    /// (S3 error XML) so the cause is legible in logs.
    async fn backend_err(&self, op: &str, resp: reqwest::Response) -> StorageError {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        StorageError::Backend(format!("{op} {status}: {body}"))
    }
}

/// Media path (`SERVER-DATA-FORMAT.md` §12) — wired in M3. `presign_put` is also
/// exercised now by the `checksum_enforced_by_backend` test.
#[allow(dead_code)]
impl S3Store {
    /// HEAD for size/etag. `None` if absent (§12 graceful-404). Used by the media
    /// confirm step (size ≤ cap) — integrity was already enforced at the PUT.
    pub async fn head_object(&self, key: &str) -> Result<Option<ObjectHead>, StorageError> {
        let url = self
            .bucket
            .head_object(Some(&self.credentials), key)
            .sign(PROXY_TTL);
        let resp = self.http.head(url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(self.backend_err("head_object", resp).await);
        }
        let size = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string());
        Ok(Some(ObjectHead { size, etag }))
    }

    /// Server-side copy `from` → `to` (media confirm: staging → final, §12). S3
    /// models a copy as a PUT to the destination carrying `x-amz-copy-source`.
    pub async fn copy_object(&self, from: &str, to: &str) -> Result<(), StorageError> {
        let source = format!("/{}/{}", self.bucket_name, from);
        let mut action = self.bucket.put_object(Some(&self.credentials), to);
        action.headers_mut().insert("x-amz-copy-source", &source);
        let url = action.sign(PROXY_TTL);
        let resp = self
            .http
            .put(url)
            .header("x-amz-copy-source", &source)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(self.backend_err("copy_object", resp).await)
        }
    }

    /// Presign a client media upload. `object_sha256_b64` is the base64 SHA-256 of
    /// the exact bytes the client will PUT; we sign it as `x-amz-checksum-sha256` so
    /// the backend rejects a mismatched body (§9.10 confirm relies on this). The
    /// client MUST send every `required_headers` entry verbatim.
    pub fn presign_put(
        &self,
        key: &str,
        object_sha256_b64: &str,
        ttl: Duration,
    ) -> PresignedUpload {
        let mut action = self.bucket.put_object(Some(&self.credentials), key);
        action.headers_mut().insert(CHECKSUM_HEADER, object_sha256_b64);
        let url = action.sign(ttl);
        PresignedUpload {
            url: url.to_string(),
            required_headers: vec![(CHECKSUM_HEADER.to_string(), object_sha256_b64.to_string())],
        }
    }

    /// Presign a client media download (membership-gated at mint time, §12).
    pub fn presign_get(&self, key: &str, ttl: Duration) -> String {
        self.bucket
            .get_object(Some(&self.credentials), key)
            .sign(ttl)
            .to_string()
    }
}

/// Base64 (standard, padded) SHA-256 — the `x-amz-checksum-sha256` encoding.
fn sha256_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes))
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("bad S3 endpoint url: {0}")]
    Url(#[from] url::ParseError),
    #[error("bucket config: {0}")]
    Bucket(#[from] rusty_s3::BucketError),
    #[error("http transport: {0}")]
    Http(String),
    #[error("backend: {0}")]
    Backend(String),
}

impl From<reqwest::Error> for StorageError {
    fn from(e: reqwest::Error) -> Self {
        // A reqwest error's Display embeds the request URL — and for a presigned
        // media URL that URL carries the SigV4 signature + credential in its query
        // string. `warn!(%err)` would then write an access grant into the logs (and
        // on to a third-party aggregator). `without_url()` strips it at the source,
        // so no caller can leak it by accident. See SERVER-DATA-FORMAT §7 discipline.
        StorageError::Http(e.without_url().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies the load-bearing assumption of the media confirm step (§9.10): the
    /// backend enforces `x-amz-checksum-sha256` **at the PUT**, rejecting a body that
    /// doesn't match. Hits a *live* S3 backend, so it is `#[ignore]`d — run it
    /// explicitly against whichever backend the env points at:
    ///
    /// - **MinIO** (proves the mechanism): bring up the compose stack, then
    ///   `S3_ENDPOINT=http://host.docker.internal:9000 cargo test -p openom --
    ///   checksum_enforced_by_backend --ignored --nocapture` (the container reaches
    ///   the host-published MinIO via `host.docker.internal`).
    /// - **R2** (the deploy-time reverification the spec flags as unverified): set
    ///   `S3_ENDPOINT`/`S3_BUCKET`/`S3_REGION=auto`/`S3_ACCESS_KEY`/`S3_SECRET_KEY`
    ///   to the R2 values and run the same command. A green run there closes the
    ///   "R2 enforcement unverified" caveat.
    #[tokio::test]
    #[ignore = "requires a live S3 backend; see doc comment"]
    async fn checksum_enforced_by_backend() {
        let config = Config::from_env();
        let store = S3Store::from_config(&config).expect("store");
        store.ensure_bucket().await.expect("ensure bucket");

        let good = b"openom checksum-enforcement probe".to_vec();
        let checksum = sha256_b64(&good);
        let key = "spike/checksum-enforcement-test";

        // Correct body against the signed checksum → accepted.
        let upload = store.presign_put(key, &checksum, Duration::from_secs(120));
        let ok = put_via(&store.http, &upload, good.clone()).await;
        assert!(ok.is_success(), "correct checksum should be accepted, got {ok}");

        // Wrong body against the same signed checksum → rejected at PUT.
        let tampered = b"openom checksum-enforcement probe -- tampered".to_vec();
        let bad = put_via(&store.http, &upload, tampered).await;
        assert!(
            bad.is_client_error(),
            "backend must reject a body that doesn't match the signed checksum, got {bad}"
        );
    }

    async fn put_via(
        http: &reqwest::Client,
        upload: &PresignedUpload,
        body: Vec<u8>,
    ) -> reqwest::StatusCode {
        let mut req = http.put(&upload.url).body(body);
        for (name, value) in &upload.required_headers {
            req = req.header(name, value);
        }
        req.send().await.expect("send").status()
    }
}
