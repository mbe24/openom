//! Tree envelope PUT/GET — the V1 write/read path.
//!
//! A tree is one encrypted snapshot Envelope stored in R2, pointed at by a Postgres
//! row. The server is a zero-knowledge blob store: it validates the envelope's
//! *self-consistency* (hash, kind, tree binding) and enforces the log contract
//! (§9), but never decrypts. Concurrency is **compare-and-swap on a Postgres-held
//! opaque version token** (§9.7), surfaced to the client as an HTTP `ETag` +
//! `If-Match` — deliberately *not* S3 `If-Match`, the least portable S3 feature.
//!
//! Write order (§9.7): write the new snapshot to a fresh R2 key, *then* CAS the
//! pointer. A CAS loss orphans the just-written object, which we delete immediately
//! (and a sweep would catch anyway).

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_TYPE, ETAG, IF_MATCH, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use openom_protocol::v1::{Envelope, Kind};
use openom_protocol::{Message, ENVELOPE_VERSION};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::Identity;
use crate::authz::Access;
use crate::AppState;

/// Per-object ceiling. The Lambda proxy path tops out around 6 MB (§9.9); tree
/// snapshots are far smaller, but the limit is enforced so a client can't wedge the
/// proxy. Media (large) takes the presigned path instead, never this one.
pub const MAX_OBJECT_BYTES: usize = 6 * 1024 * 1024;

/// The envelope fields the metadata row mirrors, extracted after validation.
struct Validated {
    aead: i16,
    ciphertext_hash: Vec<u8>,
    covers_through_seq: i64,
}

/// Validate an uploaded snapshot envelope against the V1 contract (§9.2–§9.6):
/// decodable, supported version, `KIND_SNAPSHOT`, bound to *this* tree, and a
/// `ciphertext_hash` the keyless server can — and must — recompute.
fn validate_snapshot(
    body: &[u8],
    tree_id: Uuid,
    reject_dev_key: bool,
) -> Result<Validated, ApiError> {
    let env = Envelope::decode(body)
        .map_err(|e| ApiError::BadRequest(format!("not a valid envelope: {e}")))?;
    if env.version != ENVELOPE_VERSION {
        return Err(ApiError::BadRequest(format!(
            "unsupported envelope version {} (server speaks {ENVELOPE_VERSION})",
            env.version
        )));
    }
    let header = env
        .header
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("envelope has no header".into()))?;
    if header.kind() != Kind::Snapshot {
        return Err(ApiError::BadRequest(
            "V1 accepts only KIND_SNAPSHOT on the tree path".into(),
        ));
    }
    // The header's opaque tree_id (16 raw UUID bytes) must match the URL, or the
    // client is filing this tree's bytes under another tree's coordinates.
    if header.tree_id.as_slice() != tree_id.as_bytes() {
        return Err(ApiError::BadRequest(
            "header tree_id does not match the url".into(),
        ));
    }
    // §16: the reserved dev key_id can never seal real user data. Refuse it in
    // production so a misconfigured dev client can't write with the well-known dev DEK.
    if reject_dev_key && header.key_id.as_slice() == openom_crypto::DEV_KEY_ID {
        return Err(ApiError::BadRequest(
            "dev key_id refused under RUN_MODE=production (§16)".into(),
        ));
    }
    // ciphertext_hash is a hash of *ciphertext*, so the keyless server verifies it.
    let computed = Sha256::digest(&env.ciphertext);
    if header.ciphertext_hash.as_slice() != computed.as_slice() {
        return Err(ApiError::BadRequest(
            "ciphertext_hash does not match the ciphertext".into(),
        ));
    }
    Ok(Validated {
        aead: header.aead as i16,
        ciphertext_hash: header.ciphertext_hash.clone(),
        covers_through_seq: header.covers_through_seq as i64,
    })
}

/// `PUT /trees/{tree_id}` — upload a new snapshot. `If-Match: "<version>"` names the
/// snapshot the edit was based on (CAS); its absence means "create, must not exist".
pub async fn put_tree(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("tree.put");
    let valid = validate_snapshot(&body, tree_id, !state.config.is_local())?;
    let expected = if_match(&headers);

    // New opaque version + fresh key; the object is written before the pointer CAS.
    let version = Uuid::new_v4().to_string();
    let r2_key = format!("trees/{tree_id}/snapshot/{version}");
    let size = body.len() as i64;

    state
        .storage
        .put_object(&r2_key, body.to_vec())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let outcome = match &expected {
        None => cas_create(&state, tree_id, identity.member_id, &r2_key, &version, size, &valid).await,
        Some(exp) => {
            cas_update(&state, tree_id, identity.member_id, &r2_key, &version, size, &valid, exp).await
        }
    };

    match outcome {
        Ok(()) => Ok((StatusCode::OK, [(ETAG, etag(&version))]).into_response()),
        Err(err) => {
            // GC the orphan we wrote before the failed CAS (best effort).
            if let Err(e) = state.storage.delete_object(&r2_key).await {
                tracing::warn!(%e, key = %r2_key, "could not delete orphaned snapshot object");
            }
            Err(err)
        }
    }
}

/// `GET /trees/{tree_id}` — the current snapshot bytes + its `ETag` version.
pub async fn get_tree(
    State(state): State<AppState>,
    identity: Identity,
    Path(tree_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _p = crate::prof::span("tree.get");
    let row: Option<(Uuid, String, Option<String>)> =
        sqlx::query_as("SELECT owner_id, r2_key, snapshot_version FROM trees WHERE id = $1")
            .bind(tree_id)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;

    let (owner_id, r2_key, version) = row.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner_id, identity.member_id, Access::Read).await?;
    let version = version.ok_or(ApiError::NotFound)?; // row exists but no snapshot yet

    let bytes = state
        .storage
        .get_object(&r2_key)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)?; // pointer present, object gone → graceful 404

    Ok((
        StatusCode::OK,
        [(ETAG, etag(&version)), (CONTENT_TYPE, "application/octet-stream".to_string())],
        bytes,
    )
        .into_response())
}

/// First snapshot for a tree: insert the row iff the tree is new *and* the owner is
/// under their `max_trees` entitlement (§9). 0 rows → disambiguate the reason.
async fn cas_create(
    state: &AppState,
    tree_id: Uuid,
    owner: Uuid,
    r2_key: &str,
    version: &str,
    size: i64,
    valid: &Validated,
) -> Result<(), ApiError> {
    let res = sqlx::query(
        "INSERT INTO trees
             (id, owner_id, r2_key, snapshot_version, envelope_version, aead,
              size_bytes, ciphertext_hash, covers_through_seq)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
         WHERE (SELECT count(*) FROM trees WHERE owner_id = $2)
             < (SELECT max_trees FROM accounts WHERE id = $2)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tree_id)
    .bind(owner)
    .bind(r2_key)
    .bind(version)
    .bind(ENVELOPE_VERSION as i32)
    .bind(valid.aead)
    .bind(size)
    .bind(&valid.ciphertext_hash)
    .bind(valid.covers_through_seq)
    .execute(&state.db)
    .await
    .map_err(internal)?;

    if res.rows_affected() == 1 {
        return Ok(());
    }

    // 0 rows: the tree already exists, or the entitlement/account gate blocked it.
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    match existing {
        // Exists and is ours → the client should have sent If-Match.
        Some(o) if o == owner => {
            tracing::info!(event = "snapshot_cas_conflict", reason = "exists_no_if_match");
            Err(ApiError::Conflict)
        }
        Some(_) => Err(ApiError::Forbidden),
        // Doesn't exist → the entitlement gate blocked it. Separate over-quota (a
        // countable product signal, §9.9) from an unknown account.
        None => {
            let limits: Option<(i64, i32)> = sqlx::query_as(
                "SELECT (SELECT count(*) FROM trees WHERE owner_id = $1), a.max_trees
                   FROM accounts a WHERE a.id = $1",
            )
            .bind(owner)
            .fetch_optional(&state.db)
            .await
            .map_err(internal)?;
            match limits {
                Some((count, max)) if count >= max as i64 => {
                    tracing::info!(event = "quota_rejected", resource = "trees", %owner);
                    Err(ApiError::QuotaExceeded)
                }
                None => Err(ApiError::Forbidden), // unknown account
                Some(_) => Err(ApiError::Conflict), // guard passed yet insert lost — retry
            }
        }
    }
}

/// Replace an existing snapshot under CAS: match the expected version and never let
/// `covers_through_seq` regress (§9.6). 0 rows → not found / not owner / stale.
#[allow(clippy::too_many_arguments)]
async fn cas_update(
    state: &AppState,
    tree_id: Uuid,
    caller: Uuid,
    r2_key: &str,
    version: &str,
    size: i64,
    valid: &Validated,
    expected: &str,
) -> Result<(), ApiError> {
    // Authorize through the seam on the tree's REAL owner, not the caller. A snapshot PUT is a
    // *commit*, so under B3 this widens to Maintainer+ by changing authorize() alone — previously the
    // owner check was inlined as `owner_id = caller` in the CAS predicate, which would have 403'd every
    // non-owner committer no matter what the seam said. Resolving the owner up front also lets the CAS
    // key purely on the version.
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal)?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    crate::authz::authorize(&state.db, tree_id, owner, caller, Access::Write).await?;

    let res = sqlx::query(
        "UPDATE trees
            SET r2_key = $1, snapshot_version = $2, envelope_version = $3, aead = $4,
                size_bytes = $5, ciphertext_hash = $6, covers_through_seq = $7,
                updated_at = now()
          WHERE id = $8 AND snapshot_version = $9
            AND $7 >= covers_through_seq",
    )
    .bind(r2_key)
    .bind(version)
    .bind(ENVELOPE_VERSION as i32)
    .bind(valid.aead)
    .bind(size)
    .bind(&valid.ciphertext_hash)
    .bind(valid.covers_through_seq)
    .bind(tree_id)
    .bind(expected)
    .execute(&state.db)
    .await
    .map_err(internal)?;

    if res.rows_affected() == 1 {
        return Ok(());
    }
    // Owner + existence already confirmed above, so a 0-row now is a stale version or a
    // covers_through_seq regression — the common concurrency case (§9.7).
    tracing::info!(event = "snapshot_cas_conflict", reason = "stale_version");
    Err(ApiError::Conflict)
}

/// Read `If-Match`, unwrapping the ETag quoting. `None` (or `*`) means "create".
fn if_match(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(IF_MATCH)?.to_str().ok()?.trim();
    let v = raw.trim_matches('"');
    if v.is_empty() || v == "*" {
        None
    } else {
        Some(v.to_string())
    }
}

/// A quoted (strong) ETag header value from an opaque version token.
fn etag(version: &str) -> String {
    format!("\"{version}\"")
}

fn internal(e: sqlx::Error) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// Handler error → HTTP status. Internal causes are logged, never leaked.
pub enum ApiError {
    Forbidden,
    NotFound,
    Conflict,
    QuotaExceeded,
    /// Append rate exceeded (abuse gate). Carries a Retry-After hint in seconds. A
    /// 429 — distinct from QuotaExceeded's 403 — because it's transient: the client
    /// should back off and retry, not treat it as a plan limit (§17).
    TooManyRequests(u64),
    /// The requested log tail is no longer retained — the client must bootstrap from a snapshot.
    Gone(String),
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Rate limiting carries a header, so build its response directly.
        if let ApiError::TooManyRequests(secs) = self {
            let mut resp =
                (StatusCode::TOO_MANY_REQUESTS, "append rate exceeded — retry after the indicated delay".to_string())
                    .into_response();
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(RETRY_AFTER, v);
            }
            return resp;
        }
        let (status, msg) = match self {
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::Conflict => (
                StatusCode::CONFLICT,
                "version conflict — pull the current snapshot and retry".to_string(),
            ),
            // 403 (not 402): entitlement is an authorization decision, not a payment
            // handshake. A distinct variant so it's a countable signal, not a generic
            // Forbidden (§9.9).
            ApiError::QuotaExceeded => {
                (StatusCode::FORBIDDEN, "account resource limit reached".to_string())
            }
            ApiError::TooManyRequests(_) => unreachable!("handled before the match (carries a header)"),
            ApiError::Gone(m) => (StatusCode::GONE, m),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Internal(m) => {
                tracing::error!(error = %m, "tree handler internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
        };
        (status, msg).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openom_protocol::v1::Header;

    // A validly-hashed snapshot envelope sealed under the reserved dev key_id (§16).
    fn dev_envelope(tree: Uuid) -> Vec<u8> {
        let ciphertext = b"opaque-dev-ciphertext".to_vec();
        let header = Header {
            kind: Kind::Snapshot as i32,
            tree_id: tree.as_bytes().to_vec(),
            key_id: openom_crypto::DEV_KEY_ID.to_vec(),
            ciphertext_hash: Sha256::digest(&ciphertext).to_vec(),
            ..Default::default()
        };
        Envelope { version: ENVELOPE_VERSION, header: Some(header), ciphertext }.encode_to_vec()
    }

    #[test]
    fn dev_key_refused_in_production_only() {
        let tree = Uuid::new_v4();
        let body = dev_envelope(tree);
        // Production (reject_dev_key = true) refuses the dev key_id.
        assert!(matches!(
            validate_snapshot(&body, tree, true),
            Err(ApiError::BadRequest(_))
        ));
        // Local dev (reject_dev_key = false) accepts it.
        assert!(validate_snapshot(&body, tree, false).is_ok());
    }
}
