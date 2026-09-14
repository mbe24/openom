//! Server integration tests — drive the real router (routing, extractors, handlers,
//! Postgres, and S3) in-process via `tower`'s `oneshot`, no socket. The presigned
//! media PUT/GET legs go out to `MinIO` over reqwest, exactly as a client would.
//!
//! These hit a **live** Postgres + `MinIO`, so they're `#[ignore]`d. They own only
//! random tree ids under the seeded dev account and assert invariants/deltas (not
//! absolute meter values), so they're safe to run against the shared local stack.
//!
//! Run against the compose stack from the cargo container (host-published services
//! reached via `host.docker.internal`):
//!
//! ```text
//! docker run --rm -v "$PWD:/work" -v openom-cargo-registry:/usr/local/cargo/registry \
//!   -v openom-cargo-target:/tmp/target -w /work -e CARGO_TARGET_DIR=/tmp/target \
//!   -e DATABASE_URL=postgres://openom:openom@host.docker.internal:5432/openom \
//!   -e S3_ENDPOINT=http://host.docker.internal:9000 \
//!   -e S3_PUBLIC_ENDPOINT=http://host.docker.internal:9000 \
//!   -e S3_BUCKET=openom-trees -e S3_REGION=us-east-1 \
//!   -e S3_ACCESS_KEY=openom -e S3_SECRET_KEY=openompw123 \
//!   --add-host host.docker.internal:host-gateway rust:1-bookworm \
//!   cargo test -p openom --test api -- --ignored --nocapture
//! ```

use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use base64::Engine as _;
use openom_keyring_chain::{generate_identity, keyring_hash, sign_keyring, SigningKey};
use openom_protocol::v1::{Aead, Envelope, Header, Kind, MemberRole};
use openom_keyring_chain::wire::{Keyring, Member};
use openom_protocol::Message;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

async fn router() -> Router {
    let config = openom::config::Config::from_env();
    let state = openom::build_state(&config).await.expect("build_state");
    openom::app(state)
}

/// A GC sweep mutates GLOBAL state: the reaper physically deletes EVERY marked log row / tombstoned blob past
/// its grace, across all trees — not just the tree under test. So a test that drives a sweep, or asserts on a
/// marked/tombstoned row that must survive, cannot run concurrently with another such test: one test's
/// grace-0 reap would delete the other's freshly-marked rows. This process-wide lock serializes exactly those
/// GC tests (acquire it as the first line); every non-GC test still runs fully in parallel.
static GC_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One in-process request; returns status, headers, and the collected body.
async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("router is infallible");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn sha256_b64(bytes: &[u8]) -> String {
    b64(Sha256::digest(bytes))
}

/// A real, prost-encoded snapshot envelope. `hash_of` lets a test forge a mismatched
/// `ciphertext_hash` (defaults to the true hash of `ciphertext`).
fn snapshot_envelope(tree: Uuid, ciphertext: &[u8], hash_of: Option<&[u8]>) -> Vec<u8> {
    let header = Header {
        kind: Kind::Snapshot as i32,
        aead: Aead::Xchacha20Poly1305 as i32,
        tree_id: tree.as_bytes().to_vec(),
        ciphertext_hash: Sha256::digest(hash_of.unwrap_or(ciphertext)).to_vec(),
        ..Default::default()
    };
    Envelope {
        version: 1,
        header: Some(header),
        ciphertext: ciphertext.to_vec(),
    }
    .encode_to_vec()
}

/// A real `KIND_PROPOSAL` envelope (no replica dot — each proposal is a fresh submission).
fn proposal_envelope(tree: Uuid, ciphertext: &[u8]) -> Vec<u8> {
    let header = Header {
        kind: Kind::Proposal as i32,
        aead: Aead::Xchacha20Poly1305 as i32,
        tree_id: tree.as_bytes().to_vec(),
        ciphertext_hash: Sha256::digest(ciphertext).to_vec(),
        ..Default::default()
    };
    Envelope {
        version: 1,
        header: Some(header),
        ciphertext: ciphertext.to_vec(),
    }
    .encode_to_vec()
}

/// A real delta envelope with a replica dot (`replica_id` + `replica_counter`).
fn delta_envelope(tree: Uuid, ciphertext: &[u8], replica: &[u8], counter: u64) -> Vec<u8> {
    let header = Header {
        kind: Kind::Delta as i32,
        aead: Aead::Xchacha20Poly1305 as i32,
        tree_id: tree.as_bytes().to_vec(),
        ciphertext_hash: Sha256::digest(ciphertext).to_vec(),
        replica_id: replica.to_vec(),
        replica_counter: counter,
        ..Default::default()
    };
    Envelope {
        version: 1,
        header: Some(header),
        ciphertext: ciphertext.to_vec(),
    }
    .encode_to_vec()
}

fn post_bytes(uri: String, body: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .body(Body::from(body.to_vec()))
        .unwrap()
}

/// As `post_bytes`, but authenticated as a specific member (local fake-auth accepts a
/// UUID bearer as the caller id — see auth.rs).
fn post_bytes_as(uri: String, body: &[u8], member: Uuid) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {member}"))
        .body(Body::from(body.to_vec()))
        .unwrap()
}

/// A bodyless POST authenticated as a specific member — e.g. `POST /v1/trees/{id}` (create-tree, OPE-407).
fn post_as(uri: String, member: Uuid) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {member}"))
        .body(Body::empty())
        .unwrap()
}

/// A blob PUT authenticated as a specific member. `if_absent` sends `if-none-match: *`
/// (`Precondition::IfAbsent`); otherwise no conditional header (`Precondition::Any`).
fn put_bytes_as(uri: String, body: &[u8], member: Uuid, if_absent: bool) -> Request<Body> {
    let mut b = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {member}"));
    if if_absent {
        b = b.header("if-none-match", "*");
    }
    b.body(Body::from(body.to_vec())).unwrap()
}

/// A snapshot PUT authenticated as a specific member (creates a tree owned by them).
fn put_tree_as(tree: Uuid, env: &[u8], member: Uuid) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(format!("/v1/trees/{tree}"))
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {member}"))
        .body(Body::from(env.to_vec()))
        .unwrap()
}

/// A pool straight to the test DB, to seed accounts with specific metering caps. Uses
/// the same `DATABASE_URL` the router builds its state from.
async fn db() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set for integration tests");
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect test db")
}

/// Insert (or reset) a fresh account with explicit metering caps, isolated from the
/// shared generous dev account. The bucket starts full (`log_tokens = log_burst`).
async fn seed_account(
    db: &sqlx::PgPool,
    id: Uuid,
    max_tree_bytes: i64,
    log_rate: f64,
    log_burst: i32,
) {
    sqlx::query(
        "INSERT INTO accounts (id, max_trees, max_tree_bytes, log_rate, log_burst, log_tokens, log_refilled_at)
         VALUES ($1, 1000, $2, $3, $4, $4::float8, now())
         ON CONFLICT (id) DO UPDATE SET
             max_tree_bytes = EXCLUDED.max_tree_bytes,
             log_rate = EXCLUDED.log_rate,
             log_burst = EXCLUDED.log_burst,
             log_tokens = EXCLUDED.log_tokens,
             tree_used_bytes = 0,
             log_refilled_at = now()",
    )
    .bind(id)
    .bind(max_tree_bytes)
    .bind(log_rate)
    .bind(log_burst)
    .execute(db)
    .await
    .expect("seed account");
}

/// Enable/limit proposals for an account (default seed leaves them disabled = free tier).
async fn set_proposal_meters(
    db: &sqlx::PgPool,
    id: Uuid,
    max_bytes: i64,
    max_open: i32,
    max_day: i32,
) {
    sqlx::query(
        "UPDATE accounts
            SET max_proposal_bytes = $2, max_open_proposals_per_tree = $3, max_proposals_per_member_day = $4
          WHERE id = $1",
    )
    .bind(id)
    .bind(max_bytes)
    .bind(max_open)
    .bind(max_day)
    .execute(db)
    .await
    .expect("set proposal meters");
}

/// Grant (or change) a member's role on a tree — stands in for slice 2's keyring-derived ACL.
/// Roles: 1 owner, 2 `co_owner`, 3 maintainer, 4 editor, 5 viewer.
async fn grant_role(db: &sqlx::PgPool, tree_id: Uuid, member: Uuid, role: i16) {
    sqlx::query(
        "INSERT INTO tree_access (tree_id, member_id, role) VALUES ($1, $2, $3)
         ON CONFLICT (tree_id, member_id) DO UPDATE SET role = EXCLUDED.role",
    )
    .bind(tree_id)
    .bind(member)
    .bind(role)
    .execute(db)
    .await
    .expect("grant role");
}

/// Turn on media entitlements for an account (so a `StageMedia` authz PASS isn't masked by an
/// entitlement 403).
async fn enable_media(db: &sqlx::PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE accounts SET allow_media = true, max_blob_bytes = 1048576,
             max_blob_count = 100, max_storage_bytes = 104857600 WHERE id = $1",
    )
    .bind(id)
    .execute(db)
    .await
    .expect("enable media");
}

/// A JSON media-intent body with a well-formed (base64 32-byte) object hash.
fn intent_body() -> Value {
    let hash = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    serde_json::json!({ "size_bytes": 100, "object_sha256": hash })
}

fn post_json_as(uri: String, json: &Value, member: Uuid) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {member}"))
        .body(Body::from(json.to_string()))
        .unwrap()
}

/// Build a signed keyring for `tree` at `revision`, with `owner` as the founder + owner-member and each
/// `(id, member_role)` in `extra` as an additional member (with the wraps `wrap_complete` requires),
/// signed by `founder`. Models the builder in openom-crypto's chain.rs tests, but uses real UUID member
/// ids so the server's ACL derivation can parse them. `prev_hash` empty for genesis.
fn build_keyring(
    tree: Uuid,
    revision: u32,
    prev_hash: Vec<u8>,
    founder: &SigningKey,
    owner: Uuid,
    extra: &[(Uuid, i32)],
) -> Keyring {
    let fpub = founder.verifying_key().to_bytes().to_vec();
    let owner_s = owner.to_string();
    let mut members = vec![Member {
        member_id: owner_s.clone(),
        role: MemberRole::Owner as i32,
        author_public_key: fpub.clone(),
        hpke_public_key: vec![9; 32],
    }];
    // Newest epoch: the founder's RRK wrap + an HPKE wrap per non-founder member. The DEK wraps are keyeo
    // key material now, encoded into the keyring's `epochs` bytes.
    let mkwrap = |id: &str, rrk: bool| {
        let encapped = keyeo_crypto::EncappedKey::from_bytes([0u8; 32]);
        let recipient_key = keyeo_crypto::X25519PublicKey::from_bytes([9u8; 32]);
        let method = if rrk {
            keyeo_crypto::WrapMethod::RrkHpke { encapped, recipient_key }
        } else {
            keyeo_crypto::WrapMethod::MemberHpke { encapped, recipient_key }
        };
        keyeo_crypto::Wrap {
            recipient: id.to_string(),
            method,
            ciphertext: keyeo_crypto::WrappedDek::from_bytes([1u8; 48]),
        }
    };
    let mut wraps = vec![mkwrap(&owner_s, true)];
    for (id, role) in extra {
        let s = id.to_string();
        members.push(Member {
            member_id: s.clone(),
            role: *role,
            author_public_key: vec![7; 32],
            hpke_public_key: vec![9; 32],
        });
        wraps.push(mkwrap(&s, false));
    }
    let mut k = Keyring {
        tree_id: tree.as_bytes().to_vec(),
        revision,
        layout_version: 1,
        prev_keyring_hash: prev_hash,
        // The signer set is derived from members: the OWNER-role member (built above) is the founder.
        members,
        signatures: vec![],
        recovery_keys: vec![],
        epochs: keyeo_crypto::codec::encode_epochs(&[keyeo_crypto::Epoch {
            key_id: keyeo_crypto::KeyId::new(vec![0]),
            ordinal: 0,
            dek_commitment: [0u8; 32],
            wraps,
        }]),
        ..Default::default()
    };
    sign_keyring(&mut k, founder);
    k
}

fn put_keyring_as(tree: Uuid, k: &Keyring, member: Uuid) -> Request<Body> {
    // Frame the signed Keyring as the client now does: MembershipEnvelope(chain) inside the KeyringUpdate
    // transport envelope. The server parses only the outer KeyringUpdate.
    let payload = openom_keyring_api::MembershipEnvelope::wrap(openom_keyring_api::EngineKind::Chain, k.encode_to_vec()).encode();
    let update = openom_protocol::v1::KeyringUpdate {
        version: 1,
        tree_id: tree.as_bytes().to_vec(),
        engine: "chain".to_string(),
        update_ref: openom_keyring_chain::encode_governing_ref(k.revision),
        payload,
    };
    Request::builder()
        .method("PUT")
        .uri(format!("/v1/trees/{tree}/keyring"))
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {member}"))
        .body(Body::from(update.encode_to_vec()))
        .unwrap()
}

async fn role_of(db: &sqlx::PgPool, tree: Uuid, member: Uuid) -> Option<i16> {
    sqlx::query_scalar("SELECT role FROM tree_access WHERE tree_id = $1 AND member_id = $2")
        .bind(tree)
        .bind(member)
        .fetch_optional(db)
        .await
        .unwrap()
}

/// A DELETE authenticated as a specific member.
fn delete_as(uri: String, member: Uuid) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {member}"))
        .body(Body::empty())
        .unwrap()
}

fn put_tree(tree: Uuid, env: &[u8], if_match: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("PUT")
        .uri(format!("/v1/trees/{tree}"))
        .header("content-type", "application/octet-stream");
    if let Some(v) = if_match {
        b = b.header("if-match", v);
    }
    b.body(Body::from(env.to_vec())).unwrap()
}
fn get(uri: String) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}
fn get_as(uri: String, member: Uuid) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {member}"))
        .body(Body::empty())
        .unwrap()
}
fn post(uri: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}
fn post_json(uri: String, json: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(json.to_string()))
        .unwrap()
}
fn etag(headers: &HeaderMap) -> String {
    headers.get("etag").unwrap().to_str().unwrap().to_string()
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn tree_lifecycle() {
    let app = router().await;
    let tree = Uuid::new_v4();

    let env1 = snapshot_envelope(tree, b"ciphertext-rev-1", None);
    let (s, h, _) = send(&app, put_tree(tree, &env1, None)).await;
    assert_eq!(s, StatusCode::OK, "create");
    let v1 = etag(&h);

    let (s, h, body) = send(&app, get(format!("/v1/trees/{tree}"))).await;
    assert_eq!(s, StatusCode::OK, "get");
    assert_eq!(body, env1, "byte round-trip");
    assert_eq!(etag(&h), v1, "etag matches");

    let env2 = snapshot_envelope(tree, b"ciphertext-rev-2-longer", None);
    let (s, h, _) = send(&app, put_tree(tree, &env2, Some(&v1))).await;
    assert_eq!(s, StatusCode::OK, "CAS update");
    assert_ne!(etag(&h), v1, "new version");

    let (s, _, _) = send(&app, put_tree(tree, &env2, Some(&v1))).await;
    assert_eq!(s, StatusCode::CONFLICT, "stale If-Match");

    // ciphertext_hash that doesn't match the ciphertext → 400.
    let bad = snapshot_envelope(tree, b"ciphertext-x", Some(b"something-else"));
    let (s, _, _) = send(&app, put_tree(tree, &bad, Some(&v1))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "tampered hash");

    let (s, _, _) = send(&app, get(format!("/v1/trees/{}", Uuid::new_v4()))).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "unknown tree");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn delta_log_lifecycle() {
    let app = router().await;
    let tree = Uuid::new_v4();
    // The tree must exist (created by an initial snapshot) before deltas append to it.
    send(
        &app,
        put_tree(tree, &snapshot_envelope(tree, b"ct", None), None),
    )
    .await;

    let ra = b"replica-aaaaaaaa".to_vec();
    let d0 = delta_envelope(tree, b"delta-zero", &ra, 0);
    let d1 = delta_envelope(tree, b"delta-one", &ra, 1);

    let (s, _, b0) = send(&app, post_bytes(format!("/v1/trees/{tree}/log"), &d0)).await;
    assert_eq!(s, StatusCode::OK, "append d0");
    assert_eq!(
        serde_json::from_slice::<Value>(&b0).unwrap()["seq"]
            .as_i64()
            .unwrap(),
        0
    );

    let (s, _, b1) = send(&app, post_bytes(format!("/v1/trees/{tree}/log"), &d1)).await;
    assert_eq!(s, StatusCode::OK, "append d1");
    assert_eq!(
        serde_json::from_slice::<Value>(&b1).unwrap()["seq"]
            .as_i64()
            .unwrap(),
        1
    );

    // Re-delivering d0 (same replica dot) is idempotent — same seq, no new entry.
    let (s, _, br) = send(&app, post_bytes(format!("/v1/trees/{tree}/log"), &d0)).await;
    assert_eq!(s, StatusCode::OK, "re-append idempotent");
    assert_eq!(
        serde_json::from_slice::<Value>(&br).unwrap()["seq"]
            .as_i64()
            .unwrap(),
        0
    );

    // Whole tail: both deltas, in order, payloads round-tripping the exact sealed bytes.
    let (s, _, tb) = send(&app, get(format!("/v1/trees/{tree}/log?since=-1"))).await;
    assert_eq!(s, StatusCode::OK, "read tail");
    let tail: Value = serde_json::from_slice(&tb).unwrap();
    let entries = tail["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        2,
        "two deltas, not three (re-delivery didn't duplicate)"
    );
    assert_eq!(tail["head_seq"].as_i64().unwrap(), 1);
    assert_eq!(tail["next_cursor"].as_i64().unwrap(), 1);
    assert!(
        !entries[0]["time"].as_str().unwrap().is_empty(),
        "entries carry a timestamp for the activity feed"
    );
    assert!(
        !entries[0]["member"].as_str().unwrap().is_empty(),
        "and an author"
    );
    let p0 = base64::engine::general_purpose::STANDARD
        .decode(entries[0]["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(p0, d0, "payload round-trips the sealed delta bytes");

    // From a cursor: only the tail after seq 0.
    let (s, _, tb2) = send(&app, get(format!("/v1/trees/{tree}/log?since=0"))).await;
    assert_eq!(s, StatusCode::OK, "read tail since 0");
    let tail2: Value = serde_json::from_slice(&tb2).unwrap();
    assert_eq!(
        tail2["entries"].as_array().unwrap().len(),
        1,
        "one delta after seq 0"
    );
    assert_eq!(tail2["entries"][0]["seq"].as_i64().unwrap(), 1);

    // Appending to a tree that doesn't exist → 404 (header tree_id matches the url so validation passes).
    let unknown = Uuid::new_v4();
    let (s, _, _) = send(
        &app,
        post_bytes(
            format!("/v1/trees/{unknown}/log"),
            &delta_envelope(unknown, b"x", &ra, 0),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "append to unknown tree");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn oversized_delta_spills_to_r2_and_reads_back() {
    let app = router().await;
    let db = db().await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree(tree, &snapshot_envelope(tree, b"ct", None), None),
    )
    .await;

    // A ciphertext well over the 32 KiB inline cap forces the spill path.
    let big = vec![0x5au8; 40 * 1024];
    let ra = b"replica-spill000".to_vec();
    let d = delta_envelope(tree, &big, &ra, 0);
    assert!(
        d.len() > 32 * 1024,
        "the envelope must exceed the inline cap to exercise spill"
    );

    let (s, _, b) = send(&app, post_bytes(format!("/v1/trees/{tree}/log"), &d)).await;
    assert_eq!(s, StatusCode::OK, "append oversized delta");
    let seq = serde_json::from_slice::<Value>(&b).unwrap()["seq"]
        .as_i64()
        .unwrap();

    // It really spilled: the row keeps no inline payload, only the R2 key.
    let (payload, object_key): (Option<Vec<u8>>, Option<String>) =
        sqlx::query_as("SELECT payload, object_key FROM tree_log WHERE tree_id = $1 AND seq = $2")
            .bind(tree)
            .bind(seq)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(payload.is_none(), "a spilled row stores no inline payload");
    assert!(object_key.is_some(), "a spilled row records its R2 key");

    // …yet the tail read resolves it transparently — the client gets the exact sealed bytes back,
    // indistinguishable from an inline delta.
    let (s, _, tb) = send(&app, get(format!("/v1/trees/{tree}/log?since=-1"))).await;
    assert_eq!(s, StatusCode::OK, "read tail");
    let tail: Value = serde_json::from_slice(&tb).unwrap();
    let got = base64::engine::general_purpose::STANDARD
        .decode(tail["entries"][0]["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        got, d,
        "the spilled payload round-trips the exact sealed delta bytes"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn cross_owner_access_forbidden() {
    // The single-owner boundary the authz seam enforces: a member who doesn't own a
    // tree gets 403 on every access. This is exactly the predicate B3 will widen to
    // role-based, so it doubles as a regression anchor for that change.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let other = Uuid::new_v4(); // a different member; needn't even have an account
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;

    let tree = Uuid::new_v4();
    let (s, h, _) = send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner creates the tree");
    let version = etag(&h);
    // Owner seeds one delta so the log read path has something to guard.
    let ra = b"replica-owner000".to_vec();
    send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/log"),
            &delta_envelope(tree, b"d0", &ra, 0),
            owner,
        ),
    )
    .await;

    // A non-owner is refused on read snapshot, read log, append, and a CAS snapshot update (the
    // seam now guards the PUT/commit path too — it used to inline owner_id in the SQL predicate).
    let (s, _, _) = send(&app, get_as(format!("/v1/trees/{tree}"), other)).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "non-owner cannot read the snapshot"
    );
    let cas = Request::builder()
        .method("PUT")
        .uri(format!("/v1/trees/{tree}"))
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {other}"))
        .header("if-match", version.trim_matches('"'))
        .body(Body::from(snapshot_envelope(tree, b"hostile-rev", None)))
        .unwrap();
    let (s, _, _) = send(&app, cas).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "non-owner cannot commit a snapshot update"
    );
    let (s, _, _) = send(&app, get_as(format!("/v1/trees/{tree}/log?since=-1"), other)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot read the log");
    let (s, _, _) = send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/log"),
            &delta_envelope(tree, b"x", b"replica-other000", 0),
            other,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot append");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn roles_read_propose_commit() {
    // The core role matrix: Read = Viewer+, Propose = Editor+, Commit (append) = Maintainer+.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, owner, 1 << 20, 50, 50).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let viewer = Uuid::new_v4();
    let editor = Uuid::new_v4();
    let maint = Uuid::new_v4();
    grant_role(&db, tree, viewer, 5).await;
    grant_role(&db, tree, editor, 4).await;
    grant_role(&db, tree, maint, 3).await;

    // Read — every member role can read snapshot, log, and proposals.
    for m in [viewer, editor, maint] {
        assert_eq!(
            send(&app, get_as(format!("/v1/trees/{tree}"), m)).await.0,
            StatusCode::OK,
            "read snapshot"
        );
        assert_eq!(
            send(&app, get_as(format!("/v1/trees/{tree}/log?since=-1"), m))
                .await
                .0,
            StatusCode::OK,
            "read log"
        );
        assert_eq!(
            send(&app, get_as(format!("/v1/trees/{tree}/proposals"), m))
                .await
                .0,
            StatusCode::OK,
            "read proposals"
        );
    }

    // Propose — Editor+ yes, Viewer no.
    let prop = proposal_envelope(tree, b"suggestion");
    for (member, want, msg) in [
        (viewer, StatusCode::FORBIDDEN, "viewer can't propose"),
        (editor, StatusCode::OK, "editor proposes"),
        (maint, StatusCode::OK, "maintainer proposes"),
    ] {
        let (s, ..) =
            send(&app, post_bytes_as(format!("/v1/trees/{tree}/proposals"), &prop, member)).await;
        assert_eq!(s, want, "{msg}");
    }

    // Commit (append a delta) — Maintainer+ yes, Editor + Viewer no.
    let d = |r: &'static [u8]| delta_envelope(tree, b"x", r, 0);
    for (member, replica, want, msg) in [
        (viewer, b"replica-viewer00", StatusCode::FORBIDDEN, "viewer can't commit"),
        (editor, b"replica-editor00", StatusCode::FORBIDDEN, "editor can't commit (V1 propose/approve)"),
        (maint, b"replica-maint000", StatusCode::OK, "maintainer commits"),
    ] {
        let (s, ..) =
            send(&app, post_bytes_as(format!("/v1/trees/{tree}/log"), &d(replica), member)).await;
        assert_eq!(s, want, "{msg}");
    }
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn roles_media() {
    // Media split: upload (StageMedia) = Editor+, attach (Commit) = Maintainer+.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    enable_media(&db, owner).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let viewer = Uuid::new_v4();
    let editor = Uuid::new_v4();
    let maint = Uuid::new_v4();
    grant_role(&db, tree, viewer, 5).await;
    grant_role(&db, tree, editor, 4).await;
    grant_role(&db, tree, maint, 3).await;

    // Upload (intent) — Editor+ passes authz (media enabled, so a pass isn't masked); Viewer 403.
    assert_eq!(
        send(
            &app,
            post_json_as(format!("/v1/trees/{tree}/media/intent"), &intent_body(), viewer)
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "viewer can't upload"
    );
    assert_eq!(
        send(
            &app,
            post_json_as(format!("/v1/trees/{tree}/media/intent"), &intent_body(), editor)
        )
        .await
        .0,
        StatusCode::OK,
        "editor uploads"
    );

    // Attach = Commit. Insert a live blob directly (no MinIO round-trip needed to test the gate).
    let blob = Uuid::new_v4();
    sqlx::query("INSERT INTO tree_blobs (tree_id, blob_id, object_key, size_bytes, state, ref_count) VALUES ($1,$2,$3,10,1,0)")
        .bind(tree).bind(blob.as_bytes().as_slice()).bind(format!("k/{blob}"))
        .execute(&db).await.unwrap();
    assert_eq!(
        send(
            &app,
            post_bytes_as(format!("/v1/trees/{tree}/media/{blob}/attach"), &[], editor)
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "editor can't attach (commit-adjacent)"
    );
    assert_eq!(
        send(
            &app,
            post_bytes_as(format!("/v1/trees/{tree}/media/{blob}/attach"), &[], maint)
        )
        .await
        .0,
        StatusCode::OK,
        "maintainer attaches"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn per_member_rate_isolation() {
    // One member exhausting their rate bucket must NOT throttle the owner (or co-members).
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 0.001, 1).await; // burst 1, negligible refill
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;
    let maint = Uuid::new_v4();
    grant_role(&db, tree, maint, 3).await;

    // The maintainer spends their single token, then is throttled.
    assert_eq!(
        send(
            &app,
            post_bytes_as(
                format!("/v1/trees/{tree}/log"),
                &delta_envelope(tree, b"m0", b"replica-maint000", 0),
                maint
            )
        )
        .await
        .0,
        StatusCode::OK,
        "maintainer's first append"
    );
    assert_eq!(
        send(
            &app,
            post_bytes_as(
                format!("/v1/trees/{tree}/log"),
                &delta_envelope(tree, b"m1", b"replica-maint000", 1),
                maint
            )
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS,
        "maintainer throttled"
    );
    // The owner has their OWN bucket — unaffected by the maintainer draining theirs.
    assert_eq!(
        send(
            &app,
            post_bytes_as(
                format!("/v1/trees/{tree}/log"),
                &delta_envelope(tree, b"o0", b"replica-owner000", 0),
                owner
            )
        )
        .await
        .0,
        StatusCode::OK,
        "owner not throttled by the maintainer"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_genesis_derives_acl() {
    // A genesis keyring PUT verifies + derives tree_access from its members, wiring slice 2 into the
    // slice-1 enforcement: the derived roles gate the endpoints.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, owner, 1 << 20, 50, 50).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let founder = generate_identity().unwrap();
    let editor = Uuid::new_v4();
    let viewer = Uuid::new_v4();
    let genesis = build_keyring(
        tree,
        1,
        vec![],
        &founder,
        owner,
        &[(editor, 4), (viewer, 5)],
    );

    let (s, _, body) = send(&app, put_keyring_as(tree, &genesis, owner)).await;
    assert_eq!(s, StatusCode::OK, "owner PUTs the genesis keyring");
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["revision"]
            .as_i64()
            .unwrap(),
        1
    );

    // ACL derived from the members list.
    assert_eq!(role_of(&db, tree, owner).await, Some(1), "owner");
    assert_eq!(role_of(&db, tree, editor).await, Some(4), "editor");
    assert_eq!(role_of(&db, tree, viewer).await, Some(5), "viewer");

    // And the derived roles actually gate: the editor may propose but not commit; the viewer neither.
    let prop = proposal_envelope(tree, b"p");
    assert_eq!(
        send(
            &app,
            post_bytes_as(format!("/v1/trees/{tree}/proposals"), &prop, editor)
        )
        .await
        .0,
        StatusCode::OK,
        "derived editor proposes"
    );
    assert_eq!(
        send(
            &app,
            post_bytes_as(
                format!("/v1/trees/{tree}/log"),
                &delta_envelope(tree, b"x", b"replica-editor00", 0),
                editor
            )
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "derived editor can't commit"
    );
    assert_eq!(
        send(
            &app,
            post_bytes_as(format!("/v1/trees/{tree}/proposals"), &prop, viewer)
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "derived viewer can't propose"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_transition_updates_and_removes() {
    // A verified successor updates the ACL: promote a member, then remove them.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let founder = generate_identity().unwrap();
    let m = Uuid::new_v4();
    let rev1 = build_keyring(tree, 1, vec![], &founder, owner, &[(m, 4)]); // editor
    assert_eq!(
        send(&app, put_keyring_as(tree, &rev1, owner)).await.0,
        StatusCode::OK,
        "genesis"
    );
    assert_eq!(role_of(&db, tree, m).await, Some(4));

    // rev2: promote m to maintainer (ordinary change, founder-signed), chaining onto rev1.
    let rev2 = build_keyring(
        tree,
        2,
        keyring_hash(&rev1).to_vec(),
        &founder,
        owner,
        &[(m, 3)],
    );
    assert_eq!(
        send(&app, put_keyring_as(tree, &rev2, owner)).await.0,
        StatusCode::OK,
        "promote"
    );
    assert_eq!(
        role_of(&db, tree, m).await,
        Some(3),
        "promoted to maintainer"
    );
    // Now m can commit.
    assert_eq!(
        send(
            &app,
            post_bytes_as(
                format!("/v1/trees/{tree}/log"),
                &delta_envelope(tree, b"c", b"replica-m0000000", 0),
                m
            )
        )
        .await
        .0,
        StatusCode::OK,
        "maintainer commits"
    );

    // rev3: remove m entirely → their ACL row is deleted → they're refused.
    let rev3 = build_keyring(tree, 3, keyring_hash(&rev2).to_vec(), &founder, owner, &[]);
    assert_eq!(
        send(&app, put_keyring_as(tree, &rev3, owner)).await.0,
        StatusCode::OK,
        "remove"
    );
    assert_eq!(
        role_of(&db, tree, m).await,
        None,
        "ACL row gone after removal"
    );
    assert_eq!(
        send(&app, get_as(format!("/v1/trees/{tree}/log?since=-1"), m))
            .await
            .0,
        StatusCode::FORBIDDEN,
        "removed member refused"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_rejects_rollback_fork_unsigned() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let founder = generate_identity().unwrap();
    let rev1 = build_keyring(tree, 1, vec![], &founder, owner, &[]);
    assert_eq!(
        send(&app, put_keyring_as(tree, &rev1, owner)).await.0,
        StatusCode::OK,
        "genesis"
    );

    // Rollback: re-PUT revision 1 while head is 1 → not a sequential successor → 409.
    assert_eq!(
        send(&app, put_keyring_as(tree, &rev1, owner)).await.0,
        StatusCode::CONFLICT,
        "rollback refused"
    );

    // Fork: a revision-2 with a wrong prev_keyring_hash → 409.
    let forked = build_keyring(tree, 2, vec![0u8; 32], &founder, owner, &[]);
    assert_eq!(
        send(&app, put_keyring_as(tree, &forked, owner)).await.0,
        StatusCode::CONFLICT,
        "fork refused"
    );

    // Unsigned/unauthorized: a valid-shaped rev2 signed by a stranger, not a prior signer → 400.
    let stranger = generate_identity().unwrap();
    let mut rev2 = build_keyring(tree, 2, keyring_hash(&rev1).to_vec(), &founder, owner, &[]);
    rev2.signatures.clear();
    sign_keyring(&mut rev2, &stranger);
    assert_eq!(
        send(&app, put_keyring_as(tree, &rev2, owner)).await.0,
        StatusCode::BAD_REQUEST,
        "unendorsed change refused"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_history() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let founder = generate_identity().unwrap();
    let rev1 = build_keyring(tree, 1, vec![], &founder, owner, &[]);
    let rev2 = build_keyring(tree, 2, keyring_hash(&rev1).to_vec(), &founder, owner, &[]);
    send(&app, put_keyring_as(tree, &rev1, owner)).await;
    send(&app, put_keyring_as(tree, &rev2, owner)).await;

    let (s, _, b) = send(&app, get_as(format!("/v1/trees/{tree}/keyring?from=1"), owner)).await;
    assert_eq!(s, StatusCode::OK);
    let h: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(h["head"].as_i64().unwrap(), 2);
    assert_eq!(
        h["revisions"].as_array().unwrap().len(),
        2,
        "whole chain from 1"
    );
    let p1 = base64::engine::general_purpose::STANDARD
        .decode(h["revisions"][0]["payload"].as_str().unwrap())
        .unwrap();
    // The stored payload is the engine-opaque Admitted.state = the MembershipEnvelope wrapping the Keyring.
    let env1 = openom_keyring_api::MembershipEnvelope::decode(&p1).unwrap();
    assert_eq!(env1.engine, "chain");
    assert_eq!(env1.body, rev1.encode_to_vec(), "the revision's keyring round-trips inside the envelope");

    let (_, _, b2) = send(&app, get_as(format!("/v1/trees/{tree}/keyring?from=2"), owner)).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&b2).unwrap()["revisions"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "tail from 2"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_put_requires_privilege() {
    // A non-member can't PUT a genesis; a viewer (derived) can't PUT a successor.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let founder = generate_identity().unwrap();
    let viewer = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    let genesis = build_keyring(tree, 1, vec![], &founder, owner, &[(viewer, 5)]);

    // A non-owner non-member can't establish the keyring.
    assert_eq!(
        send(&app, put_keyring_as(tree, &genesis, stranger)).await.0,
        StatusCode::FORBIDDEN,
        "stranger can't PUT genesis"
    );
    // Owner establishes it.
    assert_eq!(
        send(&app, put_keyring_as(tree, &genesis, owner)).await.0,
        StatusCode::OK
    );
    // The derived viewer lacks Administer → can't PUT a successor (refused before any crypto).
    let rev2 = build_keyring(
        tree,
        2,
        keyring_hash(&genesis).to_vec(),
        &founder,
        owner,
        &[(viewer, 5)],
    );
    assert_eq!(
        send(&app, put_keyring_as(tree, &rev2, viewer)).await.0,
        StatusCode::FORBIDDEN,
        "viewer can't PUT a keyring"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_accepts_a_recovery_reset() {
    // A recovery/succession reset: chains onto the head (hash + revision+1) but installs a NEW founder
    // without the old founder's endorsement (old key lost). The server accepts it (can't roll back / fork)
    // and flags it is_reset; the client re-verifies the signer change out of band.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let founder_a = generate_identity().unwrap();
    let rev1 = build_keyring(tree, 1, vec![], &founder_a, owner, &[]);
    assert_eq!(
        send(&app, put_keyring_as(tree, &rev1, owner)).await.0,
        StatusCode::OK,
        "genesis"
    );

    // Recovery: a fresh founder identity, chaining onto rev1 by hash at revision 2.
    let founder_b = generate_identity().unwrap();
    let reset = build_keyring(
        tree,
        2,
        keyring_hash(&rev1).to_vec(),
        &founder_b,
        owner,
        &[],
    );
    assert_eq!(
        send(&app, put_keyring_as(tree, &reset, owner)).await.0,
        StatusCode::OK,
        "recovery reset accepted"
    );
    assert_eq!(
        role_of(&db, tree, owner).await,
        Some(1),
        "owner ACL preserved across the reset"
    );

    // GET flags the reset revision (a UX hint for the OOB re-verify prompt).
    let (_, _, b) = send(&app, get_as(format!("/v1/trees/{tree}/keyring?from=2"), owner)).await;
    let h: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(h["head"].as_i64().unwrap(), 2);
    assert!(
        h["revisions"][0]["is_reset"].as_bool().unwrap(),
        "revision 2 is flagged a reset"
    );

    // A plain fork (wrong prev_hash) is NOT a reset — still refused.
    let forked = build_keyring(tree, 3, vec![0u8; 32], &founder_b, owner, &[]);
    assert_eq!(
        send(&app, put_keyring_as(tree, &forked, owner)).await.0,
        StatusCode::CONFLICT,
        "a fork is not a reset"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_reset_rate_capped() {
    // A reset bypasses the prior-signer signature gate, so per-tree resets are cooldown-capped.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let fa = generate_identity().unwrap();
    let rev1 = build_keyring(tree, 1, vec![], &fa, owner, &[]);
    send(&app, put_keyring_as(tree, &rev1, owner)).await;

    let fb = generate_identity().unwrap();
    let reset2 = build_keyring(tree, 2, keyring_hash(&rev1).to_vec(), &fb, owner, &[]);
    assert_eq!(
        send(&app, put_keyring_as(tree, &reset2, owner)).await.0,
        StatusCode::OK,
        "first reset"
    );

    // A second reset immediately after → within the cooldown → 429.
    let fc = generate_identity().unwrap();
    let reset3 = build_keyring(tree, 3, keyring_hash(&reset2).to_vec(), &fc, owner, &[]);
    assert_eq!(
        send(&app, put_keyring_as(tree, &reset3, owner)).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "reset cooldown"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_removal_purges_and_access_list() {
    // Removing a member (via a keyring transition) drops their ACL row AND reclaims their transient
    // state — open proposals + rate bucket — so they leave nothing behind. GET /access reflects it.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, owner, 1 << 20, 50, 50).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let founder = generate_identity().unwrap();
    let m = Uuid::new_v4();
    let rev1 = build_keyring(tree, 1, vec![], &founder, owner, &[(m, 3)]); // maintainer
    send(&app, put_keyring_as(tree, &rev1, owner)).await;

    // m leaves a footprint: a proposal + a delta (which creates their rate bucket).
    send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/proposals"),
            &proposal_envelope(tree, b"p"),
            m,
        ),
    )
    .await;
    send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/log"),
            &delta_envelope(tree, b"c", b"replica-m0000000", 0),
            m,
        ),
    )
    .await;
    let props: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM proposals WHERE tree_id = $1 AND proposer_member_id = $2",
    )
    .bind(tree)
    .bind(m)
    .fetch_one(&db)
    .await
    .unwrap();
    let rate: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM member_rate WHERE tree_id = $1 AND member_id = $2",
    )
    .bind(tree)
    .bind(m)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        (props, rate),
        (1, 1),
        "m has a proposal + a rate bucket before removal"
    );

    // The access list shows both members.
    let (_, _, ab) = send(&app, get_as(format!("/v1/trees/{tree}/access"), owner)).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&ab).unwrap()["members"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "owner + m"
    );

    // rev2 removes m.
    let rev2 = build_keyring(tree, 2, keyring_hash(&rev1).to_vec(), &founder, owner, &[]);
    assert_eq!(
        send(&app, put_keyring_as(tree, &rev2, owner)).await.0,
        StatusCode::OK,
        "remove m"
    );

    assert_eq!(role_of(&db, tree, m).await, None, "ACL row gone");
    let props: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM proposals WHERE tree_id = $1 AND proposer_member_id = $2",
    )
    .bind(tree)
    .bind(m)
    .fetch_one(&db)
    .await
    .unwrap();
    let rate: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM member_rate WHERE tree_id = $1 AND member_id = $2",
    )
    .bind(tree)
    .bind(m)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        (props, rate),
        (0, 0),
        "m's proposal + rate bucket reclaimed on removal"
    );
    let (_, _, ab2) = send(&app, get_as(format!("/v1/trees/{tree}/access"), owner)).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&ab2).unwrap()["members"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "only owner remains"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn proposals_lifecycle() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let other = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, owner, 1 << 20, 50, 50).await;

    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    // Submit a proposal.
    let prop = proposal_envelope(tree, b"suggested-edit-bundle");
    let (s, _, body) = send(
        &app,
        post_bytes_as(format!("/v1/trees/{tree}/proposals"), &prop, owner),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "submit proposal");
    let id = serde_json::from_slice::<Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // List it back — payload round-trips the exact sealed bytes, attributed to the proposer.
    let (s, _, lb) = send(&app, get_as(format!("/v1/trees/{tree}/proposals"), owner)).await;
    assert_eq!(s, StatusCode::OK, "list proposals");
    let list: Value = serde_json::from_slice(&lb).unwrap();
    let items = list["proposals"].as_array().unwrap();
    assert_eq!(items.len(), 1, "one open proposal");
    let payload = base64::engine::general_purpose::STANDARD
        .decode(items[0]["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(payload, prop, "proposal payload round-trips");
    assert!(
        !items[0]["proposer"].as_str().unwrap().is_empty(),
        "attributed to a member"
    );

    // A non-owner can neither list nor submit (the authz seam) — V1 owner-only.
    let (s, _, _) = send(&app, get_as(format!("/v1/trees/{tree}/proposals"), other)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot list proposals");
    let (s, _, _) = send(
        &app,
        post_bytes_as(format!("/v1/trees/{tree}/proposals"), &prop, other),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot propose");

    // Resolve (delete) it → gone from the open list; deleting again is idempotent.
    let (s, _, _) = send(
        &app,
        delete_as(format!("/v1/trees/{tree}/proposals/{id}"), owner),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "delete proposal");
    let (s, _, lb2) = send(&app, get_as(format!("/v1/trees/{tree}/proposals"), owner)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&lb2).unwrap()["proposals"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "no open proposals after resolve"
    );
    let (s, _, _) = send(
        &app,
        delete_as(format!("/v1/trees/{tree}/proposals/{id}"), owner),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "delete is idempotent");

    // The security property: a proposal must be refused on the delta-log path, so a hostile server
    // can never replay an editor's proposal into the authoritative tree history.
    let (s, _, _) = send(
        &app,
        post_bytes_as(format!("/v1/trees/{tree}/log"), &prop, owner),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "KIND_PROPOSAL refused on the log path"
    );
}

/// POST a fresh proposal `label` to `tree` as `member`; returns the status + response body.
async fn propose(app: &Router, tree: Uuid, label: &[u8], member: Uuid) -> (StatusCode, Vec<u8>) {
    let (s, _, body) = send(
        app,
        post_bytes_as(format!("/v1/trees/{tree}/proposals"), &proposal_envelope(tree, label), member),
    )
    .await;
    (s, body)
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn proposals_caps() {
    let app = router().await;
    let db = db().await;

    // (1) Free tier: proposals disabled (default meters = 0) → 403.
    let free = Uuid::new_v4();
    seed_account(&db, free, 1 << 30, 1000.0, 1000).await; // proposal meters left at 0
    let t_free = Uuid::new_v4();
    send(
        &app,
        put_tree_as(t_free, &snapshot_envelope(t_free, b"ct", None), free),
    )
    .await;
    let (s, _) = propose(&app, t_free, b"x", free).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "proposals disabled on the free tier"
    );

    // (2) Open-per-tree cap of 1: second concurrent proposal → 403; frees up after a delete.
    let cap = Uuid::new_v4();
    seed_account(&db, cap, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, cap, 1 << 20, 1, 50).await;
    let t_cap = Uuid::new_v4();
    send(
        &app,
        put_tree_as(t_cap, &snapshot_envelope(t_cap, b"ct", None), cap),
    )
    .await;
    let (s, b1) = propose(&app, t_cap, b"p1", cap).await;
    assert_eq!(s, StatusCode::OK, "first proposal fits");
    let id1 = serde_json::from_slice::<Value>(&b1).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, _) = propose(&app, t_cap, b"p2", cap).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "second exceeds the open-per-tree cap"
    );
    send(
        &app,
        delete_as(format!("/v1/trees/{t_cap}/proposals/{id1}"), cap),
    )
    .await;
    let (s, _) = propose(&app, t_cap, b"p3", cap).await;
    assert_eq!(s, StatusCode::OK, "a slot freed up after resolving one");

    // (3) Per-member/day cap of 1 backed by the ledger: survives delete-then-resubmit.
    let day = Uuid::new_v4();
    seed_account(&db, day, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, day, 1 << 20, 50, 1).await;
    let t_day = Uuid::new_v4();
    send(
        &app,
        put_tree_as(t_day, &snapshot_envelope(t_day, b"ct", None), day),
    )
    .await;
    let (s, bd) = propose(&app, t_day, b"d1", day).await;
    assert_eq!(s, StatusCode::OK, "first submission of the day");
    let idd = serde_json::from_slice::<Value>(&bd).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    send(
        &app,
        delete_as(format!("/v1/trees/{t_day}/proposals/{idd}"), day),
    )
    .await; // resolve it
    let (s, _) = propose(&app, t_day, b"d2", day).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "daily cap counts submissions, not open rows"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn proposals_ttl_swept() {
    let _gc = GC_TEST_LOCK.lock().await;
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, owner, 1 << 20, 50, 50).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let (_, _, body) = send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/proposals"),
            &proposal_envelope(tree, b"stale"),
            owner,
        ),
    )
    .await;
    let id = serde_json::from_slice::<Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    // Backdate its TTL so it's expired, then run the sweep.
    sqlx::query("UPDATE proposals SET expires_at = now() - interval '1 hour' WHERE id = $1::uuid")
        .bind(&id)
        .execute(&db)
        .await
        .unwrap();
    // Already invisible to reads before the physical sweep.
    let (_, _, lb) = send(&app, get_as(format!("/v1/trees/{tree}/proposals"), owner)).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&lb).unwrap()["proposals"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "expired hidden from reads"
    );
    // The sweep physically reclaims it.
    let (s, _, gb) = send(&app, post("/dev/media/gc".to_string())).await;
    assert_eq!(s, StatusCode::OK, "run dev gc");
    assert!(
        serde_json::from_slice::<Value>(&gb).unwrap()["proposals_expired"]
            .as_u64()
            .unwrap()
            >= 1,
        "swept ≥1 expired proposal"
    );
    // Gone even when explicitly asking for expired ones.
    let (_, _, lb2) = send(
        &app,
        get_as(
            format!("/v1/trees/{tree}/proposals?include_expired=true"),
            owner,
        ),
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&lb2).unwrap()["proposals"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "physically gone"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn log_rate_limit_429() {
    let app = router().await;
    let db = db().await;
    // A dedicated account with a one-token bucket that barely refills, so the second
    // *new* append trips the abuse gate. Generous byte cap — this isolates the rate axis.
    let member = Uuid::new_v4();
    seed_account(&db, member, 1 << 30, 0.001, 1).await;

    let tree = Uuid::new_v4();
    let (s, _, _) = send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), member),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "create tree as the throttled member");

    let ra = b"replica-rate0000".to_vec();
    // First new append spends the single token.
    let (s, _, _) = send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/log"),
            &delta_envelope(tree, b"d0", &ra, 0),
            member,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "first append within rate");

    // Second new append: bucket empty → 429 with a Retry-After hint.
    let (s, h, _) = send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/log"),
            &delta_envelope(tree, b"d1", &ra, 1),
            member,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "second append over rate");
    assert!(h.get("retry-after").is_some(), "429 carries Retry-After");

    // A re-delivery of the already-appended d0 is NOT metered — idempotent success even while throttled.
    let (s, _, _) = send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/log"),
            &delta_envelope(tree, b"d0", &ra, 0),
            member,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "re-delivery bypasses the rate gate");

    // Only d0 actually landed — the throttled append never persisted.
    let read = Request::builder()
        .uri(format!("/v1/trees/{tree}/log?since=-1"))
        .header("authorization", format!("Bearer {member}"))
        .body(Body::empty())
        .unwrap();
    let (s, _, tb) = send(&app, read).await;
    assert_eq!(s, StatusCode::OK);
    let tail: Value = serde_json::from_slice(&tb).unwrap();
    assert_eq!(
        tail["entries"].as_array().unwrap().len(),
        1,
        "throttled append never persisted"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn log_capacity_403() {
    let app = router().await;
    let db = db().await;
    // Generous rate, but we'll pin the byte cap to exactly one delta's worth mid-test.
    let member = Uuid::new_v4();
    seed_account(&db, member, 1 << 30, 1000.0, 1000).await;

    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), member),
    )
    .await;

    let ra = b"replica-cap00000".to_vec();
    let (s, _, _) = send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/log"),
            &delta_envelope(tree, b"d0", &ra, 0),
            member,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "first append within capacity");

    // Pin max_tree_bytes to exactly what's now used → the reserve is full.
    let used: i64 = sqlx::query_scalar("SELECT tree_used_bytes FROM accounts WHERE id = $1")
        .bind(member)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(used > 0, "the append charged the tree-byte meter");
    sqlx::query("UPDATE accounts SET max_tree_bytes = $2 WHERE id = $1")
        .bind(member)
        .bind(used)
        .execute(&db)
        .await
        .unwrap();

    // Next new append would overflow the reserve → 403 (a plan limit, not a transient throttle).
    let (s, _, _) = send(
        &app,
        post_bytes_as(
            format!("/v1/trees/{tree}/log"),
            &delta_envelope(tree, b"d1", &ra, 1),
            member,
        ),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "append over the tree-byte reserve"
    );

    // The rejected append charged nothing (rolled back).
    let after: i64 = sqlx::query_scalar("SELECT tree_used_bytes FROM accounts WHERE id = $1")
        .bind(member)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(after, used, "a rejected append leaves the meter untouched");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn media_lifecycle_and_gc() {
    let _gc = GC_TEST_LOCK.lock().await;
    let app = router().await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree(tree, &snapshot_envelope(tree, b"ct", None), None),
    )
    .await;

    // Intent → presigned staging PUT → confirm.
    let media = b"openom fake encrypted media blob".to_vec();
    let intent = post_json(
        format!("/v1/trees/{tree}/media/intent"),
        &serde_json::json!({ "size_bytes": media.len(), "object_sha256": sha256_b64(&media) }),
    );
    let (s, _, body) = send(&app, intent).await;
    assert_eq!(s, StatusCode::OK, "intent");
    let j: Value = serde_json::from_slice(&body).unwrap();
    let blob = j["blob_id"].as_str().unwrap().to_string();

    let client = reqwest::Client::new();
    let mut put = client
        .put(j["upload_url"].as_str().unwrap())
        .body(media.clone());
    for pair in j["required_headers"].as_array().unwrap() {
        let kv = pair.as_array().unwrap();
        put = put.header(kv[0].as_str().unwrap(), kv[1].as_str().unwrap().to_string());
    }
    assert!(
        put.send().await.unwrap().status().is_success(),
        "presigned PUT"
    );

    let (s, _, cbody) = send(&app, post(format!("/v1/trees/{tree}/media/{blob}/confirm"))).await;
    assert_eq!(s, StatusCode::OK, "confirm");
    let cj: Value = serde_json::from_slice(&cbody).unwrap();
    assert_eq!(usize::try_from(cj["size_bytes"].as_u64().unwrap()).unwrap(), media.len());

    // Presigned download round-trips the exact bytes.
    let (s, _, gbody) = send(&app, get(format!("/v1/trees/{tree}/media/{blob}"))).await;
    assert_eq!(s, StatusCode::OK, "get media");
    let gj: Value = serde_json::from_slice(&gbody).unwrap();
    let dl = reqwest::get(gj["download_url"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        dl.bytes().await.unwrap().as_ref(),
        media.as_slice(),
        "download round-trip"
    );

    // attach → detach-to-zero → tombstone → sweep physically deletes → 404.
    send(&app, post(format!("/v1/trees/{tree}/media/{blob}/attach"))).await;
    let (_, _, dbody) = send(&app, post(format!("/v1/trees/{tree}/media/{blob}/detach"))).await;
    let dj: Value = serde_json::from_slice(&dbody).unwrap();
    assert_eq!(
        dj["state"].as_str().unwrap(),
        "tombstoned",
        "detach-to-zero tombstones"
    );

    let (s, _, sbody) = send(
        &app,
        post("/dev/media/gc?tombstone_grace_secs=0&pending_expiry_secs=999999".into()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "sweep");
    let sj: Value = serde_json::from_slice(&sbody).unwrap();
    assert!(
        sj["physically_deleted"].as_u64().unwrap() >= 1,
        "swept the tombstone"
    );

    let (s, _, _) = send(&app, get(format!("/v1/trees/{tree}/media/{blob}"))).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "gone after sweep");
}

// ---- membership summary (OPE-278 / server-keyring-decoupling) ----

fn put_json_as(uri: String, json: &Value, member: Uuid) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {member}"))
        .body(Body::from(json.to_string()))
        .unwrap()
}

/// A summary body: opaque basis tokens, the CAS `expected_generation`, and `(member_id, role)` pairs.
fn summary_body(basis: &[&str], expected: Option<i64>, members: &[(Uuid, i16)]) -> Value {
    serde_json::json!({
        "basis": basis,
        "expected_generation": expected,
        "members": members
            .iter()
            .map(|(id, role)| serde_json::json!({ "member_id": id.to_string(), "role": role }))
            .collect::<Vec<_>>(),
    })
}

async fn new_tree(app: &Router, db: &sqlx::PgPool, owner: Uuid) -> Uuid {
    seed_account(db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;
    tree
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn access_summary_derives_acl_generation_and_basis() {
    // The client pushes an engine-neutral advisory summary; the server derives the ACL WITHOUT parsing a
    // keyring, and GET returns members + the CAS generation + the opaque basis for the client's next push.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;
    let editor = Uuid::new_v4();
    let uri = format!("/v1/trees/{tree}/access");

    let (s, _, body) = send(
        &app,
        put_json_as(uri.clone(), &summary_body(&["op:aa", "op:bb"], None, &[(owner, 1), (editor, 4)]), owner),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner pushes the first summary");
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["generation"].as_i64().unwrap(), 1);

    assert_eq!(role_of(&db, tree, owner).await, Some(1), "owner in the ACL");
    assert_eq!(role_of(&db, tree, editor).await, Some(4), "editor derived from the summary");

    let (s, _, body) = send(&app, get_as(uri, owner)).await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["generation"].as_i64().unwrap(), 1);
    assert_eq!(v["basis"], serde_json::json!(["op:aa", "op:bb"]), "the opaque basis round-trips");
    assert_eq!(v["members"].as_array().unwrap().len(), 2);
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn access_summary_cas_and_idempotent_reassert() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;
    let editor = Uuid::new_v4();
    let viewer = Uuid::new_v4();
    let uri = format!("/v1/trees/{tree}/access");
    let g = |body: &[u8]| serde_json::from_slice::<Value>(body).unwrap()["generation"].as_i64().unwrap();

    // First push (expects no summary yet) → generation 1.
    let (_, _, b) = send(&app, put_json_as(uri.clone(), &summary_body(&["op:1"], None, &[(owner, 1), (editor, 4)]), owner)).await;
    assert_eq!(g(&b), 1);

    // Idempotent re-assert (same members) → 200, generation NOT bumped.
    let (s, _, b) = send(&app, put_json_as(uri.clone(), &summary_body(&["op:1"], Some(1), &[(owner, 1), (editor, 4)]), owner)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(g(&b), 1, "an identical re-assert does not bump the generation");
    assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["unchanged"], serde_json::json!(true));

    // A real change (add a viewer) → generation 2.
    let (_, _, b) = send(&app, put_json_as(uri.clone(), &summary_body(&["op:2"], Some(1), &[(owner, 1), (editor, 4), (viewer, 5)]), owner)).await;
    assert_eq!(g(&b), 2);
    assert_eq!(role_of(&db, tree, viewer).await, Some(5));

    // A stale push (wrong expected generation) → 409, and it does not apply.
    let (s, _, _) = send(&app, put_json_as(uri, &summary_body(&["op:2"], Some(1), &[(owner, 1)]), owner)).await;
    assert_eq!(s, StatusCode::CONFLICT, "a stale generation is a CAS conflict");
    assert_eq!(role_of(&db, tree, viewer).await, Some(5), "the refused push did not drop the viewer");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn access_summary_signer_gate() {
    // The summary has no crypto backstop, so the push is gated at SIGNER level (owner or co-owner). A
    // Maintainer (role 3) and a stranger are refused; a co-owner is allowed.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;
    let coowner = Uuid::new_v4();
    let maint = Uuid::new_v4();
    let editor = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    let uri = format!("/v1/trees/{tree}/access");

    // Owner establishes the roster.
    send(&app, put_json_as(uri.clone(), &summary_body(&["op:1"], None, &[(owner, 1), (coowner, 2), (maint, 3), (editor, 4)]), owner)).await;

    // A co-owner may push (adds a viewer).
    let viewer = Uuid::new_v4();
    let (s, _, _) = send(&app, put_json_as(uri.clone(), &summary_body(&["op:2"], Some(1), &[(owner, 1), (coowner, 2), (maint, 3), (editor, 4), (viewer, 5)]), coowner)).await;
    assert_eq!(s, StatusCode::OK, "a co-owner may assert membership");

    // A Maintainer (role 3) may NOT.
    let (s, _, _) = send(&app, put_json_as(uri.clone(), &summary_body(&["op:3"], Some(2), &[(owner, 1)]), maint)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a Maintainer is below the signer gate");

    // A stranger with no role may NOT.
    let (s, _, _) = send(&app, put_json_as(uri, &summary_body(&["op:3"], Some(2), &[(owner, 1)]), stranger)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a non-member is refused");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn access_summary_owner_invariant_and_validation() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;
    let editor = Uuid::new_v4();
    let uri = format!("/v1/trees/{tree}/access");

    // A summary that OMITS the owner still keeps the owner in the ACL at role Owner (owner is invariant).
    let (s, _, _) = send(&app, put_json_as(uri.clone(), &summary_body(&["op:1"], None, &[(editor, 4)]), owner)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(role_of(&db, tree, owner).await, Some(1), "the owner row is never dropped");
    assert_eq!(role_of(&db, tree, editor).await, Some(4));

    // An empty member list is refused (never nuke the ACL).
    let (s, _, _) = send(&app, put_json_as(uri.clone(), &summary_body(&[], Some(1), &[]), owner)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "empty membership is refused");

    // A non-UUID member_id is refused (the advisory layer keys on the account UUID).
    let bad_id = serde_json::json!({ "basis": ["op:1"], "expected_generation": 1, "members": [{ "member_id": "not-a-uuid", "role": 4 }] });
    let (s, _, _) = send(&app, put_json_as(uri.clone(), &bad_id, owner)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "member_id must be a uuid");

    // A role outside 1..=5 is refused.
    let bad_role = summary_body(&["op:1"], Some(1), &[(owner, 1), (editor, 9)]);
    let (s, _, _) = send(&app, put_json_as(uri, &bad_role, owner)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "role out of range is refused");
}

// ---- OPE-398 data-channel blob store (blobs.rs) ----------------------------------------------------

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn blob_put_404s_on_nonexistent_tree() {
    // OPE-407 (decision 3-B): a blob write no longer mints. A PUT to a tree that was never created via
    // `POST /trees/{id}` is a 404 — the tree row must exist first.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();

    let (s, _, _) = send(
        &app,
        put_bytes_as(
            format!("/v1/trees/{tree}/blobs/log/replicaAAA/0"),
            b"delta-bytes",
            owner,
            true,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "a blob write to an uncreated tree 404s");

    let row: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree)
        .fetch_optional(&db)
        .await
        .unwrap();
    assert_eq!(row, None, "the failed write minted nothing");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn create_tree_then_blob_write_succeeds() {
    // The OPE-407 provisioning shape: POST /trees/{id} first (entitlement-gated mint, caller becomes owner),
    // then the blob writes the client's data channel makes land normally.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();

    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{tree}"), owner)).await;
    assert_eq!(s, StatusCode::CREATED, "create-tree mints the row");
    let row_owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_id FROM trees WHERE id = $1")
        .bind(tree)
        .fetch_optional(&db)
        .await
        .unwrap();
    assert_eq!(row_owner, Some(owner), "the creator is the owner");

    let (s, h, _) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/log/replicaAAA/0"), b"delta", owner, true),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "a blob write to the created tree succeeds");
    assert!(h.get("etag").is_some());
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn create_tree_idempotent_for_owner_forbidden_for_others() {
    // Idempotent for the owner (a returning device re-POSTs → 200, not an error); refused for a different
    // caller (never hijack an existing tree → 403).
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let intruder = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    seed_account(&db, intruder, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();

    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{tree}"), owner)).await;
    assert_eq!(s, StatusCode::CREATED, "first create");
    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{tree}"), owner)).await;
    assert_eq!(s, StatusCode::OK, "the owner re-creating is an idempotent 200");
    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{tree}"), intruder)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a different caller cannot claim an existing tree");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn create_tree_enforces_max_trees_limit() {
    // The entitlement gate counts real rows: at max_trees=2 the first two creates succeed and the third is
    // refused (403 QuotaExceeded) — exercising the `count < max` arithmetic, not just the degenerate 0.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    sqlx::query("UPDATE accounts SET max_trees = 2 WHERE id = $1")
        .bind(owner)
        .execute(&db)
        .await
        .unwrap();

    for _ in 0..2 {
        let (s, _, _) = send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)).await;
        assert_eq!(s, StatusCode::CREATED, "creates up to max_trees succeed");
    }
    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "the create past max_trees is refused");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn create_tree_concurrent_creates_respect_max_trees() {
    // The entitlement gate must be ATOMIC: with exactly one free slot, several concurrent creates of
    // different ids by one owner must not all pass (a bare count-then-insert races under READ COMMITTED).
    // The accounts-row lock serializes them → exactly one wins, and the owner never exceeds the cap.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    sqlx::query("UPDATE accounts SET max_trees = 1 WHERE id = $1")
        .bind(owner)
        .execute(&db)
        .await
        .unwrap();

    let (a, b, c, d) = tokio::join!(
        send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)),
        send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)),
        send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)),
        send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)),
    );
    let created = [a.0, b.0, c.0, d.0]
        .iter()
        .filter(|s| **s == StatusCode::CREATED)
        .count();
    assert_eq!(created, 1, "exactly one concurrent create wins the single free slot");

    let tree_count: i64 = sqlx::query_scalar("SELECT count(*) FROM trees WHERE owner_id = $1")
        .bind(owner)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(tree_count, 1, "the owner never exceeds max_trees under a concurrent race");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn create_tree_then_get_tree_404s_gracefully() {
    // A data-channel tree has no scalar snapshot, so GET /trees/{id} (the scalar path) 404s gracefully via
    // its `snapshot_version IS NULL` check — the create-tree row and the scalar-snapshot path don't collide.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();

    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{tree}"), owner)).await;
    assert_eq!(s, StatusCode::CREATED, "create-tree mints the row");
    let (s, _, _) = send(&app, get_as(format!("/v1/trees/{tree}"), owner)).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "a snapshot-less tree 404s on the scalar GET, not 500");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn create_tree_is_rate_limited_per_account() {
    // OPE-408: POST /trees is rate-gated per account. With a 1-token bucket (and ~no refill), the first create
    // spends the token and the second is 429 — independent of the entitlement gate (max_trees is 1000 here, so
    // it's the RATE gate firing, not the quota). Closes the "scriptable create with no backoff" DB-load vector.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 0.001, 1).await; // 1-token create bucket, negligible refill

    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)).await;
    assert_eq!(s, StatusCode::CREATED, "first create spends the one token");
    let (s, h, _) = send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "the second create is rate-limited, not entitlement-blocked");
    assert!(h.get("retry-after").is_some(), "the 429 carries Retry-After");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn create_tree_rate_debits_even_a_rejected_attempt() {
    // The debit is committed independently of the create tx, so an attempt that is REJECTED downstream still
    // spends a token — else a hammer hitting the entitlement 403 would face no backoff. With max_trees=1 and a
    // 2-token bucket: create #1 succeeds (token 2→1), create #2 is over-quota 403 (token 1→0), create #3 is
    // 429 (bucket empty) — proving the 403 attempt consumed its token.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 0.001, 2).await; // 2-token bucket, negligible refill
    sqlx::query("UPDATE accounts SET max_trees = 1 WHERE id = $1").bind(owner).execute(&db).await.unwrap();

    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)).await;
    assert_eq!(s, StatusCode::CREATED, "create #1 succeeds (token 2->1)");
    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "create #2 is over-quota (403) but still spends a token (1->0)");
    let (s, _, _) = send(&app, post_as(format!("/v1/trees/{}", Uuid::new_v4()), owner)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "create #3 is 429 — the rejected #2 consumed its token");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn blob_put_get_roundtrip_pointer() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;

    let (s, h, _) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), b"7", owner, false),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "pointer put (Precondition::Any)");
    let e1 = etag(&h);

    let (s, h2, body) = send(
        &app,
        get_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), owner),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "get roundtrip");
    assert_eq!(body, b"7");
    assert_eq!(etag(&h2), e1, "get etag matches put etag");

    // Unconditional overwrite — no conflict, new etag.
    let (s, h3, _) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), b"8", owner, false),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "pointer overwrite");
    assert_ne!(etag(&h3), e1, "new content, new etag");
    let (_, _, body2) = send(
        &app,
        get_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), owner),
    )
    .await;
    assert_eq!(body2, b"8", "the overwrite landed");

    // Missing key -> 404 (graceful absence).
    let (s, _, _) = send(
        &app,
        get_as(format!("/v1/trees/{tree}/blobs/heads/replicaZZZ"), owner),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "missing key");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn blob_if_absent_create_then_conflict_and_idempotent_retry() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;
    let key = format!("/v1/trees/{tree}/blobs/log/replicaAAA/0");

    let (s, h, _) = send(&app, put_bytes_as(key.clone(), b"delta-zero", owner, true)).await;
    assert_eq!(s, StatusCode::OK, "immutable create");
    let e1 = etag(&h);

    // A different-content PUT to the same immutable key conflicts.
    let (s, h2, _) = send(&app, put_bytes_as(key.clone(), b"delta-different", owner, true)).await;
    assert_eq!(
        s,
        StatusCode::PRECONDITION_FAILED,
        "IfAbsent on an existing key conflicts"
    );
    assert_eq!(etag(&h2), e1, "412 carries the existing etag");

    // The identical-content retry a client actually sends on a crash-retry is the same shape — still
    // 412s (the client treats this as idempotent success, remoteStore.js:224) — and the stored bytes are
    // untouched either way.
    let (s, _, _) = send(&app, put_bytes_as(key.clone(), b"delta-zero", owner, true)).await;
    assert_eq!(
        s,
        StatusCode::PRECONDITION_FAILED,
        "identical-content retry still 412s"
    );

    let (_, _, body) = send(&app, get_as(key, owner)).await;
    assert_eq!(body, b"delta-zero", "the conflicting writes did not land");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn blob_list_by_prefix() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;

    send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), b"1", owner, false),
    )
    .await;
    send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/replicaBBB"), b"2", owner, false),
    )
    .await;
    send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/log/replicaAAA/0"), b"d", owner, true),
    )
    .await;
    // A snapshot PUT now MANDATES the covered-frontier header (OPE-409); an empty map is valid here (this
    // test exercises listing, not coverage).
    send(
        &app,
        put_bytes_with_headers_as(
            format!("/v1/trees/{tree}/blobs/snapshot"),
            b"s",
            owner,
            &[("x-openom-covered", &covered_b64(&[]))],
        ),
    )
    .await;

    let (s, _, b) = send(
        &app,
        get_as(format!("/v1/trees/{tree}/blobs?prefix=heads/"), owner),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_slice(&b).unwrap();
    let mut keys: Vec<String> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["key"].as_str().unwrap().to_string())
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["heads/replicaAAA".to_string(), "heads/replicaBBB".to_string()],
        "prefix scopes the listing, relative to the tree segment"
    );

    // No prefix -> everything.
    let (s, _, b2) = send(&app, get_as(format!("/v1/trees/{tree}/blobs"), owner)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&b2).unwrap()["keys"]
            .as_array()
            .unwrap()
            .len(),
        4,
        "an empty prefix lists everything under the tree"
    );

    // A tree with no blobs yet -> empty list, not an error.
    let empty_tree = new_tree(&app, &db, owner).await;
    let (s, _, eb) = send(&app, get_as(format!("/v1/trees/{empty_tree}/blobs"), owner)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&eb).unwrap()["keys"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn blob_http_conformance() {
    // OPE-403: the HTTP-level analog of store-blob's conformance suite (packages/store-blob/src/conformance.rs).
    // The managed backend deliberately does NOT `impl store_blob::BlobStore` — that trait is SYNCHRONOUS (for
    // in-process Fs/Memory backends); this backend is async Axum handlers over R2 (bytes) + Neon (index/CAS)
    // that realize the SAME get / put(precondition) / list contract over HTTP. So we assert the contract at the
    // endpoints, clause-for-clause against conformance::run, using a MemoryBlob as the etag oracle.
    use store_blob::{BlobStore, MemoryBlob, Precondition};

    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;
    let blob = |k: &str| format!("/v1/trees/{tree}/blobs/{k}");
    let oracle = MemoryBlob::new(); // the reference impl the Fs/Memory conformance runs against

    // get_missing_is_none → a missing key is 404 (the HTTP analog of `None`).
    let (s, _, _) = send(&app, get_as(blob("ptr/missing"), owner)).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "get of a missing key is 404 (None)");

    // put_then_get_roundtrips + ETAG PARITY: the managed etag equals what the reference MemoryBlob yields for
    // the same bytes (both are hex(sha256)), so a client reading R2 sees the SAME etag as one reading
    // MemoryBlob/FsBlob — the cross-store etag convention the whole sync layer relies on.
    // Use a generic `ptr/` key — the OPAQUE pointer path — NOT `heads/`: `heads/{replica}` is deliberately
    // semantic (head-monotonicity parses its body as an ASCII decimal count, blobs.rs), so opaque bytes there
    // are a 400 by design. The generic-namespace pointer is what realizes the opaque BlobStore contract.
    let (s, h, _) = send(&app, put_bytes_as(blob("ptr/rA"), b"hello", owner, false)).await;
    assert_eq!(s, StatusCode::OK, "pointer put (Precondition::Any)");
    let put_etag = etag(&h);
    // The managed etag arrives as an RFC-quoted HTTP header (`"<hex>"`); the in-process MemoryBlob oracle
    // yields the bare hex. Compare the unquoted VALUE — that hex is the cross-store convention (both hex(sha256)).
    assert_eq!(
        put_etag.trim_matches('"'),
        oracle.put("ptr/rA", b"hello", Precondition::Any).unwrap(),
        "managed etag (unquoted) matches the store-blob reference convention (cross-store parity)"
    );
    let (s, h2, body) = send(&app, get_as(blob("ptr/rA"), owner)).await;
    assert_eq!(s, StatusCode::OK, "get roundtrips");
    assert_eq!(body, b"hello", "get returns the put bytes");
    assert_eq!(etag(&h2), put_etag, "get etag matches put etag");

    // idempotent_put_same_etag → identical content (Precondition::Any) yields the same etag.
    let (_, h3, _) = send(&app, put_bytes_as(blob("ptr/rA"), b"hello", owner, false)).await;
    assert_eq!(etag(&h3), put_etag, "identical content yields the same etag");

    // if_absent_creates_then_conflicts → IfAbsent creates; a conflicting IfAbsent 412s carrying the existing
    // etag; the first value stands.
    let (s, hc, _) = send(&app, put_bytes_as(blob("log/rA/0"), b"v1", owner, true)).await;
    assert_eq!(s, StatusCode::OK, "IfAbsent create");
    let created = etag(&hc);
    let (s, hc2, _) = send(&app, put_bytes_as(blob("log/rA/0"), b"v2", owner, true)).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED, "IfAbsent on an existing key conflicts");
    assert_eq!(etag(&hc2), created, "the 412 carries the existing etag");
    let (_, _, body) = send(&app, get_as(blob("log/rA/0"), owner)).await;
    assert_eq!(body, b"v1", "the conflicting write did not land");

    // list_by_prefix → a prefix scopes the listing; the empty prefix lists everything under the tree.
    send(&app, put_bytes_as(blob("log/rA/1"), b"v", owner, true)).await;
    let (s, _, b) = send(&app, get_as(format!("/v1/trees/{tree}/blobs?prefix=log/"), owner)).await;
    assert_eq!(s, StatusCode::OK);
    let mut keys: Vec<String> = serde_json::from_slice::<Value>(&b).unwrap()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["key"].as_str().unwrap().to_string())
        .collect();
    keys.sort();
    assert_eq!(keys, vec!["log/rA/0".to_string(), "log/rA/1".to_string()], "list returns only the prefix");
    let (_, _, ball) = send(&app, get_as(format!("/v1/trees/{tree}/blobs"), owner)).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&ball).unwrap()["keys"].as_array().unwrap().len(),
        3,
        "the empty prefix lists everything (ptr/rA + log/rA/0 + log/rA/1)"
    );

    // if_match_cas + delete_semantics: N/A on this surface, by design. IfMatch has no wire representation — the
    // client flows use only Any (LWW pointers/snapshots) + IfAbsent (immutable log dots), and server-side
    // monotonicity is enforced with `SELECT ... FOR UPDATE` locks, not a client-driven etag CAS. There is no
    // DELETE route — reclamation is server-internal GC (gc.rs), never a client operation.
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn blob_metering_capacity_gates_immutable_only() {
    // §3.1: the byte-capacity meter fires only on an IfAbsent (immutable, accumulating) put; a pointer
    // (Precondition::Any) overwrite is capacity-exempt.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let (s, _, _) = send(
        &app,
        put_bytes_as(
            format!("/v1/trees/{tree}/blobs/log/replicaAAA/0"),
            b"delta-zero",
            owner,
            true,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "first immutable write");
    let used: i64 = sqlx::query_scalar("SELECT tree_used_bytes FROM accounts WHERE id = $1")
        .bind(owner)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(used > 0, "an immutable put charged the capacity meter");

    // Pin max_tree_bytes to exactly what's used — the reserve is now full.
    sqlx::query("UPDATE accounts SET max_tree_bytes = $2 WHERE id = $1")
        .bind(owner)
        .bind(used)
        .execute(&db)
        .await
        .unwrap();

    // A pointer overwrite still succeeds — capacity-exempt.
    let (s, _, _) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), b"1", owner, false),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "a pointer put is capacity-exempt");

    // Another immutable write over the (now full) reserve is refused.
    let (s, _, _) = send(
        &app,
        put_bytes_as(
            format!("/v1/trees/{tree}/blobs/log/replicaAAA/1"),
            b"delta-one",
            owner,
            true,
        ),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "an immutable put over the reserve is refused"
    );

    // The rejected put charged nothing.
    let after: i64 = sqlx::query_scalar("SELECT tree_used_bytes FROM accounts WHERE id = $1")
        .bind(owner)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(after, used, "a rejected immutable put leaves the meter untouched");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn blob_metering_rate_gates_every_put() {
    // §3.1: the per-(tree,member) rate bucket gates EVERY blob put, immutable or pointer.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 0.001, 1).await; // burst 1, negligible refill
    let tree = Uuid::new_v4();
    send(
        &app,
        put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner),
    )
    .await;

    let (s, _, _) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), b"1", owner, false),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "first pointer put spends the single token");

    let (s, h, _) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), b"2", owner, false),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "second put over rate — pointer writes are rate-gated too"
    );
    assert!(h.get("retry-after").is_some(), "429 carries Retry-After");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn blob_authz_forbidden_for_non_members_viewer_cant_commit() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;
    send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), b"1", owner, false),
    )
    .await;

    let (s, _, _) = send(
        &app,
        get_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), stranger),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-member can't read a blob");
    let (s, _, _) = send(&app, get_as(format!("/v1/trees/{tree}/blobs"), stranger)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-member can't list blobs");
    let (s, _, _) = send(
        &app,
        put_bytes_as(
            format!("/v1/trees/{tree}/blobs/heads/replicaAAA"),
            b"2",
            stranger,
            false,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-member can't write a blob");

    // A Viewer (Read-only) can read but not commit a write.
    let viewer = Uuid::new_v4();
    grant_role(&db, tree, viewer, 5).await;
    let (s, _, _) = send(
        &app,
        get_as(format!("/v1/trees/{tree}/blobs/heads/replicaAAA"), viewer),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "viewer can read");
    let (s, _, _) = send(
        &app,
        put_bytes_as(
            format!("/v1/trees/{tree}/blobs/heads/replicaAAA"),
            b"2",
            viewer,
            false,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "viewer can't commit a blob write");
}

// ---- OPE-398 seen-frontier plumbing (frontier.rs) -------------------------------------------------------

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn frontier_report_upserts_and_administer_gates_read() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_tree(&app, &db, owner).await;
    let maint = Uuid::new_v4();
    grant_role(&db, tree, maint, 3).await;
    let editor = Uuid::new_v4();
    grant_role(&db, tree, editor, 4).await;

    let body = serde_json::json!({ "frontier": { "replicaAAA": 3, "replicaBBB": 1 } });
    let (s, _, _) = send(&app, put_json_as(format!("/v1/trees/{tree}/frontier"), &body, editor)).await;
    assert_eq!(s, StatusCode::OK, "a member reports its own frontier");

    // Administer (Maintainer+) can read the raw reports.
    let (s, _, b) = send(&app, get_as(format!("/v1/trees/{tree}/frontier"), maint)).await;
    assert_eq!(s, StatusCode::OK, "maintainer reads frontier reports");
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(
        v["frontier"].as_array().unwrap().len(),
        2,
        "one row per reported replica"
    );

    // Re-report updates in place, not duplicates.
    let body2 = serde_json::json!({ "frontier": { "replicaAAA": 5 } });
    send(&app, put_json_as(format!("/v1/trees/{tree}/frontier"), &body2, editor)).await;
    let (_, _, b2) = send(&app, get_as(format!("/v1/trees/{tree}/frontier"), maint)).await;
    let v2: Value = serde_json::from_slice(&b2).unwrap();
    let rows2 = v2["frontier"].as_array().unwrap();
    assert_eq!(rows2.len(), 2, "still one row per replica — updated, not appended");
    let a = rows2.iter().find(|r| r["replica"] == "replicaAAA").unwrap();
    assert_eq!(a["counter"].as_i64().unwrap(), 5, "counter updated in place");

    // An Editor (below the Administer gate) can't read the raw reports back.
    let (s, _, _) = send(&app, get_as(format!("/v1/trees/{tree}/frontier"), editor)).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "editor is below the Administer gate for GET /frontier"
    );

    // A non-member can't even PUT.
    let stranger = Uuid::new_v4();
    let body3 = serde_json::json!({ "frontier": { "replicaAAA": 1 } });
    let (s, _, _) = send(
        &app,
        put_json_as(format!("/v1/trees/{tree}/frontier"), &body3, stranger),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-member can't report frontier");
}

// ---- OPE-409 log GC + OPE-412 metering (data-channel blobs) --------------------------------------------

/// A blob PUT authenticated as a member, carrying extra headers (e.g. `x-openom-covered` on a snapshot,
/// `if-none-match: *` on a log dot).
fn put_bytes_with_headers_as(
    uri: String,
    body: &[u8],
    member: Uuid,
    extra: &[(&str, &str)],
) -> Request<Body> {
    let mut b = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {member}"));
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body.to_vec())).unwrap()
}

/// The `x-openom-covered` header value: base64 of the JSON `{replica: counter}` map.
fn covered_b64(map: &[(&str, u64)]) -> String {
    let obj: serde_json::Map<String, Value> = map
        .iter()
        .map(|(r, c)| ((*r).to_string(), serde_json::json!(c)))
        .collect();
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&obj).unwrap())
}

/// A data-channel tree owned by a freshly-seeded account (blob path needs the `trees` row, OPE-407).
async fn new_blob_tree(app: &Router, db: &sqlx::PgPool, owner: Uuid) -> Uuid {
    seed_account(db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    assert_eq!(
        send(app, post_as(format!("/v1/trees/{tree}"), owner)).await.0,
        StatusCode::CREATED,
        "create data-channel tree"
    );
    tree
}

/// The typed `code` from an RFC 9457 problem+json error body (empty if absent).
fn body_code(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["code"].as_str().map(str::to_string))
        .unwrap_or_default()
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn snapshot_covered_publish_and_guards() {
    // A snapshot PUT installs tree_snapshot_covered (bound to the object etag), and the three write-guards —
    // M3 over-claim, the below-floor ratchet, and M6 monotonicity — reject a bad covered frontier.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_blob_tree(&app, &db, owner).await;

    // Five REAL log objects for rA (0..5) + a published head of 5. A covered frontier may only span objects
    // the tree actually retains (OPE-421 M3: indexed or reaped-below-floor) — heads alone (client-writable)
    // is not proof of coverage, so the objects must exist for {rA:5} to be publishable.
    for i in 0..5 {
        send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rA/{i}"), b"d", owner, true)).await;
    }
    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/rA"), b"5", owner, false)).await;

    // covered {rA:5} — accepted; the coverage row is written, bound to the snapshot object's etag.
    let (s, h, _) = send(
        &app,
        put_bytes_with_headers_as(
            format!("/v1/trees/{tree}/blobs/snapshot"),
            b"snap-1",
            owner,
            &[("x-openom-covered", &covered_b64(&[("rA", 5)]))],
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "publish snapshot + covered");
    let snap_etag = etag(&h);
    let row: (i64, String) = sqlx::query_as(
        "SELECT counter, snapshot_etag FROM tree_snapshot_covered WHERE tree_id = $1 AND replica = 'rA'",
    )
    .bind(tree)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(row.0, 5, "covered counter stored");
    assert_eq!(
        format!("\"{}\"", row.1),
        snap_etag,
        "coverage is bound to the live snapshot object's etag (ETAG-BINDING)"
    );

    // M3 over-claim: covered {rA:6} exceeds the head of 5 → 409 covered_over_claim.
    let (s, _, b) = send(
        &app,
        put_bytes_with_headers_as(
            format!("/v1/trees/{tree}/blobs/snapshot"),
            b"snap-2",
            owner,
            &[("x-openom-covered", &covered_b64(&[("rA", 6)]))],
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "over-claim rejected");
    assert_eq!(body_code(&b), "covered_anomaly");

    // M6 monotonicity: covered {rA:4} regresses the published 5 → 409 covered_regressed.
    let (s, _, b) = send(
        &app,
        put_bytes_with_headers_as(
            format!("/v1/trees/{tree}/blobs/snapshot"),
            b"snap-3",
            owner,
            &[("x-openom-covered", &covered_b64(&[("rA", 4)]))],
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "regression rejected");
    assert_eq!(body_code(&b), "covered_anomaly");

    // The covered header is mandatory: a snapshot PUT without it → 400.
    let (s, _, _) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/snapshot"), b"snap-4", owner, false),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "missing x-openom-covered rejected");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn log_write_guards_below_floor_and_immutability() {
    // With a GC floor seeded for a replica: a log PUT below the floor → 409 below_gc_floor; a non-IfAbsent
    // log PUT → 400 (M2 immutability); a covered frontier below the floor → 409 covered_below_gc_floor.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_blob_tree(&app, &db, owner).await;

    // Seed a floor of 3 for rB directly (stands in for a prior sweep having ratcheted it).
    sqlx::query("INSERT INTO tree_gc_floor (tree_id, replica, floor) VALUES ($1, 'rB', 3)")
        .bind(tree)
        .execute(&db)
        .await
        .unwrap();

    // M2: a log/* PUT must be immutable (if-none-match: *) → 400 otherwise.
    let (s, _, _) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rB/0"), b"d", owner, false),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "non-IfAbsent log PUT rejected (M2)");

    // D2: an IfAbsent log PUT below the floor (counter 1 < 3) → 409 below_gc_floor.
    let (s, _, b) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rB/1"), b"d", owner, true),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "below-floor log PUT rejected (D2)");
    assert_eq!(body_code(&b), "below_gc_floor");

    // At/above the floor is fine (counter 3 >= 3).
    let (s, _, _) = send(
        &app,
        put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rB/3"), b"d", owner, true),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "at-floor log PUT accepted");

    // A covered frontier below the floor → 409 covered_below_gc_floor (head high enough that M3 passes first).
    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/rB"), b"5", owner, false)).await;
    let (s, _, b) = send(
        &app,
        put_bytes_with_headers_as(
            format!("/v1/trees/{tree}/blobs/snapshot"),
            b"snap",
            owner,
            &[("x-openom-covered", &covered_b64(&[("rB", 2)]))],
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "covered below floor rejected");
    assert_eq!(body_code(&b), "covered_anomaly");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn log_get_states_absent_present_marked() {
    // get_blob's three states for a GC-managed log key: not-yet-written → 404, present → 200, and a
    // marked-pending row (floor advanced but not yet reaped) → still 200 (M4).
    let _gc = GC_TEST_LOCK.lock().await;
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_blob_tree(&app, &db, owner).await;

    // Present: write rX/0.
    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rX/0"), b"d0", owner, true)).await;
    assert_eq!(
        send(&app, get_as(format!("/v1/trees/{tree}/blobs/log/rX/0"), owner)).await.0,
        StatusCode::OK,
        "present log dot serves 200"
    );
    // Not yet written: rX/5 (at/above floor 0) → 404 graceful-absence.
    assert_eq!(
        send(&app, get_as(format!("/v1/trees/{tree}/blobs/log/rX/5"), owner)).await.0,
        StatusCode::NOT_FOUND,
        "not-yet-written log dot is 404"
    );

    // Mark rX/0 pending WITHOUT reaping: publish head + report + covered, then sweep with a huge grace.
    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/rX"), b"1", owner, false)).await;
    send(
        &app,
        put_json_as(
            format!("/v1/trees/{tree}/frontier"),
            &serde_json::json!({ "frontier": { "rX": 1 } }),
            owner,
        ),
    )
    .await;
    send(
        &app,
        put_bytes_with_headers_as(
            format!("/v1/trees/{tree}/blobs/snapshot"),
            b"snap",
            owner,
            &[("x-openom-covered", &covered_b64(&[("rX", 1)]))],
        ),
    )
    .await;
    let (s, _, _) = send(&app, post("/dev/log/gc?deletion_grace_secs=999999".into())).await;
    assert_eq!(s, StatusCode::OK, "mark-only sweep");
    // The row is marked (floor now 1, counter 0 < 1) but not reaped → still served.
    let marked: Option<String> = sqlx::query_scalar(
        "SELECT pending_delete_at::text FROM tree_blob_index WHERE tree_id = $1 AND key = 'log/rX/0'",
    )
    .bind(tree)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(marked.is_some(), "row is marked pending_delete_at");
    assert_eq!(
        send(&app, get_as(format!("/v1/trees/{tree}/blobs/log/rX/0"), owner)).await.0,
        StatusCode::OK,
        "a marked-pending dot still serves 200 (M4)"
    );
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn gc_sweep_reaps_credits_and_gones() {
    // The full mark → grace → reap: two log dots below the floor are physically reaped, the byte meter is
    // credited back, and a subsequent get of a reaped dot → 410 below_gc_floor.
    let _gc = GC_TEST_LOCK.lock().await;
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_blob_tree(&app, &db, owner).await;

    let before: i64 = sqlx::query_scalar("SELECT tree_used_bytes FROM accounts WHERE id = $1")
        .bind(owner)
        .fetch_one(&db)
        .await
        .unwrap();

    // Two immutable log dots (accumulating bytes), a published head of 2, an in-window owner report, and a
    // snapshot covering both.
    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rG/0"), b"delta-zero", owner, true)).await;
    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rG/1"), b"delta-one", owner, true)).await;
    let charged: i64 = sqlx::query_scalar("SELECT tree_used_bytes FROM accounts WHERE id = $1")
        .bind(owner)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(charged > before, "log dots charged the byte meter");

    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/rG"), b"2", owner, false)).await;
    send(
        &app,
        put_json_as(
            format!("/v1/trees/{tree}/frontier"),
            &serde_json::json!({ "frontier": { "rG": 2 } }),
            owner,
        ),
    )
    .await;
    send(
        &app,
        put_bytes_with_headers_as(
            format!("/v1/trees/{tree}/blobs/snapshot"),
            b"snap",
            owner,
            &[("x-openom-covered", &covered_b64(&[("rG", 2)]))],
        ),
    )
    .await;

    // Sweep with a zero grace → mark advances the floor to 2 and both dots reap immediately.
    let (s, _, sb) = send(&app, post("/dev/log/gc?deletion_grace_secs=0".into())).await;
    assert_eq!(s, StatusCode::OK, "sweep");
    let sj: Value = serde_json::from_slice(&sb).unwrap();
    assert!(sj["reaped"].as_u64().unwrap() >= 2, "both dots reaped: {sj}");

    // The index rows are gone…
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tree_blob_index WHERE tree_id = $1 AND key LIKE 'log/rG/%'",
    )
    .bind(tree)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(remaining, 0, "reaped log rows removed from the index");

    // …the byte meter was credited back to the pre-write level…
    let after: i64 = sqlx::query_scalar("SELECT tree_used_bytes FROM accounts WHERE id = $1")
        .bind(owner)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(after, before, "reclaimed bytes credited back to the owner");

    // …and a get of a reaped dot (below the floor of 2) is 410 below_gc_floor, telling the client to bootstrap.
    let (s, _, b) = send(&app, get_as(format!("/v1/trees/{tree}/blobs/log/rG/0"), owner)).await;
    assert_eq!(s, StatusCode::GONE, "reaped dot is 410");
    assert_eq!(body_code(&b), "below_gc_floor");
}

/// Build a router whose config has the internal-GC shared secret set (the env var is unset under test), so
/// the `POST /internal/gc` trigger is enabled and authenticated by it.
async fn router_with_internal_token(token: &str) -> Router {
    let mut config = openom::config::Config::from_env();
    config.internal_gc_token = Some(token.to_string());
    let state = openom::build_state(&config).await.expect("build_state");
    openom::app(state)
}

/// A `POST /internal/gc` with an optional token header and a JSON body of overrides.
fn internal_gc_req(token: Option<&str>, json: &Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/internal/gc")
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("x-openom-internal-token", t);
    }
    b.body(Body::from(json.to_string())).unwrap()
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn internal_gc_requires_configured_token() {
    // The scheduled trigger is registered in every deployment but FAIL-CLOSED: no secret configured ⇒ every
    // call is refused; a wrong/absent token ⇒ refused; only the exact secret runs it.
    let _gc = GC_TEST_LOCK.lock().await;
    let empty = serde_json::json!({});

    // No secret configured (the default router() — env unset): even presenting a token is refused.
    let app = router().await;
    let (s, _, _) = send(&app, internal_gc_req(Some("anything"), &empty)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "trigger inert without a configured secret");

    // Secret configured: absent header, wrong token → 403; exact token → 200.
    let app = router_with_internal_token("s3cret-token").await;
    let (s, _, _) = send(&app, internal_gc_req(None, &empty)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "no token header");
    let (s, _, _) = send(&app, internal_gc_req(Some("wrong"), &empty)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "wrong token");
    let (s, _, _) = send(&app, internal_gc_req(Some("s3cret-token"), &empty)).await;
    assert_eq!(s, StatusCode::OK, "exact token runs the sweep");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn internal_gc_drives_both_sweeps() {
    // The authenticated trigger runs BOTH the log GC (batched, stamping the round-robin cursor) and the media
    // GC in one call — the same reap path the dev route exercises, reached through the production seam.
    let _gc = GC_TEST_LOCK.lock().await;
    let token = "s3cret-token";
    let app = router_with_internal_token(token).await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_blob_tree(&app, &db, owner).await;

    // Two log dots below a published, covered, in-window frontier — the reapable setup from the dev sweep.
    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rI/0"), b"delta-zero", owner, true)).await;
    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rI/1"), b"delta-one", owner, true)).await;
    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/rI"), b"2", owner, false)).await;
    send(
        &app,
        put_json_as(
            format!("/v1/trees/{tree}/frontier"),
            &serde_json::json!({ "frontier": { "rI": 2 } }),
            owner,
        ),
    )
    .await;
    send(
        &app,
        put_bytes_with_headers_as(
            format!("/v1/trees/{tree}/blobs/snapshot"),
            b"snap",
            owner,
            &[("x-openom-covered", &covered_b64(&[("rI", 2)]))],
        ),
    )
    .await;

    // Drive both sweeps with zero grace so the two dots reap in this run (deterministic under GC_TEST_LOCK —
    // no sibling sweep runs concurrently).
    let (s, _, sb) = send(
        &app,
        internal_gc_req(
            Some(token),
            &serde_json::json!({ "deletion_grace_secs": 0, "tombstone_grace_secs": 0 }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "internal sweep");
    let sj: Value = serde_json::from_slice(&sb).unwrap();
    assert!(sj["log"].is_object(), "log section reported: {sj}");
    assert!(sj["media"].is_object(), "media section reported: {sj}");

    // The round-robin batch cursor was stamped for the swept tree.
    let stamped: bool =
        sqlx::query_scalar("SELECT last_gc_at IS NOT NULL FROM trees WHERE id = $1")
            .bind(tree)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(stamped, "last_gc_at cursor advanced for the swept tree");

    // Both dots were reaped: their index rows are gone (log-GC ran end-to-end through the internal seam).
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tree_blob_index WHERE tree_id = $1 AND key LIKE 'log/rI/%'",
    )
    .bind(tree)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(remaining, 0, "reaped log rows removed from the index");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn reads_and_writes_are_metered_into_usage_month() {
    // OPE-412 cost attribution: a write increments write_ops/bytes_write and a read increments
    // read_ops/bytes_read in usage_month for (owner-account, tree, member, month).
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_blob_tree(&app, &db, owner).await;

    send(&app, put_bytes_as(format!("/v1/trees/{tree}/blobs/log/rM/0"), b"delta", owner, true)).await;
    send(&app, get_as(format!("/v1/trees/{tree}/blobs/log/rM/0"), owner)).await;
    send(&app, get_as(format!("/v1/trees/{tree}/blobs/log/rM/0"), owner)).await;

    let row: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT write_ops, bytes_write, read_ops, bytes_read FROM usage_month
          WHERE account_id = $1 AND tree_id = $2 AND member_id = $1
            AND month = date_trunc('month', now())::date",
    )
    .bind(owner)
    .bind(tree)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(row.0 >= 1, "write_ops counted");
    assert!(row.1 >= 5, "bytes_write counted (>= the 5-byte delta)");
    assert!(row.2 >= 2, "read_ops counted (two GETs)");
    assert!(row.3 >= 10, "bytes_read counted (>= two 5-byte serves)");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn head_pointer_is_monotonic() {
    // OPE-411: a heads/{replica} pointer PUT that LOWERS the stored count is rejected (409 head_rollback) —
    // anti-rollback/griefing. A monotonic advance and an idempotent re-publish of the same count are allowed.
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    let tree = new_blob_tree(&app, &db, owner).await;

    let put_head = |n: &str| put_bytes_as(format!("/v1/trees/{tree}/blobs/heads/rH"), n.as_bytes(), owner, false);

    assert_eq!(send(&app, put_head("3")).await.0, StatusCode::OK, "initial head");
    assert_eq!(send(&app, put_head("5")).await.0, StatusCode::OK, "advance 3 -> 5");
    assert_eq!(send(&app, put_head("5")).await.0, StatusCode::OK, "idempotent re-publish of 5");

    // A rollback to 2 is refused with the typed code, and the stored head stays 5.
    let (s, _, b) = send(&app, put_head("2")).await;
    assert_eq!(s, StatusCode::CONFLICT, "rollback 5 -> 2 refused");
    assert_eq!(body_code(&b), "head_rollback");

    let (gs, _, gb) = send(&app, get_as(format!("/v1/trees/{tree}/blobs/heads/rH"), owner)).await;
    assert_eq!(gs, StatusCode::OK, "head still served");
    assert_eq!(gb, b"5", "the rejected rollback did not overwrite the stored head");

    // And a further legitimate advance past 5 still works (the guard only blocks going backward).
    assert_eq!(send(&app, put_head("9")).await.0, StatusCode::OK, "advance 5 -> 9");
}
