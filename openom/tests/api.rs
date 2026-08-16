//! Server integration tests — drive the real router (routing + extractors + handlers
//! + Postgres + S3) in-process via `tower`'s `oneshot`, no socket. The presigned
//! media PUT/GET legs go out to MinIO over reqwest, exactly as a client would.
//!
//! These hit a **live** Postgres + MinIO, so they're `#[ignore]`d. They own only
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
use openom_protocol::v1::{
    Aead, AuthorizedSigner, Envelope, Header, KeyEpoch, KeyWrap, Keyring, Kind, Member, MemberRole,
    SignerRole, WrapMethod,
};
use openom_protocol::Message;
use openom_crypto::{generate_identity, keyring_hash, sign_keyring, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

async fn router() -> Router {
    let config = openom::config::Config::from_env();
    let state = openom::build_state(&config).await.expect("build_state");
    openom::app(state)
}

/// One in-process request; returns status, headers, and the collected body.
async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.expect("router is infallible");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
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
    Envelope { version: 1, header: Some(header), ciphertext: ciphertext.to_vec() }.encode_to_vec()
}

/// A real KIND_PROPOSAL envelope (no replica dot — each proposal is a fresh submission).
fn proposal_envelope(tree: Uuid, ciphertext: &[u8]) -> Vec<u8> {
    let header = Header {
        kind: Kind::Proposal as i32,
        aead: Aead::Xchacha20Poly1305 as i32,
        tree_id: tree.as_bytes().to_vec(),
        ciphertext_hash: Sha256::digest(ciphertext).to_vec(),
        ..Default::default()
    };
    Envelope { version: 1, header: Some(header), ciphertext: ciphertext.to_vec() }.encode_to_vec()
}

/// A real delta envelope with a replica dot (replica_id + replica_counter).
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
    Envelope { version: 1, header: Some(header), ciphertext: ciphertext.to_vec() }.encode_to_vec()
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

/// A snapshot PUT authenticated as a specific member (creates a tree owned by them).
fn put_tree_as(tree: Uuid, env: &[u8], member: Uuid) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(format!("/trees/{tree}"))
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {member}"))
        .body(Body::from(env.to_vec()))
        .unwrap()
}

/// A pool straight to the test DB, to seed accounts with specific metering caps. Uses
/// the same DATABASE_URL the router builds its state from.
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
async fn seed_account(db: &sqlx::PgPool, id: Uuid, max_tree_bytes: i64, log_rate: f64, log_burst: i32) {
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
async fn set_proposal_meters(db: &sqlx::PgPool, id: Uuid, max_bytes: i64, max_open: i32, max_day: i32) {
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
/// Roles: 1 owner, 2 co_owner, 3 maintainer, 4 editor, 5 viewer.
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

/// Turn on media entitlements for an account (so a StageMedia authz PASS isn't masked by an
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

fn post_json_as(uri: String, json: Value, member: Uuid) -> Request<Body> {
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
    // Newest epoch: the founder's RRK wrap + an HPKE wrap per non-founder member.
    let mut wraps = vec![KeyWrap {
        member_id: owner_s.clone(),
        wrap_method: WrapMethod::RrkHpke as i32,
        nonce: vec![],
        wrapped_dek: vec![1],
        kdf_params: None,
        ephemeral_public_key: vec![],
    }];
    for (id, role) in extra {
        let s = id.to_string();
        members.push(Member { member_id: s.clone(), role: *role, author_public_key: vec![7; 32], hpke_public_key: vec![9; 32] });
        wraps.push(KeyWrap { member_id: s, wrap_method: WrapMethod::X25519Hpke as i32, nonce: vec![], wrapped_dek: vec![1], kdf_params: None, ephemeral_public_key: vec![] });
    }
    let mut k = Keyring {
        tree_id: tree.as_bytes().to_vec(),
        revision,
        layout_version: 1,
        prev_keyring_hash: prev_hash,
        authorized_signers: vec![AuthorizedSigner {
            public_key: fpub,
            member_id: owner_s,
            role: SignerRole::Founder as i32,
        }],
        members,
        signatures: vec![],
        recovery_keys: vec![],
        epochs: vec![KeyEpoch { key_id: vec![0], epoch: 0, wraps }],
    };
    sign_keyring(&mut k, founder);
    k
}

fn put_keyring_as(tree: Uuid, k: &Keyring, member: Uuid) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(format!("/trees/{tree}/keyring"))
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {member}"))
        .body(Body::from(k.encode_to_vec()))
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
        .uri(format!("/trees/{tree}"))
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
    Request::builder().method("POST").uri(uri).body(Body::empty()).unwrap()
}
fn post_json(uri: String, json: Value) -> Request<Body> {
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

    let (s, h, body) = send(&app, get(format!("/trees/{tree}"))).await;
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

    let (s, _, _) = send(&app, get(format!("/trees/{}", Uuid::new_v4()))).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "unknown tree");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn delta_log_lifecycle() {
    let app = router().await;
    let tree = Uuid::new_v4();
    // The tree must exist (created by an initial snapshot) before deltas append to it.
    send(&app, put_tree(tree, &snapshot_envelope(tree, b"ct", None), None)).await;

    let ra = b"replica-aaaaaaaa".to_vec();
    let d0 = delta_envelope(tree, b"delta-zero", &ra, 0);
    let d1 = delta_envelope(tree, b"delta-one", &ra, 1);

    let (s, _, b0) = send(&app, post_bytes(format!("/trees/{tree}/log"), &d0)).await;
    assert_eq!(s, StatusCode::OK, "append d0");
    assert_eq!(serde_json::from_slice::<Value>(&b0).unwrap()["seq"].as_i64().unwrap(), 0);

    let (s, _, b1) = send(&app, post_bytes(format!("/trees/{tree}/log"), &d1)).await;
    assert_eq!(s, StatusCode::OK, "append d1");
    assert_eq!(serde_json::from_slice::<Value>(&b1).unwrap()["seq"].as_i64().unwrap(), 1);

    // Re-delivering d0 (same replica dot) is idempotent — same seq, no new entry.
    let (s, _, br) = send(&app, post_bytes(format!("/trees/{tree}/log"), &d0)).await;
    assert_eq!(s, StatusCode::OK, "re-append idempotent");
    assert_eq!(serde_json::from_slice::<Value>(&br).unwrap()["seq"].as_i64().unwrap(), 0);

    // Whole tail: both deltas, in order, payloads round-tripping the exact sealed bytes.
    let (s, _, tb) = send(&app, get(format!("/trees/{tree}/log?since=-1"))).await;
    assert_eq!(s, StatusCode::OK, "read tail");
    let tail: Value = serde_json::from_slice(&tb).unwrap();
    let entries = tail["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "two deltas, not three (re-delivery didn't duplicate)");
    assert_eq!(tail["head_seq"].as_i64().unwrap(), 1);
    assert_eq!(tail["next_cursor"].as_i64().unwrap(), 1);
    assert!(!entries[0]["time"].as_str().unwrap().is_empty(), "entries carry a timestamp for the activity feed");
    assert!(!entries[0]["member"].as_str().unwrap().is_empty(), "and an author");
    let p0 = base64::engine::general_purpose::STANDARD
        .decode(entries[0]["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(p0, d0, "payload round-trips the sealed delta bytes");

    // From a cursor: only the tail after seq 0.
    let (s, _, tb2) = send(&app, get(format!("/trees/{tree}/log?since=0"))).await;
    assert_eq!(s, StatusCode::OK, "read tail since 0");
    let tail2: Value = serde_json::from_slice(&tb2).unwrap();
    assert_eq!(tail2["entries"].as_array().unwrap().len(), 1, "one delta after seq 0");
    assert_eq!(tail2["entries"][0]["seq"].as_i64().unwrap(), 1);

    // Appending to a tree that doesn't exist → 404 (header tree_id matches the url so validation passes).
    let unknown = Uuid::new_v4();
    let (s, _, _) = send(
        &app,
        post_bytes(format!("/trees/{unknown}/log"), &delta_envelope(unknown, b"x", &ra, 0)),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "append to unknown tree");
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
    let (s, h, _) = send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;
    assert_eq!(s, StatusCode::OK, "owner creates the tree");
    let version = etag(&h);
    // Owner seeds one delta so the log read path has something to guard.
    let ra = b"replica-owner000".to_vec();
    send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"d0", &ra, 0), owner)).await;

    // A non-owner is refused on read snapshot, read log, append, and a CAS snapshot update (the
    // seam now guards the PUT/commit path too — it used to inline owner_id in the SQL predicate).
    let (s, _, _) = send(&app, get_as(format!("/trees/{tree}"), other)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot read the snapshot");
    let cas = Request::builder()
        .method("PUT")
        .uri(format!("/trees/{tree}"))
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {other}"))
        .header("if-match", version.trim_matches('"'))
        .body(Body::from(snapshot_envelope(tree, b"hostile-rev", None)))
        .unwrap();
    let (s, _, _) = send(&app, cas).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot commit a snapshot update");
    let (s, _, _) = send(&app, get_as(format!("/trees/{tree}/log?since=-1"), other)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot read the log");
    let (s, _, _) = send(
        &app,
        post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"x", b"replica-other000", 0), other),
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
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    let viewer = Uuid::new_v4();
    let editor = Uuid::new_v4();
    let maint = Uuid::new_v4();
    grant_role(&db, tree, viewer, 5).await;
    grant_role(&db, tree, editor, 4).await;
    grant_role(&db, tree, maint, 3).await;

    // Read — every member role can read snapshot, log, and proposals.
    for m in [viewer, editor, maint] {
        assert_eq!(send(&app, get_as(format!("/trees/{tree}"), m)).await.0, StatusCode::OK, "read snapshot");
        assert_eq!(send(&app, get_as(format!("/trees/{tree}/log?since=-1"), m)).await.0, StatusCode::OK, "read log");
        assert_eq!(send(&app, get_as(format!("/trees/{tree}/proposals"), m)).await.0, StatusCode::OK, "read proposals");
    }

    // Propose — Editor+ yes, Viewer no.
    let prop = proposal_envelope(tree, b"suggestion");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/proposals"), &prop, viewer)).await.0, StatusCode::FORBIDDEN, "viewer can't propose");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/proposals"), &prop, editor)).await.0, StatusCode::OK, "editor proposes");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/proposals"), &prop, maint)).await.0, StatusCode::OK, "maintainer proposes");

    // Commit (append a delta) — Maintainer+ yes, Editor + Viewer no.
    let d = |r: &'static [u8]| delta_envelope(tree, b"x", r, 0);
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/log"), &d(b"replica-viewer00"), viewer)).await.0, StatusCode::FORBIDDEN, "viewer can't commit");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/log"), &d(b"replica-editor00"), editor)).await.0, StatusCode::FORBIDDEN, "editor can't commit (V1 propose/approve)");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/log"), &d(b"replica-maint000"), maint)).await.0, StatusCode::OK, "maintainer commits");
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
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    let viewer = Uuid::new_v4();
    let editor = Uuid::new_v4();
    let maint = Uuid::new_v4();
    grant_role(&db, tree, viewer, 5).await;
    grant_role(&db, tree, editor, 4).await;
    grant_role(&db, tree, maint, 3).await;

    // Upload (intent) — Editor+ passes authz (media enabled, so a pass isn't masked); Viewer 403.
    assert_eq!(send(&app, post_json_as(format!("/trees/{tree}/media/intent"), intent_body(), viewer)).await.0, StatusCode::FORBIDDEN, "viewer can't upload");
    assert_eq!(send(&app, post_json_as(format!("/trees/{tree}/media/intent"), intent_body(), editor)).await.0, StatusCode::OK, "editor uploads");

    // Attach = Commit. Insert a live blob directly (no MinIO round-trip needed to test the gate).
    let blob = Uuid::new_v4();
    sqlx::query("INSERT INTO tree_blobs (tree_id, blob_id, r2_key, size_bytes, state, ref_count) VALUES ($1,$2,$3,10,1,0)")
        .bind(tree).bind(blob.as_bytes().as_slice()).bind(format!("k/{blob}"))
        .execute(&db).await.unwrap();
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/media/{blob}/attach"), &[], editor)).await.0, StatusCode::FORBIDDEN, "editor can't attach (commit-adjacent)");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/media/{blob}/attach"), &[], maint)).await.0, StatusCode::OK, "maintainer attaches");
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
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;
    let maint = Uuid::new_v4();
    grant_role(&db, tree, maint, 3).await;

    // The maintainer spends their single token, then is throttled.
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"m0", b"replica-maint000", 0), maint)).await.0, StatusCode::OK, "maintainer's first append");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"m1", b"replica-maint000", 1), maint)).await.0, StatusCode::TOO_MANY_REQUESTS, "maintainer throttled");
    // The owner has their OWN bucket — unaffected by the maintainer draining theirs.
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"o0", b"replica-owner000", 0), owner)).await.0, StatusCode::OK, "owner not throttled by the maintainer");
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
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    let founder = generate_identity().unwrap();
    let editor = Uuid::new_v4();
    let viewer = Uuid::new_v4();
    let genesis = build_keyring(tree, 1, vec![], &founder, owner, &[(editor, 4), (viewer, 5)]);

    let (s, _, body) = send(&app, put_keyring_as(tree, &genesis, owner)).await;
    assert_eq!(s, StatusCode::OK, "owner PUTs the genesis keyring");
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["revision"].as_i64().unwrap(), 1);

    // ACL derived from the members list.
    assert_eq!(role_of(&db, tree, owner).await, Some(1), "owner");
    assert_eq!(role_of(&db, tree, editor).await, Some(4), "editor");
    assert_eq!(role_of(&db, tree, viewer).await, Some(5), "viewer");

    // And the derived roles actually gate: the editor may propose but not commit; the viewer neither.
    let prop = proposal_envelope(tree, b"p");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/proposals"), &prop, editor)).await.0, StatusCode::OK, "derived editor proposes");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"x", b"replica-editor00", 0), editor)).await.0, StatusCode::FORBIDDEN, "derived editor can't commit");
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/proposals"), &prop, viewer)).await.0, StatusCode::FORBIDDEN, "derived viewer can't propose");
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
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    let founder = generate_identity().unwrap();
    let m = Uuid::new_v4();
    let rev1 = build_keyring(tree, 1, vec![], &founder, owner, &[(m, 4)]); // editor
    assert_eq!(send(&app, put_keyring_as(tree, &rev1, owner)).await.0, StatusCode::OK, "genesis");
    assert_eq!(role_of(&db, tree, m).await, Some(4));

    // rev2: promote m to maintainer (ordinary change, founder-signed), chaining onto rev1.
    let rev2 = build_keyring(tree, 2, keyring_hash(&rev1).to_vec(), &founder, owner, &[(m, 3)]);
    assert_eq!(send(&app, put_keyring_as(tree, &rev2, owner)).await.0, StatusCode::OK, "promote");
    assert_eq!(role_of(&db, tree, m).await, Some(3), "promoted to maintainer");
    // Now m can commit.
    assert_eq!(send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"c", b"replica-m0000000", 0), m)).await.0, StatusCode::OK, "maintainer commits");

    // rev3: remove m entirely → their ACL row is deleted → they're refused.
    let rev3 = build_keyring(tree, 3, keyring_hash(&rev2).to_vec(), &founder, owner, &[]);
    assert_eq!(send(&app, put_keyring_as(tree, &rev3, owner)).await.0, StatusCode::OK, "remove");
    assert_eq!(role_of(&db, tree, m).await, None, "ACL row gone after removal");
    assert_eq!(send(&app, get_as(format!("/trees/{tree}/log?since=-1"), m)).await.0, StatusCode::FORBIDDEN, "removed member refused");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_rejects_rollback_fork_unsigned() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    let founder = generate_identity().unwrap();
    let rev1 = build_keyring(tree, 1, vec![], &founder, owner, &[]);
    assert_eq!(send(&app, put_keyring_as(tree, &rev1, owner)).await.0, StatusCode::OK, "genesis");

    // Rollback: re-PUT revision 1 while head is 1 → not a sequential successor → 409.
    assert_eq!(send(&app, put_keyring_as(tree, &rev1, owner)).await.0, StatusCode::CONFLICT, "rollback refused");

    // Fork: a revision-2 with a wrong prev_keyring_hash → 409.
    let forked = build_keyring(tree, 2, vec![0u8; 32], &founder, owner, &[]);
    assert_eq!(send(&app, put_keyring_as(tree, &forked, owner)).await.0, StatusCode::CONFLICT, "fork refused");

    // Unsigned/unauthorized: a valid-shaped rev2 signed by a stranger, not a prior signer → 400.
    let stranger = generate_identity().unwrap();
    let mut rev2 = build_keyring(tree, 2, keyring_hash(&rev1).to_vec(), &founder, owner, &[]);
    rev2.signatures.clear();
    sign_keyring(&mut rev2, &stranger);
    assert_eq!(send(&app, put_keyring_as(tree, &rev2, owner)).await.0, StatusCode::BAD_REQUEST, "unendorsed change refused");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn keyring_history() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    let tree = Uuid::new_v4();
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    let founder = generate_identity().unwrap();
    let rev1 = build_keyring(tree, 1, vec![], &founder, owner, &[]);
    let rev2 = build_keyring(tree, 2, keyring_hash(&rev1).to_vec(), &founder, owner, &[]);
    send(&app, put_keyring_as(tree, &rev1, owner)).await;
    send(&app, put_keyring_as(tree, &rev2, owner)).await;

    let (s, _, b) = send(&app, get_as(format!("/trees/{tree}/keyring?from=1"), owner)).await;
    assert_eq!(s, StatusCode::OK);
    let h: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(h["head"].as_i64().unwrap(), 2);
    assert_eq!(h["revisions"].as_array().unwrap().len(), 2, "whole chain from 1");
    let p1 = base64::engine::general_purpose::STANDARD.decode(h["revisions"][0]["payload"].as_str().unwrap()).unwrap();
    assert_eq!(p1, rev1.encode_to_vec(), "revision payload round-trips");

    let (_, _, b2) = send(&app, get_as(format!("/trees/{tree}/keyring?from=2"), owner)).await;
    assert_eq!(serde_json::from_slice::<Value>(&b2).unwrap()["revisions"].as_array().unwrap().len(), 1, "tail from 2");
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
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    let founder = generate_identity().unwrap();
    let viewer = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    let genesis = build_keyring(tree, 1, vec![], &founder, owner, &[(viewer, 5)]);

    // A non-owner non-member can't establish the keyring.
    assert_eq!(send(&app, put_keyring_as(tree, &genesis, stranger)).await.0, StatusCode::FORBIDDEN, "stranger can't PUT genesis");
    // Owner establishes it.
    assert_eq!(send(&app, put_keyring_as(tree, &genesis, owner)).await.0, StatusCode::OK);
    // The derived viewer lacks Administer → can't PUT a successor (refused before any crypto).
    let rev2 = build_keyring(tree, 2, keyring_hash(&genesis).to_vec(), &founder, owner, &[(viewer, 5)]);
    assert_eq!(send(&app, put_keyring_as(tree, &rev2, viewer)).await.0, StatusCode::FORBIDDEN, "viewer can't PUT a keyring");
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
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    let founder = generate_identity().unwrap();
    let m = Uuid::new_v4();
    let rev1 = build_keyring(tree, 1, vec![], &founder, owner, &[(m, 3)]); // maintainer
    send(&app, put_keyring_as(tree, &rev1, owner)).await;

    // m leaves a footprint: a proposal + a delta (which creates their rate bucket).
    send(&app, post_bytes_as(format!("/trees/{tree}/proposals"), &proposal_envelope(tree, b"p"), m)).await;
    send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"c", b"replica-m0000000", 0), m)).await;
    let props: i64 = sqlx::query_scalar("SELECT count(*) FROM proposals WHERE tree_id = $1 AND proposer_member_id = $2").bind(tree).bind(m).fetch_one(&db).await.unwrap();
    let rate: i64 = sqlx::query_scalar("SELECT count(*) FROM member_rate WHERE tree_id = $1 AND member_id = $2").bind(tree).bind(m).fetch_one(&db).await.unwrap();
    assert_eq!((props, rate), (1, 1), "m has a proposal + a rate bucket before removal");

    // The access list shows both members.
    let (_, _, ab) = send(&app, get_as(format!("/trees/{tree}/access"), owner)).await;
    assert_eq!(serde_json::from_slice::<Value>(&ab).unwrap()["members"].as_array().unwrap().len(), 2, "owner + m");

    // rev2 removes m.
    let rev2 = build_keyring(tree, 2, keyring_hash(&rev1).to_vec(), &founder, owner, &[]);
    assert_eq!(send(&app, put_keyring_as(tree, &rev2, owner)).await.0, StatusCode::OK, "remove m");

    assert_eq!(role_of(&db, tree, m).await, None, "ACL row gone");
    let props: i64 = sqlx::query_scalar("SELECT count(*) FROM proposals WHERE tree_id = $1 AND proposer_member_id = $2").bind(tree).bind(m).fetch_one(&db).await.unwrap();
    let rate: i64 = sqlx::query_scalar("SELECT count(*) FROM member_rate WHERE tree_id = $1 AND member_id = $2").bind(tree).bind(m).fetch_one(&db).await.unwrap();
    assert_eq!((props, rate), (0, 0), "m's proposal + rate bucket reclaimed on removal");
    let (_, _, ab2) = send(&app, get_as(format!("/trees/{tree}/access"), owner)).await;
    assert_eq!(serde_json::from_slice::<Value>(&ab2).unwrap()["members"].as_array().unwrap().len(), 1, "only owner remains");
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
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    // Submit a proposal.
    let prop = proposal_envelope(tree, b"suggested-edit-bundle");
    let (s, _, body) = send(&app, post_bytes_as(format!("/trees/{tree}/proposals"), &prop, owner)).await;
    assert_eq!(s, StatusCode::OK, "submit proposal");
    let id = serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();

    // List it back — payload round-trips the exact sealed bytes, attributed to the proposer.
    let (s, _, lb) = send(&app, get_as(format!("/trees/{tree}/proposals"), owner)).await;
    assert_eq!(s, StatusCode::OK, "list proposals");
    let list: Value = serde_json::from_slice(&lb).unwrap();
    let items = list["proposals"].as_array().unwrap();
    assert_eq!(items.len(), 1, "one open proposal");
    let payload = base64::engine::general_purpose::STANDARD
        .decode(items[0]["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(payload, prop, "proposal payload round-trips");
    assert!(!items[0]["proposer"].as_str().unwrap().is_empty(), "attributed to a member");

    // A non-owner can neither list nor submit (the authz seam) — V1 owner-only.
    let (s, _, _) = send(&app, get_as(format!("/trees/{tree}/proposals"), other)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot list proposals");
    let (s, _, _) = send(&app, post_bytes_as(format!("/trees/{tree}/proposals"), &prop, other)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot propose");

    // Resolve (delete) it → gone from the open list; deleting again is idempotent.
    let (s, _, _) = send(&app, delete_as(format!("/trees/{tree}/proposals/{id}"), owner)).await;
    assert_eq!(s, StatusCode::OK, "delete proposal");
    let (s, _, lb2) = send(&app, get_as(format!("/trees/{tree}/proposals"), owner)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&lb2).unwrap()["proposals"].as_array().unwrap().len(),
        0,
        "no open proposals after resolve"
    );
    let (s, _, _) = send(&app, delete_as(format!("/trees/{tree}/proposals/{id}"), owner)).await;
    assert_eq!(s, StatusCode::OK, "delete is idempotent");

    // The security property: a proposal must be refused on the delta-log path, so a hostile server
    // can never replay an editor's proposal into the authoritative tree history.
    let (s, _, _) = send(&app, post_bytes_as(format!("/trees/{tree}/log"), &prop, owner)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "KIND_PROPOSAL refused on the log path");
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
    send(&app, put_tree_as(t_free, &snapshot_envelope(t_free, b"ct", None), free)).await;
    let (s, _, _) = send(
        &app,
        post_bytes_as(format!("/trees/{t_free}/proposals"), &proposal_envelope(t_free, b"x"), free),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "proposals disabled on the free tier");

    // (2) Open-per-tree cap of 1: second concurrent proposal → 403; frees up after a delete.
    let cap = Uuid::new_v4();
    seed_account(&db, cap, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, cap, 1 << 20, 1, 50).await;
    let t_cap = Uuid::new_v4();
    send(&app, put_tree_as(t_cap, &snapshot_envelope(t_cap, b"ct", None), cap)).await;
    let (s, _, b1) = send(&app, post_bytes_as(format!("/trees/{t_cap}/proposals"), &proposal_envelope(t_cap, b"p1"), cap)).await;
    assert_eq!(s, StatusCode::OK, "first proposal fits");
    let id1 = serde_json::from_slice::<Value>(&b1).unwrap()["id"].as_str().unwrap().to_string();
    let (s, _, _) = send(&app, post_bytes_as(format!("/trees/{t_cap}/proposals"), &proposal_envelope(t_cap, b"p2"), cap)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "second exceeds the open-per-tree cap");
    send(&app, delete_as(format!("/trees/{t_cap}/proposals/{id1}"), cap)).await;
    let (s, _, _) = send(&app, post_bytes_as(format!("/trees/{t_cap}/proposals"), &proposal_envelope(t_cap, b"p3"), cap)).await;
    assert_eq!(s, StatusCode::OK, "a slot freed up after resolving one");

    // (3) Per-member/day cap of 1 backed by the ledger: survives delete-then-resubmit.
    let day = Uuid::new_v4();
    seed_account(&db, day, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, day, 1 << 20, 50, 1).await;
    let t_day = Uuid::new_v4();
    send(&app, put_tree_as(t_day, &snapshot_envelope(t_day, b"ct", None), day)).await;
    let (s, _, bd) = send(&app, post_bytes_as(format!("/trees/{t_day}/proposals"), &proposal_envelope(t_day, b"d1"), day)).await;
    assert_eq!(s, StatusCode::OK, "first submission of the day");
    let idd = serde_json::from_slice::<Value>(&bd).unwrap()["id"].as_str().unwrap().to_string();
    send(&app, delete_as(format!("/trees/{t_day}/proposals/{idd}"), day)).await; // resolve it
    let (s, _, _) = send(&app, post_bytes_as(format!("/trees/{t_day}/proposals"), &proposal_envelope(t_day, b"d2"), day)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "daily cap counts submissions, not open rows");
}

#[tokio::test]
#[ignore = "requires the local Postgres + MinIO stack; see module doc"]
async fn proposals_ttl_swept() {
    let app = router().await;
    let db = db().await;
    let owner = Uuid::new_v4();
    seed_account(&db, owner, 1 << 30, 1000.0, 1000).await;
    set_proposal_meters(&db, owner, 1 << 20, 50, 50).await;
    let tree = Uuid::new_v4();
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;

    let (_, _, body) = send(&app, post_bytes_as(format!("/trees/{tree}/proposals"), &proposal_envelope(tree, b"stale"), owner)).await;
    let id = serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
    // Backdate its TTL so it's expired, then run the sweep.
    sqlx::query("UPDATE proposals SET expires_at = now() - interval '1 hour' WHERE id = $1::uuid")
        .bind(&id)
        .execute(&db)
        .await
        .unwrap();
    // Already invisible to reads before the physical sweep.
    let (_, _, lb) = send(&app, get_as(format!("/trees/{tree}/proposals"), owner)).await;
    assert_eq!(serde_json::from_slice::<Value>(&lb).unwrap()["proposals"].as_array().unwrap().len(), 0, "expired hidden from reads");
    // The sweep physically reclaims it.
    let (s, _, gb) = send(&app, post("/dev/gc".to_string())).await;
    assert_eq!(s, StatusCode::OK, "run dev gc");
    assert!(serde_json::from_slice::<Value>(&gb).unwrap()["proposals_expired"].as_u64().unwrap() >= 1, "swept ≥1 expired proposal");
    // Gone even when explicitly asking for expired ones.
    let (_, _, lb2) = send(&app, get_as(format!("/trees/{tree}/proposals?include_expired=true"), owner)).await;
    assert_eq!(serde_json::from_slice::<Value>(&lb2).unwrap()["proposals"].as_array().unwrap().len(), 0, "physically gone");
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
    let (s, _, _) = send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), member)).await;
    assert_eq!(s, StatusCode::OK, "create tree as the throttled member");

    let ra = b"replica-rate0000".to_vec();
    // First new append spends the single token.
    let (s, _, _) = send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"d0", &ra, 0), member)).await;
    assert_eq!(s, StatusCode::OK, "first append within rate");

    // Second new append: bucket empty → 429 with a Retry-After hint.
    let (s, h, _) = send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"d1", &ra, 1), member)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "second append over rate");
    assert!(h.get("retry-after").is_some(), "429 carries Retry-After");

    // A re-delivery of the already-appended d0 is NOT metered — idempotent success even while throttled.
    let (s, _, _) = send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"d0", &ra, 0), member)).await;
    assert_eq!(s, StatusCode::OK, "re-delivery bypasses the rate gate");

    // Only d0 actually landed — the throttled append never persisted.
    let read = Request::builder()
        .uri(format!("/trees/{tree}/log?since=-1"))
        .header("authorization", format!("Bearer {member}"))
        .body(Body::empty())
        .unwrap();
    let (s, _, tb) = send(&app, read).await;
    assert_eq!(s, StatusCode::OK);
    let tail: Value = serde_json::from_slice(&tb).unwrap();
    assert_eq!(tail["entries"].as_array().unwrap().len(), 1, "throttled append never persisted");
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
    send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), member)).await;

    let ra = b"replica-cap00000".to_vec();
    let (s, _, _) = send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"d0", &ra, 0), member)).await;
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
    let (s, _, _) = send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"d1", &ra, 1), member)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "append over the tree-byte reserve");

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
    let app = router().await;
    let tree = Uuid::new_v4();
    send(&app, put_tree(tree, &snapshot_envelope(tree, b"ct", None), None)).await;

    // Intent → presigned staging PUT → confirm.
    let media = b"openom fake encrypted media blob".to_vec();
    let intent = post_json(
        format!("/trees/{tree}/media/intent"),
        serde_json::json!({ "size_bytes": media.len(), "object_sha256": sha256_b64(&media) }),
    );
    let (s, _, body) = send(&app, intent).await;
    assert_eq!(s, StatusCode::OK, "intent");
    let j: Value = serde_json::from_slice(&body).unwrap();
    let blob = j["blob_id"].as_str().unwrap().to_string();

    let client = reqwest::Client::new();
    let mut put = client.put(j["upload_url"].as_str().unwrap()).body(media.clone());
    for pair in j["required_headers"].as_array().unwrap() {
        let kv = pair.as_array().unwrap();
        put = put.header(kv[0].as_str().unwrap(), kv[1].as_str().unwrap().to_string());
    }
    assert!(put.send().await.unwrap().status().is_success(), "presigned PUT");

    let (s, _, cbody) = send(&app, post(format!("/trees/{tree}/media/{blob}/confirm"))).await;
    assert_eq!(s, StatusCode::OK, "confirm");
    let cj: Value = serde_json::from_slice(&cbody).unwrap();
    assert_eq!(cj["size_bytes"].as_u64().unwrap() as usize, media.len());

    // Presigned download round-trips the exact bytes.
    let (s, _, gbody) = send(&app, get(format!("/trees/{tree}/media/{blob}"))).await;
    assert_eq!(s, StatusCode::OK, "get media");
    let gj: Value = serde_json::from_slice(&gbody).unwrap();
    let dl = reqwest::get(gj["download_url"].as_str().unwrap()).await.unwrap();
    assert_eq!(dl.bytes().await.unwrap().as_ref(), media.as_slice(), "download round-trip");

    // attach → detach-to-zero → tombstone → sweep physically deletes → 404.
    send(&app, post(format!("/trees/{tree}/media/{blob}/attach"))).await;
    let (_, _, dbody) = send(&app, post(format!("/trees/{tree}/media/{blob}/detach"))).await;
    let dj: Value = serde_json::from_slice(&dbody).unwrap();
    assert_eq!(dj["state"].as_str().unwrap(), "tombstoned", "detach-to-zero tombstones");

    let (s, _, sbody) = send(
        &app,
        post("/dev/gc?tombstone_grace_secs=0&pending_expiry_secs=999999".into()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "sweep");
    let sj: Value = serde_json::from_slice(&sbody).unwrap();
    assert!(sj["physically_deleted"].as_u64().unwrap() >= 1, "swept the tombstone");

    let (s, _, _) = send(&app, get(format!("/trees/{tree}/media/{blob}"))).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "gone after sweep");
}
