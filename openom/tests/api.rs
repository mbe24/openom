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
use openom_protocol::v1::{Aead, Envelope, Header, Kind};
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
    let (s, _, _) = send(&app, put_tree_as(tree, &snapshot_envelope(tree, b"ct", None), owner)).await;
    assert_eq!(s, StatusCode::OK, "owner creates the tree");
    // Owner seeds one delta so the log read path has something to guard.
    let ra = b"replica-owner000".to_vec();
    send(&app, post_bytes_as(format!("/trees/{tree}/log"), &delta_envelope(tree, b"d0", &ra, 0), owner)).await;

    // A non-owner is refused on read snapshot, read log, and append.
    let (s, _, _) = send(&app, get_as(format!("/trees/{tree}"), other)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot read the snapshot");
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
