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
