#!/usr/bin/env node
// Integration-test runner: runs the `#[ignore]`d tests that need the live local
// stack (Postgres + MinIO) — the in-process API tests (openom/tests/api.rs) and the
// checksum-enforcement test (openom/src/storage.rs).
//
//   docker compose up -d          # the stack must be running first
//   node scripts/itest.mjs        # runs all ignored tests against it
//   node scripts/itest.mjs media_lifecycle_and_gc   # filter to one test
//
// Like scripts/cargo.mjs it runs cargo inside a Linux container (this host's policy
// blocks executing freshly built binaries), reusing the same cargo cache volumes so
// it's incremental. The container reaches the host-published stack via
// host.docker.internal, and points both S3 endpoints there so presigned URLs it mints
// are reachable from inside the container too.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Reuse .env only for the cargo image choice.
try {
  for (const raw of fs.readFileSync(path.join(REPO, '.env'), 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const k = line.slice(0, eq).trim();
    let v = line.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (k && process.env[k] === undefined) process.env[k] = v;
  }
} catch {}

const IMAGE = process.env.OPENOM_CARGO_IMAGE || 'rust:1-bookworm';
const HOST = 'host.docker.internal';
const filter = process.argv.slice(2); // optional test-name filter passed to cargo test

const env = {
  CARGO_TARGET_DIR: '/tmp/target',
  DATABASE_URL: `postgres://openom:openom@${HOST}:5432/openom`,
  S3_ENDPOINT: `http://${HOST}:9000`,
  S3_PUBLIC_ENDPOINT: `http://${HOST}:9000`,
  S3_BUCKET: 'openom-trees',
  S3_REGION: 'us-east-1',
  S3_ACCESS_KEY: 'openom',
  S3_SECRET_KEY: 'openompw123',
};

const args = [
  'run', '--rm', '--init',
  '-v', `${REPO}:/work`,
  '-v', 'openom-cargo-registry:/usr/local/cargo/registry',
  '-v', 'openom-cargo-target:/tmp/target',
  '-w', '/work',
  '--add-host', `${HOST}:host-gateway`,
];
for (const [k, v] of Object.entries(env)) args.push('-e', `${k}=${v}`);
args.push(IMAGE, 'cargo', 'test', '-p', 'openom', ...filter, '--', '--ignored', '--nocapture');

console.error(`[itest] cargo test -p openom ${filter.join(' ')} -- --ignored  (stack via ${HOST})`);
const r = spawnSync('docker', args, { stdio: 'inherit' });
process.exit(r.status ?? 1);
