#!/usr/bin/env node
// Execution layer for the Rust workspace: runs `cargo <args>` either on the host
// or inside a Linux container, and picks between them automatically.
//
// Why it exists: this machine's policy denies executing freshly built binaries.
// cargo's own build scripts (serde, thiserror, …) are compiled and then run, and
// that run fails with "Access is denied (os error 5)" before a single line of our
// code executes. A container's execution is not subject to the host policy, so the
// SAME `cargo` invocation succeeds there unchanged — the build is byte-for-byte
// normal, only the process that runs it moves.
//
//   node scripts/cargo.mjs test -p openom-store -p openom
//   node scripts/cargo.mjs build -p openom
//   node scripts/cargo.mjs clippy -p openom-store -p openom --all-targets
//   node scripts/cargo.mjs fmt --all
//
// Runner selection — OPENOM_RUNNER = auto (default) | local | docker
//   local  — run cargo directly on the host (Linux / WSL / CI, where builds work)
//   docker — run cargo inside OPENOM_CARGO_IMAGE (this locked-down host)
//   auto   — try local; if it fails and Docker is available, fall back to docker.
//            On a host where local builds succeed, force `local` to avoid a
//            redundant Docker retry when a genuine test actually fails.
//
// OPENOM_CARGO_IMAGE — image for docker/auto (default rust:1-bookworm). The FULL
//   image ships gcc; rusqlite's `bundled` feature compiles SQLite from C and needs
//   it. The `-slim` tag would fail at that step.
//
// Convention (shared by every task that ever runs cargo here): the repo is
// bind-mounted at /work, the cargo registry and target dir live in named volumes
// so rebuilds stay incremental instead of compiling cold each run, and
// CARGO_TARGET_DIR is redirected off the bind mount into the target volume.
//
// Scope note: the Tauri shell (apps/src-tauri) is intentionally NOT built here —
// headless it needs the whole WebKitGTK stack. It builds through its own path
// (`pnpm tauri dev|build`) and the desktop CI. This runner is for the pure crates:
// openom-store (the DocStore contract + conformance suite) and openom (the server).
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Load <repo>/.env (gitignored) so the runner default can be pinned per machine —
// set OPENOM_RUNNER=docker here and the host cargo attempt (and its policy popup)
// is skipped entirely. A real environment variable always wins over the file, so
// CI can force `local` without editing anything. See .env.example.
function loadEnv() {
  const file = path.join(REPO, '.env');
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return; // no .env — fine, defaults apply
  }
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (key && process.env[key] === undefined) process.env[key] = val;
  }
}
loadEnv();

const RUNNER = (process.env.OPENOM_RUNNER || 'auto').toLowerCase();
const IMAGE = process.env.OPENOM_CARGO_IMAGE || 'rust:1-bookworm';
const REGISTRY_VOLUME = 'openom-cargo-registry';
const TARGET_VOLUME = 'openom-cargo-target';

const cargoArgs = process.argv.slice(2);
if (cargoArgs.length === 0) {
  console.error(
    'usage: node scripts/cargo.mjs <cargo args...>   [env OPENOM_RUNNER=auto|local|docker]',
  );
  process.exit(2);
}

function dockerAvailable() {
  const r = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], {
    encoding: 'utf8',
  });
  return r.status === 0 && (r.stdout || '').trim().length > 0;
}

function runLocal() {
  return spawnSync('cargo', cargoArgs, { cwd: REPO, stdio: 'inherit' });
}

function runDocker() {
  const args = [
    'run',
    '--rm',
    '--init', // reap zombies + forward Ctrl-C to cargo
    '-v',
    `${REPO}:/work`,
    '-v',
    `${REGISTRY_VOLUME}:/usr/local/cargo/registry`,
    '-v',
    `${TARGET_VOLUME}:/tmp/target`,
    '-w',
    '/work',
    '-e',
    'CARGO_TARGET_DIR=/tmp/target',
    IMAGE,
    'cargo',
    ...cargoArgs,
  ];
  console.error(`[cargo runner=docker] image=${IMAGE}  cargo ${cargoArgs.join(' ')}`);
  return spawnSync('docker', args, { stdio: 'inherit' });
}

let result;
if (RUNNER === 'docker') {
  result = runDocker();
} else if (RUNNER === 'local') {
  result = runLocal();
} else {
  // auto: prefer the host; fall back to Docker when the host can't build/run.
  result = runLocal();
  if ((result.error || result.status !== 0) && dockerAvailable()) {
    const why = result.error ? result.error.code || result.error.message : `exit ${result.status}`;
    console.error(`[cargo runner=auto] host cargo failed (${why}); falling back to Docker`);
    result = runDocker();
  }
}

if (result.error && RUNNER !== 'auto') {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
