#!/usr/bin/env node
// Execution layer for Kani proofs: runs `cargo kani <args>` either on the host (for people who have
// Kani installed) or inside a self-contained Kani container, and picks between them automatically.
//
// Why it exists: Kani (the bit-precise model checker, CBMC backend) has no native Windows support and
// isn't in the workspace's stable cargo image — the same shape as cargo-fuzz. This runner gives a
// repeatable proof run anywhere Docker is available, while staying a no-op fast path for a local
// install. The proof harnesses are gated behind `#[cfg(kani)]`, so they never touch the normal build.
//
//   node scripts/kani.mjs -p openom-claim          # verify one crate's proofs
//   node scripts/kani.mjs -p openom-claim --harness civil_from_days_is_the_inverse_of_days_from_civil
//   OPENOM_RUNNER=local node scripts/kani.mjs -p openom-claim   # force the host's `cargo kani`
//
// Runner selection — OPENOM_RUNNER = auto (default) | local | docker
//   local  — run `cargo kani` on the host (you installed it: `cargo install --locked kani-verifier`)
//   docker — run inside OPENOM_KANI_IMAGE (built from docker/kani.Dockerfile if missing)
//   auto   — use the host's `cargo kani` if it resolves, else Docker. Unlike a plain try-then-fall-back
//            this checks `cargo kani --version` FIRST, so a genuine proof FAILURE on the host is NOT
//            mistaken for "Kani absent" and needlessly re-run in Docker.
//
// OPENOM_KANI_IMAGE — the image tag for docker/auto (default openom-kani:latest). Built locally from
//   docker/kani.Dockerfile on first use (it bakes in Kani + its CBMC bundle, ~1 GB, one-time).
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Reuse cargo.mjs's .env loading so OPENOM_RUNNER can be pinned per machine (a real env var wins).
function loadEnv() {
  let text;
  try {
    text = fs.readFileSync(path.join(REPO, '.env'), 'utf8');
  } catch {
    return;
  }
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (key && process.env[key] === undefined) process.env[key] = val;
  }
}
loadEnv();

const RUNNER = (process.env.OPENOM_RUNNER || 'auto').toLowerCase();
const IMAGE = process.env.OPENOM_KANI_IMAGE || 'openom-kani:latest';
const DOCKERFILE = path.join(REPO, 'docker', 'kani.Dockerfile');
const REGISTRY_VOLUME = 'openom-cargo-registry'; // shared with cargo.mjs — the crate downloads overlap
const TARGET_VOLUME = 'openom-kani-target'; // separate from the cargo target: Kani's goto-build differs

const kaniArgs = process.argv.slice(2);

function localKaniAvailable() {
  const r = spawnSync('cargo', ['kani', '--version'], { encoding: 'utf8' });
  return r.status === 0;
}

function dockerAvailable() {
  const r = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' });
  return r.status === 0 && (r.stdout || '').trim().length > 0;
}

function imageExists() {
  return spawnSync('docker', ['image', 'inspect', IMAGE], { stdio: 'ignore' }).status === 0;
}

function buildImage() {
  console.error(`[kani runner=docker] building ${IMAGE} from docker/kani.Dockerfile (one-time, ~1 GB)…`);
  return spawnSync(
    'docker',
    ['build', '-f', DOCKERFILE, '-t', IMAGE, path.join(REPO, 'docker')],
    { stdio: 'inherit' },
  );
}

function runLocal() {
  return spawnSync('cargo', ['kani', ...kaniArgs], { cwd: REPO, stdio: 'inherit' });
}

function runDocker() {
  if (!imageExists()) {
    const b = buildImage();
    if (b.status !== 0) return b;
  }
  const args = [
    'run',
    '--rm',
    '--init', // reap zombies + forward Ctrl-C to Kani/CBMC
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
    'kani',
    ...kaniArgs,
  ];
  console.error(`[kani runner=docker] image=${IMAGE}  cargo kani ${kaniArgs.join(' ')}`);
  return spawnSync('docker', args, { stdio: 'inherit' });
}

let result;
if (RUNNER === 'local') {
  result = runLocal();
} else if (RUNNER === 'docker') {
  result = runDocker();
} else {
  // auto: a local Kani install wins (fast, no container); otherwise Docker. Decided by probing for
  // Kani, never by a failed run — so a real counterexample on the host isn't retried in Docker.
  if (localKaniAvailable()) {
    result = runLocal();
  } else if (dockerAvailable()) {
    result = runDocker();
  } else {
    console.error(
      'kani: no local `cargo kani` and no Docker. Install one:\n' +
        '  cargo install --locked kani-verifier && cargo kani setup   (local)\n' +
        '  …or start Docker so the openom-kani image can build.',
    );
    process.exit(2);
  }
}

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
