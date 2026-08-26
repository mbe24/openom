// Build openom-tree to WebAssembly — the claim-model family-tree engine for the web app. Same
// two-stage flow as build-treelog.mjs (Rust→wasm in Docker because the host can't run cargo build
// scripts; wasm-bindgen glue on the host), just for this crate. Output: apps/app/src/vendor/tree/
// (gitignored).
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CRATE = path.join(REPO, 'packages', 'openom-tree');
const IMAGE = process.env.OPENOM_CARGO_IMAGE || 'rust:1-bookworm';
const REGISTRY_VOLUME = 'openom-cargo-registry';

const TRIPLE = 'x86_64-pc-windows-msvc';
const TARGET_SUBDIR = 'target-wasm';
const CONTAINER_TARGET = `/work/packages/openom-tree/${TARGET_SUBDIR}`;
const PROFILE = process.env.WASM_PROFILE || 'wasm-release';
const RUSTFLAGS = process.env.WASM_RUSTFLAGS || '';

const WASM = path.join(CRATE, TARGET_SUBDIR, 'wasm32-unknown-unknown', PROFILE, 'openom_tree.wasm');
// Reuse the sealer's downloaded wasm-bindgen CLI (same version, pinned to Cargo.lock).
const TOOLS_DIR = path.join(REPO, 'packages', 'openom-sealer', 'tools');
const PKG_DIR = path.join(REPO, 'apps', 'app', 'src', 'vendor', 'tree');

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', stdio: 'inherit', ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} ${args.slice(0, 3).join(' ')}… failed (code ${r.status})`);
}

function dockerAvailable() {
  const r = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' });
  return r.status === 0 && (r.stdout || '').trim().length > 0;
}

if (!dockerAvailable()) {
  throw new Error('Docker is required for the wasm build (host cannot run cargo build scripts). Start Docker Desktop.');
}
console.log(`[·] Building openom-tree → wasm in Docker (wasm32, --features wasm · profile=${PROFILE})…`);
run('docker', [
  'run', '--rm', '--init',
  '-v', `${REPO}:/work`,
  '-v', `${REGISTRY_VOLUME}:/usr/local/cargo/registry`,
  '-w', '/work',
  '-e', `CARGO_TARGET_DIR=${CONTAINER_TARGET}`,
  '-e', `RUSTFLAGS=${RUSTFLAGS}`,
  IMAGE,
  'bash', '-c',
  'rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true; ' +
    `cargo build --profile ${PROFILE} --target wasm32-unknown-unknown ` +
    '-p openom-tree --no-default-features --features wasm',
]);
if (!fs.existsSync(WASM)) throw new Error(`expected wasm at ${WASM} after the Docker build; not found`);
console.log(`[✓] Compiled ${path.relative(REPO, WASM)} (${(fs.statSync(WASM).size / 1024).toFixed(0)} kb)`);

function resolvedBindgenVersion() {
  const lock = fs.readFileSync(path.join(REPO, 'Cargo.lock'), 'utf8');
  const m = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/);
  if (!m) throw new Error('could not find the resolved wasm-bindgen version in Cargo.lock');
  return m[1];
}

async function ensureWasmBindgen(ver) {
  const dir = path.join(TOOLS_DIR, `wasm-bindgen-${ver}-${TRIPLE}`);
  const exe = path.join(dir, 'wasm-bindgen.exe');
  if (fs.existsSync(exe)) return exe;
  const name = `wasm-bindgen-${ver}-${TRIPLE}`;
  const url = `https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${ver}/${name}.tar.gz`;
  const tarball = path.join(TOOLS_DIR, `${name}.tar.gz`);
  fs.mkdirSync(TOOLS_DIR, { recursive: true });
  console.log(`[·] Downloading wasm-bindgen CLI ${ver} (matches Cargo.lock)…`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed (${res.status}) for ${url}`);
  await pipeline(Readable.fromWeb(res.body), fs.createWriteStream(tarball));
  run('tar', ['-xzf', path.basename(tarball)], { cwd: TOOLS_DIR });
  fs.rmSync(tarball, { force: true });
  if (!fs.existsSync(exe)) throw new Error(`wasm-bindgen.exe not found after extracting ${name}`);
  console.log(`[✓] Installed wasm-bindgen CLI to ${path.relative(REPO, dir)}`);
  return exe;
}

const ver = resolvedBindgenVersion();
const bindgen = await ensureWasmBindgen(ver);
console.log('[·] Generating JS/TS bindings with wasm-bindgen (--target web)…');
run(bindgen, ['--target', 'web', '--out-dir', PKG_DIR, '--typescript', WASM]);
console.log(`[✓] Build complete → ${path.relative(REPO, PKG_DIR)}/`);
