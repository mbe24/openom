// Build the openom-sealer crate to WebAssembly, on this Windows host, in two stages that
// mirror the native Docker convention (scripts/cargo.mjs) with ONE deliberate difference.
//
//   1. Rust → wasm, in Docker (the host cannot execute freshly-compiled cargo build
//      scripts — company policy "Access is denied (os error 5)" — the same reason cargo.mjs
//      uses Docker). `--no-default-features --features wasm` compiles the wasm-bindgen
//      veneer and drops nothing else (the sealer has no native-only deps). The crypto
//      crate pulls getrandom's browser backend for wasm32, which needs
//      RUSTFLAGS=--cfg getrandom_backend="wasm_js" (see openom-crypto/Cargo.toml).
//
//      THE DIFFERENCE vs. cargo.mjs: CARGO_TARGET_DIR points at a path *on the bind mount*
//      (packages/openom-sealer/target-wasm), NOT the off-mount named volume cargo.mjs uses.
//      Stage 2's wasm-bindgen CLI runs on the HOST and must read the produced .wasm, so the
//      artifact has to land on the shared mount, not inside a container-only volume. The
//      cargo *registry* volume is still reused, so dependency compilation stays incremental.
//
//   2. JS/TS glue, on the host: the wasm-bindgen CLI only post-processes the finished
//      .wasm (no Rust compilation), so it runs on the host unaffected by the policy. Its
//      version is read FROM Cargo.lock so it always matches the resolved `wasm-bindgen`
//      crate — a skew between the two is the classic silent-broken-glue bug.
//
// Output: packages/openom-sealer/pkg/ (openom_sealer.js + .d.ts + _bg.wasm), consumed by
// the web sealer shim (apps/app/src/core/sealer/wasm.js). All artifacts are gitignored.
//
// Experiment hooks: WASM_PROFILE (default `wasm-release`), WASM_RUSTFLAGS (appended after
// the mandatory getrandom cfg).
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CRATE = path.join(REPO, 'packages', 'openom-sealer');
const IMAGE = process.env.OPENOM_CARGO_IMAGE || 'rust:1-bookworm';
const REGISTRY_VOLUME = 'openom-cargo-registry';

const TRIPLE = 'x86_64-pc-windows-msvc'; // host triple for the wasm-bindgen CLI download
const TARGET_SUBDIR = 'target-wasm'; // on the mount, so host wasm-bindgen reads the .wasm
const CONTAINER_TARGET = `/work/packages/openom-sealer/${TARGET_SUBDIR}`;
const PROFILE = process.env.WASM_PROFILE || 'wasm-release';
// getrandom's wasm_js backend is mandatory (the CSPRNG on wasm32); extra flags append.
const RUSTFLAGS = ['--cfg getrandom_backend="wasm_js"', process.env.WASM_RUSTFLAGS || '']
  .filter(Boolean)
  .join(' ');

const WASM = path.join(CRATE, TARGET_SUBDIR, 'wasm32-unknown-unknown', PROFILE, 'openom_sealer.wasm');
const TOOLS_DIR = path.join(CRATE, 'tools');
// Output under the web app's served root (no bundler — serve.mjs hands out files directly),
// alongside the other vendored module (src/vendor). The web sealer binding imports from here
// and the .wasm is fetched over HTTP relative to it; Tauri bundles the same tree.
const PKG_DIR = path.join(REPO, 'apps', 'app', 'src', 'vendor', 'sealer');

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', stdio: 'inherit', ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} ${args.slice(0, 3).join(' ')}… failed (code ${r.status})`);
}

function dockerAvailable() {
  const r = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' });
  return r.status === 0 && (r.stdout || '').trim().length > 0;
}

// ---- stage 1: Rust → wasm, in Docker ----
if (!dockerAvailable()) {
  throw new Error('Docker is required for the wasm build (host cannot run cargo build scripts). Start Docker Desktop.');
}
console.log(`[·] Building Rust → wasm in Docker (wasm32, --features wasm · profile=${PROFILE})…`);
run('docker', [
  'run',
  '--rm',
  '--init',
  '-v',
  `${REPO}:/work`,
  '-v',
  `${REGISTRY_VOLUME}:/usr/local/cargo/registry`,
  '-w',
  '/work',
  '-e',
  `CARGO_TARGET_DIR=${CONTAINER_TARGET}`,
  '-e',
  `RUSTFLAGS=${RUSTFLAGS}`,
  IMAGE,
  'bash',
  '-c',
  'rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true; ' +
    `cargo build --profile ${PROFILE} --target wasm32-unknown-unknown ` +
    '-p openom-sealer --no-default-features --features wasm',
]);
if (!fs.existsSync(WASM)) throw new Error(`expected wasm at ${WASM} after the Docker build; not found`);
console.log(`[✓] Compiled ${path.relative(REPO, WASM)} (${(fs.statSync(WASM).size / 1024).toFixed(0)} kb)`);

// ---- stage 2: wasm-bindgen glue, on the host (CLI version pinned to Cargo.lock) ----
function resolvedBindgenVersion() {
  const lock = fs.readFileSync(path.join(REPO, 'Cargo.lock'), 'utf8');
  // Match the version line that directly follows the wasm-bindgen name (not -macro/-shared).
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
  // Extract with a RELATIVE archive name from within TOOLS_DIR: a `C:\…` path makes tar
  // read the drive letter as a remote host ("Cannot connect to C:") on GNU tar and bsdtar.
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
