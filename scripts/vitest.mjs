#!/usr/bin/env node
// Runs the frontend test suite (vitest) inside a Linux Node container.
//
// Why: this host's supply-chain policy makes pnpm treat esbuild's ignored build
// script as a FATAL error, so the `pnpm install` vitest runs on startup exits 1 and
// vitest never starts. It's the same class of block scripts/cargo.mjs works around
// for Rust. A container's pnpm has no such policy, and modern esbuild ships its
// binary via an optional platform package, so vitest runs there unmodified.
//
//   node scripts/vitest.mjs [vitest args...]
//
// Named volumes keep re-runs fast and keep the container's linux install from
// clashing with the host's win32 one: a node_modules volume (shadowing the host's),
// a pnpm-store volume, and a corepack volume (so pnpm@11 is fetched once).
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Tiny .env loader — same convention as scripts/cargo.mjs (OPENOM_NODE_IMAGE).
try {
  for (const raw of fs.readFileSync(path.join(REPO, '.env'), 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (key && process.env[key] === undefined) process.env[key] = val;
  }
} catch {}

const IMAGE = process.env.OPENOM_NODE_IMAGE || 'node:22-bookworm-slim';
const args = process.argv.slice(2).join(' ');

// corepack activates the pnpm version pinned in apps/package.json (packageManager).
const inner = [
  'corepack enable',
  // Frozen + reproducible: the committed lockfile carries every platform's binaries
  // (pnpm-workspace.yaml supportedArchitectures), so Linux resolves its own esbuild.
  // confirmModulesPurge=false: don't abort reconciling the volume without a TTY.
  // (esbuild's ignored build is made non-fatal by pnpm-workspace.yaml allowBuilds.)
  'pnpm install --store-dir /pnpm-store --frozen-lockfile --config.confirmModulesPurge=false',
  `pnpm exec vitest run ${args}`.trim(),
].join(' && ');

const dockerArgs = [
  'run',
  '--rm',
  '--init',
  '-v',
  `${REPO}:/work`,
  '-v',
  'openom-apps-node-modules:/work/apps/node_modules',
  '-v',
  'openom-pnpm-store:/pnpm-store',
  '-v',
  'openom-corepack:/corepack',
  '-w',
  '/work/apps',
  '-e',
  'CI=true',
  '-e',
  'COREPACK_HOME=/corepack',
  '-e',
  'COREPACK_ENABLE_DOWNLOAD_PROMPT=0',
  IMAGE,
  'sh',
  '-c',
  inner,
];

console.error(`[vitest runner=docker] image=${IMAGE}  vitest run ${args}`.trimEnd());
const r = spawnSync('docker', dockerArgs, { stdio: 'inherit' });
process.exit(r.status ?? 1);
