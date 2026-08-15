#!/usr/bin/env node
// Runs the Tauri CLI with the repo .env applied. Its one job today: let the JDK be overridden
// per-project via JAVA_HOME_JBR in .env, without changing the machine-wide JAVA_HOME.
//
// Why: the generated Android project uses Gradle 8.14, which doesn't run on a JDK newer than 24
// — a machine-wide JAVA_HOME of, say, 25 would fail the Gradle step. Point JAVA_HOME_JBR at a
// compatible JDK (Android Studio bundles one, its "jbr") and only this build sees it. The Rust
// side uses rustc, not Java, so nothing else cares.
//
//   # in .env (gitignored):
//   JAVA_HOME_JBR=C:\Program Files\Android\Android Studio\jbr
//
//   pnpm android:dev     # → this wrapper → tauri android dev, with JAVA_HOME set for the run
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const APPS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO = path.resolve(APPS, '..');

// Load <repo>/.env — same file and convention as scripts/cargo.mjs. A real environment variable
// already set always wins (we don't overwrite it below).
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
} catch {
  /* no .env — fine, defaults apply */
}

// Point the (Gradle) build at a specific JDK, only for this process tree.
if (process.env.JAVA_HOME_JBR) process.env.JAVA_HOME = process.env.JAVA_HOME_JBR;

const args = process.argv.slice(2);
// `pnpm exec` runs the local @tauri-apps/cli binary (not the package.json "tauri" script — that
// would recurse). shell:true so Windows finds pnpm.cmd.
const r = spawnSync('pnpm', ['exec', 'tauri', ...args], { stdio: 'inherit', shell: true, cwd: APPS });
process.exit(r.status ?? 1);
