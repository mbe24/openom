#!/usr/bin/env node
// Local-only clippy `nursery` regression check — NOT wired into CI.
//
// The workspace deny-gate is `clippy::pedantic` + `clippy::cargo` (see .github/workflows/desktop.yml and
// [workspace.lints.clippy]). `nursery` is deliberately NOT in that gate: it is an unstable lint group, so
// gating on it would make CI flaky as toolchains shift what it flags. But a curated subset of nursery lints
// is genuinely worth keeping clean, so this script lets a developer check for regressions on demand:
//
//   node scripts/nursery.mjs            # check the whole workspace
//
// It runs ONLY the lints we vetted as true-positives during the 2026-09-07 nursery sweep and drove to zero.
// The two lints with documented, unavoidable false-positives are suppressed at their source, so a clean tree
// produces zero output here:
//   - missing_const_for_fn on the 8 #[wasm_bindgen] exports in openom-vault/src/wasm.rs (the macro forbids
//     const fn) — allowed per-method there.
//   - too_long_first_doc_paragraph on openom-protocol's README (via #![doc = include_str!]) — a location-less
//     clippy limitation on included markdown, allowed at that crate's root.
// Lints with SUBJECTIVE / context-dependent false-positives (redundant_pub_crate, trait_duplication_in_bounds,
// significant_drop_*, or_fun_call, option_if_let_else) are intentionally excluded — see the memory note
// `clippy-sweep-complete` for the rationale on each.
//
// Runs through scripts/cargo.mjs, so it honours OPENOM_RUNNER (docker on this locked-down host). Because
// these lints are passed at WARN level, clippy exits 0 even when it flags something; this script parses the
// output and exits 1 on any finding, so it can serve as a pre-commit hook.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// The vetted, enforced-clean subset. Keep in sync with the `clippy-sweep-complete` memory note.
const LINTS = [
  'use_self',
  'missing_const_for_fn',
  'too_long_first_doc_paragraph',
  'doc_link_code',
  'derive_partial_eq_without_eq',
];

const passthrough = process.argv.slice(2);
const clippyArgs = [
  path.join(REPO, 'scripts', 'cargo.mjs'),
  'clippy',
  '--workspace',
  '--exclude',
  'openom-tauri',
  '--all-features',
  ...passthrough,
  '--',
  ...LINTS.flatMap((l) => ['-W', `clippy::${l}`]),
];

console.error(`[nursery] ${LINTS.length} vetted lints across the workspace (excluding openom-tauri)…`);
const run = spawnSync('node', clippyArgs, { cwd: REPO, encoding: 'utf8' });
const out = `${run.stdout || ''}${run.stderr || ''}`;
process.stdout.write(out);

if (run.status !== 0 && !out) {
  console.error('[nursery] cargo runner failed to start.');
  process.exit(run.status || 1);
}

// A real deny-gate regression (pedantic/cargo) would make clippy itself exit non-zero.
if (run.status !== 0) {
  console.error('[nursery] clippy exited non-zero — a pedantic/cargo gate error, not a nursery finding. Fix that first.');
  process.exit(run.status);
}

const fragment = new RegExp(`index\\.html#(${LINTS.join('|')})\\b`, 'g');
const hits = (out.match(fragment) || []).map((m) => m.split('#')[1]);
if (hits.length === 0) {
  console.error('[nursery] ✓ clean — no findings from the vetted nursery lints.');
  process.exit(0);
}
const counts = hits.reduce((acc, l) => ((acc[l] = (acc[l] || 0) + 1), acc), {});
console.error(`\n[nursery] ✗ ${hits.length} finding(s):`);
for (const [lint, n] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
  console.error(`  ${n.toString().padStart(3)}  clippy::${lint}`);
}
console.error('[nursery] Fix, or (if a genuine false-positive) allow at the site with a reason. See scripts/nursery.mjs.');
process.exit(1);
