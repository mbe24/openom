# openom

openom is a privacy-first family tree for desktop, mobile, and the browser: a
Rust core (`openom`, `journal`) and Tauri-based apps for the different
platforms (`apps`).

## Project status — PRE-RELEASE, ZERO USERS

openom has **not shipped**. There are **no production users and no production
data**. Design and review accordingly:

- **No data migration is ever required.** There are no existing trees to convert
  or preserve. "Migrate existing users", "coexistence with the old path", and
  "don't break existing data" are **non-issues** — do not raise them as blockers.
- **Breaking changes are free.** Wire formats, schemas, APIs, storage layouts, and
  crate boundaries may change without back-compat, deprecation, or a migration path,
  whenever there's a clear reason. Prefer the clean design over a compatible one.
- A clean breaking cutover is the default answer to "old vs new"; dual-path/back-compat
  machinery is almost never warranted pre-release.

(When this changes — first real users — update this section.)

## Commits

Use Conventional Commits with a scope on the enclosing directory. Imperative
mood, lowercase start, no trailing period.

- Structure: `type(scope): summary`
- Types: `feat`, `fix`, `chore`, `build`, `docs`, `refactor`, `test`, `perf`
- Scope: the component you touched, e.g. `app`, `store`, `server`, `tauri`,
  `preview`, `brand`, `docs`, `ci`
- Example: `fix(app): keep the search palette out of the re-rendered shell`
- Do NOT append a `Co-Authored-By:` / agent-attribution trailer (or any
  Claude/session line) to commit messages.

## Validation before committing

Run quick type checks, format checks, and unit tests after a series of commits.

## Code style

Prefer functions under ~150 lines. A longer one should be split into named phases or helper
functions — unless the logic is irreducibly coupled (shared mutable state that can't be cleanly
threaded across a call boundary), in which case say why in a brief comment. This is a guideline, not
a hard gate: a clear phase structure and readability matter more than the exact line count.

Reach for the type system to make errors impossible rather than merely caught: newtype
domain values that would otherwise be interchangeable primitives (ids, keys, codes — a `TreeId` is
not a `ReplicaId`, a `Dek` is not a `Kek`), so a wrong-argument slip is a compile error, not a
runtime one.

## Package & app documentation

Every crate in `packages/` and every unit in `apps/` has a `README.md`, wired as the module doc
(`#![doc = include_str!("../README.md")]` for crates). The format, the layer map, and the exemplar
(`packages/openom-jcs/README.md`) live in `packages/README.md`.

When you add or materially change a unit:
- **The README is part of the code — keep it current.** Any change to a unit's behavior or contract
  updates its README in the *same* change; in particular, rewrite or **drop** invariants (and their
  prose) for behavior that no longer exists. A README that documents behavior the code no longer has
  is worse than none.
- Create/update its `README.md` — especially **What it is — and is not** (the scope boundary) and
  **Invariants** (the contract).
- Invariants are namespaced (`JCS-1`), stable, never renumbered, and each `verified by` names a
  **real** test. Never invent invariants to fill the table; a unit with no real contract has no
  Invariants section. A README may omit any section that would be padding — never pad one.
- Tag non-Rust code fences (` ```sh `, ` ```json `, …) so rustdoc doesn't run them as doctests.
- Keep the `packages/README.md` map and each `Position` line honest when the graph or a status changes.
- Verify before done: `node scripts/cargo.mjs test -p <crate>` (repo root; cargo runs under WSL2/Docker on Windows).