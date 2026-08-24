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