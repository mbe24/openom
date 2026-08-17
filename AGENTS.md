# openom

openom is a privacy-first family tree for desktop, mobile, and the browser: a
Rust core (`openom`, `journal`) and Tauri-based apps for the different
platforms (`apps`).

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