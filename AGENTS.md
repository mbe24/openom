# openom

openom is a privacy-first family tree for desktop, mobile, and the browser.: a Rust core daemon (`openom`) and different apps for differeent plattforms based on Tauri (`apps`)

## Commits

Use Conventional Commits with a scope on the enclosing directory. Imperative mood, lowercase start, no trailing period.

- Structure: `type(scope): summary`
- Types: `feat`, `fix`, `chore`, `build`, `docs`, `refactor`, `test`, `perf`
- Scope: the component you touched, e.g. `flowcli`, `flowd`, `flowmcp`, `flowui`, `proto`, `plan`
- Example: `chore(flowcli): add go.sum to fix first build`

## Validation before committing

Run quick type checks, format checks, and unit tests after a series of commits.
