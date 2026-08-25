# openom-edtf

> EDTF (ISO 8601-2) date parser/normalizer — every fuzzy genealogy date reduced to sortable
> `[min, max]` day bounds.

**Status:** built · foundation, pure, load-bearing (consumed by `openom-projection`) · design.data-model-claims.v1.md §10.1
**Last updated:** 2026-08-25

## What it is — and is not

A date in a family tree is rarely a precise instant: "1984", "spring 1901", "about 1850", "before
1912", "sometime in the 1870s". EDTF is the ISO grammar for exactly that, and it is the single normal
form for the `openom.org/core/date/v1` claim (§10.1) and for a place's time-bounded `validRange`. This
crate parses the genealogy-relevant subset and normalizes every expression to the same shape — the
earliest (`min`) and latest (`max`) calendar day it could denote, a [`Precision`], and the
uncertainty/approximation flags — so the projection can sort a timeline and test range overlap without
re-parsing raw strings. `min`/`max` are `None` on an open (`..`) or unknown (empty) interval end, never
a fabricated day.

Supported: dates `YYYY` / `YYYY-MM` / `YYYY-MM-DD` (with a leading `-` for BCE years); the level-1
qualifiers `?` (uncertain), `~` (approximate), `%` (both); unspecified digits `X` (`19XX`, `1984-XX`,
`1984-06-XX`); the four seasons (`YYYY-21`..`24`); and intervals `start/end` where either side may be a
date, `..` (open), or empty (unknown).

It is **not** a general EDTF library: times of day, time zones, level-2 per-component qualifiers, sets
(`[..]`/`{..}`), and `Y`-prefixed large years are all out of scope — genealogy claims never need them,
so they're simply unparsed rather than half-supported. It has no notion of a claim, a projection, or a
calendar system beyond proleptic Gregorian; it does no I/O and **depends on no other openom crate**
(only `thiserror`) — nothing may sit beneath it.

## Invariants

| id | guarantee | why it matters | verified by |
|----|-----------|----------------|-------------|
| **EDTF-1** | `parse` never panics — any input, however malformed, returns `Ok`/`Err`. | A garbled synced date must fail closed, not crash the projection. | `proptests::parse_never_panics` |
| **EDTF-2** | Whenever both bounds are present, `min ≤ max`. | Timeline sort and range-overlap logic assume an ordered pair. | `proptests::min_le_max` |
| **EDTF-3** | Parsing is a pure, deterministic function of the input string. | The same stored date must normalize identically on every client. | `proptests::deterministic` |
| **EDTF-4** | A calendar-impossible day (`1985-02-30`, non-leap `1985-02-29`, `1984-04-31`) is a hard error, never silently clamped to a plausible-looking day. | A clamped date would misreport the fact, invisibly. | `tests::rejects_impossible_and_nonconformant_days` |
| **EDTF-5** | A closed interval whose start is chronologically after its end (`2001/2000`) is rejected. | Prevents `min > max` from ever reaching the sortable bound pair. | `tests::malformed_inputs` |
| **EDTF-6** | Unspecified digits (`X`) expand to the least/most-committing value (`0`/`9` per digit), then clamp to real calendar bounds. | `19XX` must bound the whole decade; a wildcard day must not overrun its month. | `tests::unspecified_digits` |
| **EDTF-7** | Negative (BCE) years parse, with `min` the more-negative bound. | Pre-1-CE dates occur in real family trees. | `tests::bce_years` |
| **EDTF-8** | Season codes `21`-`24` map to Spring/Summer/Autumn/Winter; Winter spans into the following year. | A season is a common genealogy approximation for a birth/death date. | `tests::seasons` |
| **EDTF-9** | An open (`..`) or unknown (empty) interval end yields `None`, never a fabricated date. | Callers must be able to tell "unbounded" apart from a real day. | `tests::intervals` |

Run: `node scripts/cargo.mjs test -p openom-edtf` (from the repo root; on Windows cargo runs under
WSL2/Docker). Fuzz: `cargo +nightly fuzz run parse` (from `packages/openom-edtf/fuzz`).

## Usage

```rust
use openom_edtf::{parse, EdtfKind, Precision};

// A plain year normalizes to the whole calendar year.
let year = parse("1984").unwrap();
assert_eq!(year.precision, Precision::Year);

// Approximate + unspecified digits: "about the 1980s".
let decade = parse("198X~").unwrap();
assert!(decade.approximate);

// An open-ended interval: "born 1985-04-12, still living" — no fabricated end date.
let lifespan = parse("1985-04-12/..").unwrap();
assert_eq!(lifespan.kind, EdtfKind::Interval);
assert!(lifespan.max.is_none());
```

Entry point: `parse(&str) -> Result<Edtf, EdtfError>`. `Edtf` carries `min`/`max: Option<Date>`,
`precision: Precision`, and `uncertain` / `approximate: bool`; `Date` is a plain
`{ year: i32, month: u8, day: u8 }` (proleptic Gregorian, negative `year` for BCE).

## Position

A foundation crate: no dependency on any other openom crate, and no domain knowledge of claims or
projections. `openom-projection` is its one current consumer — normalizing `core/date/v1` values and
place `validRange`s into sortable bounds. Full dependency graph: see `packages/README.md`.
