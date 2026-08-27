//! The Hybrid Logical Clock timestamp carried by every record and op as `createdAt`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Logical ticks per physical millisecond before the counter carries into the next millisecond. Keeps
/// the logical field exactly three decimal digits, so the wire form stays fixed-width (a handful of
/// mints ever share one millisecond, so 1000 is abundant headroom).
const LOGICAL_PER_MILLI: u32 = 1000;

/// The exact character length of the canonical wire form `YYYY-MM-DDTHH:MM:SS.mmmcccZ`.
const WIRE_LEN: usize = 27;

/// A Hybrid Logical Clock timestamp: physical wall-clock milliseconds since the Unix epoch plus a
/// logical counter that disambiguates events minted on one replica within the same millisecond.
///
/// **Wire form** — a single canonical RFC 3339 UTC string with the logical counter embedded in the
/// fractional-seconds tail: `YYYY-MM-DDTHH:MM:SS.mmmcccZ`, where `mmm` is the millisecond (`000`–`999`)
/// and `ccc` is the logical counter (`000`–`999`). Fixed-width and zero-padded, so a plain
/// lexicographic string comparison matches causal order — human-readable in a raw dump, yet lossless.
///
/// `createdAt` is **provenance / display only — never a convergence tiebreak** (the fold is set-union),
/// but it *is* part of the content-hash `id`, so its encoding must be one canonical, deterministic
/// form. It is produced only by this Rust code (native and wasm compile the same source), so
/// native/wasm byte-parity is automatic — there is no cross-language JCS risk for `createdAt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hlc {
    // Field order matters: derived `Ord` compares `millis` first, then `logical` — the same order the
    // fixed-width wire string sorts in.
    millis: i64,
    logical: u32,
}

impl Hlc {
    /// A timestamp at `millis` epoch-milliseconds with logical counter `logical`. An over-large
    /// `logical` carries into `millis`, so two equal instants always share one representation — a
    /// content-hash-canonicalization requirement (else the same instant could hash two ways).
    pub fn new(millis: i64, logical: u32) -> Self {
        Hlc {
            millis: millis + (logical / LOGICAL_PER_MILLI) as i64,
            logical: logical % LOGICAL_PER_MILLI,
        }
    }

    /// The physical component: epoch milliseconds.
    pub fn millis(&self) -> i64 {
        self.millis
    }

    /// The logical component: `0`–`999`.
    pub fn logical(&self) -> u32 {
        self.logical
    }
}

/// `createdAt` did not parse as a canonical HLC timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid HLC timestamp (expected YYYY-MM-DDTHH:MM:SS.mmmcccZ)")]
pub struct HlcParseError;

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, mo, d, h, mi, s, ms) = civil_from_millis(self.millis);
        write!(
            f,
            "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}{c:03}Z",
            c = self.logical,
        )
    }
}

impl FromStr for Hlc {
    type Err = HlcParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = s.as_bytes();
        if b.len() != WIRE_LEN
            || b[4] != b'-'
            || b[7] != b'-'
            || b[10] != b'T'
            || b[13] != b':'
            || b[16] != b':'
            || b[19] != b'.'
            || b[26] != b'Z'
        {
            return Err(HlcParseError);
        }
        let num = |lo: usize, hi: usize| -> Result<i64, HlcParseError> {
            let slice = s.get(lo..hi).ok_or(HlcParseError)?;
            if !slice.bytes().all(|c| c.is_ascii_digit()) {
                return Err(HlcParseError);
            }
            slice.parse::<i64>().map_err(|_| HlcParseError)
        };
        let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
        let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
        let (ms, logical) = (num(20, 23)?, num(23, 26)?);
        if !(1..=12).contains(&mo)
            || !(1..=31).contains(&d)
            || h > 23
            || mi > 59
            || sec > 59
            || ms > 999
        {
            return Err(HlcParseError);
        }
        // Reject a calendar-invalid date (e.g. 2026-02-30, or 2027-02-29 in a non-leap year): the range
        // checks above allow day 1..=31 for every month, but `days_from_civil` would silently normalize
        // an impossible date, so two distinct strings could alias one `Hlc` and re-serialize to bytes
        // this node never received. A round-trip through the inverse conversion enforces real-calendar
        // validity exactly, keeping Display and FromStr true inverses over the accepted domain.
        let days = days_from_civil(y, mo as u32, d as u32);
        if civil_from_days(days) != (y, mo as u32, d as u32) {
            return Err(HlcParseError);
        }
        let millis = ((days * 86_400 + h * 3600 + mi * 60 + sec) * 1000) + ms;
        // `logical` is exactly three digits → already < LOGICAL_PER_MILLI, so no carry is possible.
        Ok(Hlc {
            millis,
            logical: logical as u32,
        })
    }
}

impl Serialize for Hlc {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Hlc {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// --- civil-date conversion (Howard Hinnant's algorithms, proleptic Gregorian, UTC) -----------------

/// Split epoch-milliseconds into `(year, month, day, hour, minute, second, millisecond)` (UTC).
fn civil_from_millis(millis: i64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let ms = millis.rem_euclid(1000) as u32;
    let secs = millis.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (h, mi, s) = (
        (sod / 3600) as u32,
        ((sod % 3600) / 60) as u32,
        (sod % 60) as u32,
    );
    let (y, mo, d) = civil_from_days(days);
    (y, mo, d, h, mi, s, ms)
}

/// Days since the Unix epoch → `(year, month [1..12], day [1..31])`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d)
}

/// `(year, month [1..12], day [1..31])` → days since the Unix epoch (inverse of [`civil_from_days`]).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let (m, d) = (m as i64, d as i64);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Kani proof harnesses — bit-precise model checking (CBMC backend). Compiled ONLY under `cargo kani`
/// (which sets `--cfg kani`); the normal build and `cargo test` never see them, so there is no `kani`
/// dependency in `Cargo.toml`. Run them with `node scripts/kani.mjs -p openom-claim` (Docker image or a
/// local Kani install). These are the workspace's first proofs — deliberately the simplest high-value
/// target: branch-free integer arithmetic over primitive inputs (no loops → no unwind bounds).
#[cfg(kani)]
mod verification {
    use super::*;

    /// The civil-date conversion is a lossless inverse over the whole representable day range: every
    /// day number round-trips through `(year, month, day)` unchanged. `createdAt`'s content-hash
    /// canonical form rests on this — a break here would fork ids across native and wasm. Proven for
    /// ALL days in the bounded range at once (not sampled, as a proptest would).
    #[kani::proof]
    fn civil_from_days_is_the_inverse_of_days_from_civil() {
        let days: i64 = kani::any();
        // Cover the parser's FULL domain — 4-digit years 0000..=9999. Day 0 is 1970-01-01; 0000-01-01
        // is ≈ -719_528 days and 9999-12-31 is ≈ 2_932_896, so [-720_000, 3_000_000) spans every date
        // FromStr accepts (its calendar-validity guard runs this exact pair down to year 0000). The
        // functions are branch-free (no loops), so this only scopes the integer range.
        kani::assume((-720_000..3_000_000).contains(&days));
        let (y, m, d) = civil_from_days(days);
        assert_eq!(days_from_civil(y, m, d), days);
    }

    /// `Hlc::new` canonicalizes: the logical counter always lands in `0..1000` (overflow carries into
    /// `millis`), re-normalizing an already-canonical value is a fixpoint, and the carry arithmetic
    /// never overflows in-range. (The *collapsing* half of the canonical-form guarantee is a separate
    /// harness below — this one only proves the invariant + idempotence.)
    #[kani::proof]
    fn hlc_new_canonicalizes_the_logical_carry() {
        let millis: i64 = kani::any();
        let logical: u32 = kani::any();
        // A realistic epoch-ms magnitude; keeps millis + the carry well inside i64.
        kani::assume((0..300_000_000_000_000).contains(&millis));
        let h = Hlc::new(millis, logical);
        assert!(h.logical() < 1000);
        assert_eq!(Hlc::new(h.millis(), h.logical()), h);
    }

    /// The collapsing half of the "one canonical form" guarantee: two *structurally different* inputs
    /// that denote the SAME instant canonicalize to the identical `Hlc`. `(millis, logical)` counts
    /// `millis * 1000 + logical` sub-millisecond units, so equal totals must map to one representation —
    /// else the same instant could hash two ways. (Non-vacuous: e.g. `(1, 1000)` and `(2, 0)` — this
    /// bound spans the carry boundary, which is where a split differs.)
    ///
    /// `logical` is bounded to `< 2000` (real callers only ever pass `< 1000`; `2000` still crosses one
    /// carry) and `millis` to a modest range: `Hlc::new`'s `logical/1000` / `%1000` is a wide-symbolic
    /// division that CBMC bit-blasts expensively, so keeping the operands small is what makes this
    /// tractable — the same lesson as the base58 exclusion.
    #[kani::proof]
    fn hlc_new_collapses_equivalent_inputs_to_one_form() {
        let (m1, m2): (i64, i64) = (kani::any(), kani::any());
        let (l1, l2): (u32, u32) = (kani::any(), kani::any());
        kani::assume((0..1_000_000_000).contains(&m1) && l1 < 2000);
        kani::assume((0..1_000_000_000).contains(&m2) && l2 < 2000);
        // Same instant — small enough that `m*1000` stays well inside i64.
        kani::assume(m1 * 1000 + l1 as i64 == m2 * 1000 + l2 as i64);
        assert_eq!(Hlc::new(m1, l1), Hlc::new(m2, l2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn epoch_and_a_known_instant_format_canonically() {
        assert_eq!(Hlc::new(0, 0).to_string(), "1970-01-01T00:00:00.000000Z");
        // 1_771_765_800_000 ms = 2026-02-22T13:10:00Z, logical 0.
        assert_eq!(
            Hlc::new(1_771_765_800_000, 0).to_string(),
            "2026-02-22T13:10:00.000000Z"
        );
        // The logical counter rides in the last three fractional digits.
        assert_eq!(Hlc::new(1_771_765_800_123, 7).to_string(), "2026-02-22T13:10:00.123007Z");
    }

    #[test]
    fn parse_is_the_inverse_of_display() {
        for (ms, logical) in [
            (0, 0),
            (1, 0),
            (999, 999),
            (1_771_765_800_123, 42),
            (253_402_300_799_000, 0), // 9999-12-31T23:59:59Z — top of the 4-digit-year range
        ] {
            let hlc = Hlc::new(ms, logical);
            assert_eq!(hlc.to_string().parse::<Hlc>().unwrap(), hlc);
        }
    }

    #[test]
    fn the_logical_counter_carries_so_equal_instants_share_one_form() {
        // 1000 logical ticks == advancing one millisecond; both must produce the identical struct AND
        // the identical wire string (else the same instant would hash two ways).
        assert_eq!(Hlc::new(5, 1000), Hlc::new(6, 0));
        assert_eq!(Hlc::new(5, 1000).to_string(), Hlc::new(6, 0).to_string());
        assert_eq!(Hlc::new(5, 2003), Hlc::new(7, 3));
    }

    #[test]
    fn lexicographic_string_order_matches_causal_order() {
        let a = Hlc::new(1, 0);
        let b = Hlc::new(1, 1);
        let c = Hlc::new(2, 0);
        assert!(a < b && b < c, "struct Ord is causal");
        assert!(
            a.to_string() < b.to_string() && b.to_string() < c.to_string(),
            "and the wire string sorts the same way"
        );
    }

    #[test]
    fn malformed_timestamps_are_rejected() {
        for bad in [
            "",
            "2026-02-22T13:10:00.000Z",       // too few fractional digits
            "2026-02-22T13:10:00.000000",     // no trailing Z
            "2026-02-22 13:10:00.000000Z",    // space instead of T
            "2026-13-22T13:10:00.000000Z",    // month 13
            "2026-02-22T24:10:00.000000Z",    // hour 24
            "2026-02-22T13:10:00.00000xZ",    // non-digit in the fraction
            "1771765800000",                  // the old bare-int form
            "2026-02-30T00:00:00.000000Z",    // Feb 30 does not exist
            "2027-02-29T00:00:00.000000Z",    // 2027 is not a leap year
            "2026-04-31T00:00:00.000000Z",    // April has 30 days
            // Each of these is length-correct with exactly one wrong separator, so ONLY that
            // separator's guard rejects it (kills the individual `||` -> `&&` mutations that a
            // wrong-length or multi-error string can't isolate).
            "2026-02222T13:10:00.000000Z",    // b[7] is not '-'
            "2026-02-22T13:10000.000000Z",    // b[16] is not ':'
            "2026-02-22T13:10:000000000Z",    // b[19] is not '.'
            "2026-02-22T13:10:00.0000000",    // b[26] is not 'Z'
            "2026-02-22T13:10:60.000000Z",    // second 60 (> 59), with a valid separator layout
        ] {
            assert!(bad.parse::<Hlc>().is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn accessors_report_the_components() {
        // kills millis -> 0/1/-1 and logical -> 0/1
        let h = Hlc::new(1_234_567, 42);
        assert_eq!(h.millis(), 1_234_567);
        assert_eq!(h.logical(), 42);
    }

    #[test]
    fn civil_math_covers_the_negative_branches() {
        // Every other anchor is >= 1970, so `days >= 0` and neither the negative-z branch of
        // civil_from_days nor the negative-year branch of days_from_civil is exercised by cargo test
        // (both ARE Kani-proven). Year 0 sits before the +719468 shift's epoch, so it drives both.
        for s in [
            "0000-01-01T00:00:00.000000Z", // z < 0 after the shift -> civil_from_days negative-z branch
            "0000-02-29T00:00:00.000000Z", // days_from_civil m<=2 -> y = -1 -> negative-year branch
        ] {
            assert_eq!(s.parse::<Hlc>().unwrap().to_string(), s, "{s} must round-trip");
        }
    }

    proptest! {
        /// Round-trip over the whole realistic domain: any instant this century, any logical counter.
        #[test]
        fn display_parse_roundtrips(ms in 0i64..4_000_000_000_000, logical in 0u32..1000) {
            let hlc = Hlc::new(ms, logical);
            prop_assert_eq!(hlc.to_string().parse::<Hlc>().unwrap(), hlc);
            prop_assert_eq!(hlc.to_string().len(), WIRE_LEN);
        }

        /// Serde (the path the content hash actually takes) round-trips through JSON as a string.
        #[test]
        fn serde_roundtrips_as_a_string(ms in 0i64..4_000_000_000_000, logical in 0u32..1000) {
            let hlc = Hlc::new(ms, logical);
            let json = serde_json::to_string(&hlc).unwrap();
            prop_assert!(json.starts_with('"') && json.ends_with('"'), "encodes as a JSON string");
            prop_assert_eq!(serde_json::from_str::<Hlc>(&json).unwrap(), hlc);
        }
    }
}
