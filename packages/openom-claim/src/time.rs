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
        ] {
            assert!(bad.parse::<Hlc>().is_err(), "{bad:?} must not parse");
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
