//! EDTF (ISO 8601-2, Extended Date/Time Format) — the genealogy-relevant subset, normalized to
//! sortable `[min, max]` day bounds.
//!
//! A date in a family tree is rarely a precise instant: "1984", "spring 1901", "about 1850",
//! "before 1912", "sometime in the 1870s". EDTF is the ISO grammar for exactly that. This crate
//! parses the subset genealogy needs and normalizes every expression to the same shape — the
//! earliest (`min`) and latest (`max`) calendar day it could denote, a [`Precision`], and the
//! uncertainty/approximation flags — so the projection can sort a timeline and test range overlap
//! without re-parsing. `min`/`max` are `None` on an open or unknown interval end.
//!
//! Supported: dates `YYYY`, `YYYY-MM`, `YYYY-MM-DD` (with a leading `-` for BCE years); the level-1
//! qualifiers `?` (uncertain), `~` (approximate), `%` (both) as a trailing marker; unspecified
//! digits `X` (`19XX`, `1984-XX`, `1984-06-XX`); the four seasons (`YYYY-21`..`24`); and intervals
//! `start/end`, where either end may be a date, `..` (open), or empty (unknown). Not supported
//! (out of genealogy scope): times of day, time zones, level-2 per-component qualifiers, sets
//! `[..]`/`{..}`, and `Y`-prefixed large years.

/// A concrete calendar day (proleptic Gregorian; `year` may be negative for BCE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    pub year: i32,
    pub month: u8,
    pub day: u8,
}

impl Date {
    fn new(year: i32, month: u8, day: u8) -> Self {
        Date { year, month, day }
    }
}

/// How precise the *finest* stated component is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precision {
    Year,
    Month,
    Day,
    Season,
    /// An interval end that is open (`..`) or unknown (empty) on the side consulted.
    Unknown,
}

/// A single date or an interval between two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdtfKind {
    Single,
    Interval,
}

/// A parsed, normalized EDTF value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edtf {
    pub input: String,
    pub kind: EdtfKind,
    /// Earliest day covered; `None` if the (interval) start is open/unknown.
    pub min: Option<Date>,
    /// Latest day covered; `None` if the (interval) end is open/unknown.
    pub max: Option<Date>,
    pub precision: Precision,
    pub uncertain: bool,
    pub approximate: bool,
}

/// A parse failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EdtfError {
    #[error("empty date")]
    Empty,
    #[error("malformed EDTF: {0}")]
    Malformed(String),
}

/// Parse an EDTF string into a normalized [`Edtf`].
pub fn parse(input: &str) -> Result<Edtf, EdtfError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(EdtfError::Empty);
    }

    if let Some(idx) = trimmed.find('/') {
        let start = &trimmed[..idx];
        let end = &trimmed[idx + 1..];
        if end.contains('/') {
            return Err(EdtfError::Malformed("more than one '/'".into()));
        }
        let (s, su, sa) = parse_side(start)?;
        let (e, eu, ea) = parse_side(end)?;
        let precision = s
            .map(|b| b.precision)
            .or(e.map(|b| b.precision))
            .unwrap_or(Precision::Unknown);
        return Ok(Edtf {
            input: input.to_string(),
            kind: EdtfKind::Interval,
            min: s.map(|b| b.min),
            max: e.map(|b| b.max),
            precision,
            uncertain: su || eu,
            approximate: sa || ea,
        });
    }

    let (b, uncertain, approximate) = parse_single(trimmed)?;
    Ok(Edtf {
        input: input.to_string(),
        kind: EdtfKind::Single,
        min: Some(b.min),
        max: Some(b.max),
        precision: b.precision,
        uncertain,
        approximate,
    })
}

#[derive(Clone, Copy)]
struct Bounds {
    min: Date,
    max: Date,
    precision: Precision,
}

/// An interval side: a date, `..` (open), or empty (unknown). The latter two yield `None`.
fn parse_side(s: &str) -> Result<(Option<Bounds>, bool, bool), EdtfError> {
    let t = s.trim();
    if t.is_empty() || t == ".." {
        return Ok((None, false, false));
    }
    let (b, u, a) = parse_single(t)?;
    Ok((Some(b), u, a))
}

fn parse_single(s: &str) -> Result<(Bounds, bool, bool), EdtfError> {
    let (core, uncertain, approximate) = if let Some(c) = s.strip_suffix('%') {
        (c, true, true)
    } else if let Some(c) = s.strip_suffix('?') {
        (c, true, false)
    } else if let Some(c) = s.strip_suffix('~') {
        (c, false, true)
    } else {
        (s, false, false)
    };
    Ok((parse_core(core)?, uncertain, approximate))
}

fn parse_core(s: &str) -> Result<Bounds, EdtfError> {
    let malformed = || EdtfError::Malformed(s.to_string());
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let parts: Vec<&str> = rest.split('-').collect();
    if parts.is_empty() || parts.len() > 3 {
        return Err(malformed());
    }

    // Year — exactly 4 chars of [0-9X].
    if parts[0].len() != 4 {
        return Err(malformed());
    }
    let (ypos_min, ypos_max) = parse_digits_range(parts[0]).ok_or_else(malformed)?;
    let (year_min, year_max) = if neg {
        (-(ypos_max as i32), -(ypos_min as i32))
    } else {
        (ypos_min as i32, ypos_max as i32)
    };

    // Year only.
    if parts.len() == 1 {
        return Ok(Bounds {
            min: Date::new(year_min, 1, 1),
            max: Date::new(year_max, 12, days_in_month(year_max, 12)),
            precision: Precision::Year,
        });
    }

    // Month (or season) — exactly two digits/X per ISO 8601-2 (also bounds the arithmetic below).
    if parts[1].len() != 2 {
        return Err(malformed());
    }
    let (mlo, mhi) = parse_digits_range(parts[1]).ok_or_else(malformed)?;
    let exact_month = mlo == mhi;
    if exact_month && (21..=24).contains(&mlo) {
        if parts.len() != 2 {
            return Err(malformed()); // a season takes no day component
        }
        return Ok(season_bounds(year_min, year_max, mlo as u8));
    }
    let (month_min, month_max) = if exact_month {
        if !(1..=12).contains(&mlo) {
            return Err(malformed());
        }
        (mlo as u8, mlo as u8)
    } else {
        let lo = mlo.max(1);
        let hi = mhi.min(12);
        if lo > hi {
            return Err(malformed());
        }
        (lo as u8, hi as u8)
    };

    if parts.len() == 2 {
        return Ok(Bounds {
            min: Date::new(year_min, month_min, 1),
            max: Date::new(year_max, month_max, days_in_month(year_max, month_max)),
            precision: Precision::Month,
        });
    }

    // Day — exactly two digits/X (also bounds the arithmetic).
    if parts[2].len() != 2 {
        return Err(malformed());
    }
    let (dlo, dhi) = parse_digits_range(parts[2]).ok_or_else(malformed)?;
    let (day_min, day_max) = if dlo == dhi {
        if !(1..=31).contains(&dlo) {
            return Err(malformed());
        }
        (dlo as u8, dlo as u8)
    } else {
        let lo = dlo.max(1);
        let hi = dhi.min(31);
        if lo > hi {
            return Err(malformed());
        }
        (lo as u8, hi as u8)
    };

    // A fully-specified date must be a real calendar day — reject e.g. 1985-02-30 or 1985-02-29
    // (non-leap) rather than silently clamping it to a different, plausible-looking day. Only enforce
    // when year, month, and day are all exact; a wildcard component stays permissive.
    if year_min == year_max
        && month_min == month_max
        && day_min == day_max
        && day_min > days_in_month(year_min, month_min)
    {
        return Err(malformed());
    }

    // Clamp the day bounds to the real month lengths (e.g. `1984-02-XX` → max Feb 29).
    let min = Date::new(
        year_min,
        month_min,
        day_min.min(days_in_month(year_min, month_min)),
    );
    let max = Date::new(
        year_max,
        month_max,
        day_max.min(days_in_month(year_max, month_max)),
    );
    Ok(Bounds {
        min,
        max,
        precision: Precision::Day,
    })
}

/// Numeric [min, max] of a run of digits and `X` (unspecified) — `X→0` for min, `X→9` for max.
fn parse_digits_range(s: &str) -> Option<(u32, u32)> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit() || b == b'X') {
        return None;
    }
    let mut lo = 0u32;
    let mut hi = 0u32;
    for ch in s.chars() {
        lo *= 10;
        hi *= 10;
        if ch == 'X' {
            hi += 9;
        } else {
            let d = ch.to_digit(10).unwrap();
            lo += d;
            hi += d;
        }
    }
    Some((lo, hi))
}

/// Season codes 21..24 → Spring/Summer/Autumn/Winter. Winter (24) spans into the following year.
fn season_bounds(year_min: i32, year_max: i32, code: u8) -> Bounds {
    let (min, max) = match code {
        21 => (Date::new(year_min, 3, 1), Date::new(year_max, 5, 31)),
        22 => (Date::new(year_min, 6, 1), Date::new(year_max, 8, 31)),
        23 => (Date::new(year_min, 9, 1), Date::new(year_max, 11, 30)),
        _ /* 24, winter */ => (
            Date::new(year_min, 12, 1),
            Date::new(year_max + 1, 2, days_in_month(year_max + 1, 2)),
        ),
    };
    Bounds {
        min,
        max,
        precision: Precision::Season,
    }
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u8, day: u8) -> Option<Date> {
        Some(Date::new(y, m, day))
    }

    #[test]
    fn year_month_day_bounds() {
        let y = parse("1984").unwrap();
        assert_eq!(
            (y.min, y.max, y.precision),
            (d(1984, 1, 1), d(1984, 12, 31), Precision::Year)
        );

        let m = parse("1984-06").unwrap();
        assert_eq!(
            (m.min, m.max, m.precision),
            (d(1984, 6, 1), d(1984, 6, 30), Precision::Month)
        );

        // 1984 is a leap year → February has 29 days.
        assert_eq!(parse("1984-02").unwrap().max, d(1984, 2, 29));
        assert_eq!(parse("1983-02").unwrap().max, d(1983, 2, 28));

        let day = parse("1985-04-12").unwrap();
        assert_eq!(
            (day.min, day.max, day.precision),
            (d(1985, 4, 12), d(1985, 4, 12), Precision::Day)
        );
    }

    #[test]
    fn qualifiers() {
        let q = parse("1984?").unwrap();
        assert!(q.uncertain && !q.approximate);
        assert_eq!(q.min, d(1984, 1, 1));
        let a = parse("1850~").unwrap();
        assert!(a.approximate && !a.uncertain);
        let both = parse("1850%").unwrap();
        assert!(both.uncertain && both.approximate);
    }

    #[test]
    fn unspecified_digits() {
        let decade = parse("19XX").unwrap();
        assert_eq!(
            (decade.min, decade.max, decade.precision),
            (d(1900, 1, 1), d(1999, 12, 31), Precision::Year)
        );
        let some_month = parse("1984-XX").unwrap();
        assert_eq!(
            (some_month.min, some_month.max, some_month.precision),
            (d(1984, 1, 1), d(1984, 12, 31), Precision::Month)
        );
        let some_day = parse("1984-06-XX").unwrap();
        assert_eq!(
            (some_day.min, some_day.max, some_day.precision),
            (d(1984, 6, 1), d(1984, 6, 30), Precision::Day)
        );
        // "1X" as a month → Oct..Dec (10..19 clamped to 12).
        assert_eq!(parse("1984-1X").unwrap().min, d(1984, 10, 1));
        assert_eq!(parse("1984-1X").unwrap().max, d(1984, 12, 31));
    }

    #[test]
    fn seasons() {
        let spring = parse("2001-21").unwrap();
        assert_eq!(
            (spring.min, spring.max, spring.precision),
            (d(2001, 3, 1), d(2001, 5, 31), Precision::Season)
        );
        // Winter spans into the next year.
        let winter = parse("2001-24").unwrap();
        assert_eq!((winter.min, winter.max), (d(2001, 12, 1), d(2002, 2, 28)));
    }

    #[test]
    fn intervals() {
        let closed = parse("1964/2008").unwrap();
        assert_eq!(
            (closed.kind, closed.min, closed.max),
            (EdtfKind::Interval, d(1964, 1, 1), d(2008, 12, 31))
        );

        let open_end = parse("1985-04-12/..").unwrap();
        assert_eq!((open_end.min, open_end.max), (d(1985, 4, 12), None));

        let unknown_end = parse("1985/").unwrap();
        assert_eq!((unknown_end.min, unknown_end.max), (d(1985, 1, 1), None));

        let open_start = parse("../1985").unwrap();
        assert_eq!((open_start.min, open_start.max), (None, d(1985, 12, 31)));

        // Qualifier on one side propagates to the interval.
        assert!(parse("1984?/1990").unwrap().uncertain);
    }

    #[test]
    fn bce_years() {
        let bce = parse("-0044").unwrap();
        assert_eq!((bce.min, bce.max), (d(-44, 1, 1), d(-44, 12, 31)));
        // "-004X" → years -49..-40; min is the more-negative bound.
        let range = parse("-004X").unwrap();
        assert_eq!((range.min, range.max), (d(-49, 1, 1), d(-40, 12, 31)));
    }

    #[test]
    fn rejects_impossible_and_nonconformant_days() {
        // Impossible literal days are rejected, not silently clamped to a plausible-looking day.
        assert!(matches!(parse("1985-02-30"), Err(EdtfError::Malformed(_))));
        assert!(matches!(parse("1985-02-29"), Err(EdtfError::Malformed(_)))); // 1985 is not a leap year
        assert!(matches!(parse("1984-04-31"), Err(EdtfError::Malformed(_))));
        // …but a real leap day is accepted.
        assert_eq!(parse("1984-02-29").unwrap().min, d(1984, 2, 29));

        // Month/day must be exactly two digits (ISO 8601-2).
        assert!(matches!(parse("1984-1-1"), Err(EdtfError::Malformed(_))));
        assert!(matches!(parse("1984-006"), Err(EdtfError::Malformed(_))));

        // A pathologically long digit run is rejected, not an arithmetic-overflow panic.
        assert!(matches!(
            parse("1984-99999999999999999999"),
            Err(EdtfError::Malformed(_))
        ));
    }

    #[test]
    fn malformed_inputs() {
        assert_eq!(parse(""), Err(EdtfError::Empty));
        assert_eq!(parse("   "), Err(EdtfError::Empty));
        assert!(matches!(parse("abcd"), Err(EdtfError::Malformed(_))));
        assert!(matches!(parse("1984-13"), Err(EdtfError::Malformed(_)))); // no month 13
        assert!(matches!(parse("1984-00"), Err(EdtfError::Malformed(_)))); // no month 0
        assert!(matches!(parse("984"), Err(EdtfError::Malformed(_)))); // year must be 4 digits
        assert!(matches!(
            parse("1964/2008/2010"),
            Err(EdtfError::Malformed(_))
        )); // two slashes
        assert!(matches!(parse("2001-21-05"), Err(EdtfError::Malformed(_)))); // season + day
    }
}
