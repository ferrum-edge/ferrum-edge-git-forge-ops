//! UTC timestamps in the exact RFC 3339 spellings `chrono` 0.4 produced.
//!
//! gitforgeops used `chrono` for four things: reading the clock, Unix seconds
//! for JWT claims, parsing RFC 3339 stamps to order them, and the
//! `created_at` / `updated_at` fields of the resource schema. `chrono` is
//! unmaintained (RUSTSEC-2026-0543), and those four jobs need neither time
//! zones nor calendar arithmetic, so this module does them with the standard
//! library and keeps every serialized byte the same:
//!
//! - [`Timestamp::to_rfc3339`] is `chrono::DateTime<Utc>::to_rfc3339`:
//!   `+00:00` offset, used by the state file (`last_applied_at`,
//!   `last_rotated`, `recorded_at`) and the apply lock.
//! - [`Display`](std::fmt::Display) and `Serialize` are chrono's serde form:
//!   `Z` suffix. Both use chrono's `SecondsFormat::AutoSi` fraction: none for
//!   whole seconds, otherwise 3, 6 or 9 digits, whichever is the shortest
//!   exact one.
//! - [`Timestamp::parse_rfc3339`] is `chrono::DateTime::parse_from_rfc3339`
//!   converted to UTC: four-digit year, `T`, `t` or a space between date and
//!   time, an optional fraction of any length (digits after the ninth are
//!   ignored), and `Z`, `z` or a `±HH:MM` offset below 24 hours. A `:60`
//!   second is kept as a leap second, as chrono keeps it.
//!
//! `Deserialize` uses the same parser. chrono's deserializer also accepted
//! inputs outside RFC 3339 (unpadded fields, spaces inside the stamp, offsets
//! without a colon, a `UTC` suffix, signed years); those are now rejected.
//!
//! Every [`Timestamp`] lies in UTC years 0000 through 9999, the range a
//! four-digit RFC 3339 year can spell. The parser refuses an offset that
//! moves an instant outside it (`0000-01-01T00:30:00+01:00` is UTC year -1),
//! which chrono accepted and then printed with a signed year this parser
//! cannot read back. So everything that serializes also deserializes, and
//! every stamp that parses still serializes exactly as chrono wrote it.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};

const SECONDS_PER_DAY: i64 = 86_400;
const NANOS_PER_SECOND: u32 = 1_000_000_000;
/// 0000-01-01T00:00:00Z, the earliest instant a four-digit year can spell.
const MIN_UNIX_SECONDS: i64 = -62_167_219_200;
/// 9999-12-31T23:59:59Z (plus fraction or leap second), the latest.
const MAX_UNIX_SECONDS: i64 = 253_402_300_799;

/// An instant in UTC with nanosecond precision, between
/// 0000-01-01T00:00:00Z and 9999-12-31T23:59:60.999999999Z.
///
/// `nanos` reaches past one second only for a leap second (`:60`), which is
/// stored as the preceding second plus the extra second in `nanos`, the same
/// representation chrono uses. Ordering is by instant: `secs` first, then
/// `nanos`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    secs: i64,
    nanos: u32,
}

/// Why a string is not an RFC 3339 timestamp. The messages are chrono's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The input ended before the timestamp was complete.
    TooShort,
    /// A character is not allowed where it appears.
    Invalid,
    /// A field is outside its range (month 13, February 30, offset 24:00).
    OutOfRange,
    /// Characters follow a complete timestamp.
    TooLong,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooShort => "premature end of input",
            Self::Invalid => "input contains invalid characters",
            Self::OutOfRange => "input is out of range",
            Self::TooLong => "trailing input",
        })
    }
}

impl std::error::Error for ParseError {}

impl Timestamp {
    /// The current wall-clock time, clamped to the supported range (a clock
    /// outside years 0000..=9999 is not a real clock).
    pub fn now() -> Self {
        let raw = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(after) => Self {
                secs: i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
                nanos: after.subsec_nanos(),
            },
            Err(err) => {
                let before = err.duration();
                let secs = i64::try_from(before.as_secs()).unwrap_or(i64::MAX);
                match before.subsec_nanos() {
                    0 => Self {
                        secs: -secs,
                        nanos: 0,
                    },
                    nanos => Self {
                        secs: -secs - 1,
                        nanos: NANOS_PER_SECOND - nanos,
                    },
                }
            }
        };
        if raw.secs < MIN_UNIX_SECONDS {
            Self {
                secs: MIN_UNIX_SECONDS,
                nanos: 0,
            }
        } else if raw.secs > MAX_UNIX_SECONDS {
            Self {
                secs: MAX_UNIX_SECONDS,
                nanos: NANOS_PER_SECOND - 1,
            }
        } else {
            raw
        }
    }

    /// Build a timestamp from Unix seconds and a nanosecond fraction below one
    /// second. Returns `None` for a larger fraction or an instant outside UTC
    /// years 0000..=9999.
    pub fn from_unix(secs: i64, nanos: u32) -> Option<Self> {
        (nanos < NANOS_PER_SECOND && (MIN_UNIX_SECONDS..=MAX_UNIX_SECONDS).contains(&secs))
            .then_some(Self { secs, nanos })
    }

    /// Whole seconds since the Unix epoch (`chrono`'s `timestamp()`). A leap
    /// second counts as the second before it.
    pub fn unix_seconds(self) -> i64 {
        self.secs
    }

    /// Parse an RFC 3339 timestamp with any offset and convert it to UTC.
    pub fn parse_rfc3339(input: &str) -> Result<Self, ParseError> {
        parse_rfc3339(input)
    }

    /// RFC 3339 with a `+00:00` offset, as `chrono`'s `to_rfc3339`.
    pub fn to_rfc3339(self) -> String {
        let mut out = String::with_capacity(32);
        self.write_rfc3339(&mut out, false)
            .expect("writing to a String cannot fail");
        out
    }

    fn write_rfc3339(self, out: &mut impl fmt::Write, use_z: bool) -> fmt::Result {
        let days = self.secs.div_euclid(SECONDS_PER_DAY);
        let second_of_day = self.secs.rem_euclid(SECONDS_PER_DAY);
        // Every constructor keeps the year in 0000..=9999, so four digits
        // always suffice and the output always parses again.
        let (year, month, day) = civil_from_days(days);
        write!(out, "{year:04}")?;
        let hour = second_of_day / 3600;
        let minute = second_of_day % 3600 / 60;
        let mut second = second_of_day % 60;
        let mut nanos = self.nanos;
        if nanos >= NANOS_PER_SECOND {
            second += 1;
            nanos -= NANOS_PER_SECOND;
        }
        write!(
            out,
            "-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"
        )?;
        match nanos {
            0 => {}
            _ if nanos.is_multiple_of(1_000_000) => write!(out, ".{:03}", nanos / 1_000_000)?,
            _ if nanos.is_multiple_of(1_000) => write!(out, ".{:06}", nanos / 1_000)?,
            _ => write!(out, ".{nanos:09}")?,
        }
        out.write_str(if use_z { "Z" } else { "+00:00" })
    }
}

/// The serde spelling: RFC 3339 with a `Z` suffix.
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_rfc3339(f, true)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TimestampVisitor;

        impl Visitor<'_> for TimestampVisitor {
            type Value = Timestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an RFC 3339 formatted date and time string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Timestamp, E> {
                parse_rfc3339(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
    }
}

fn parse_rfc3339(input: &str) -> Result<Timestamp, ParseError> {
    let bytes = input.as_bytes();
    if bytes.len() < 19 {
        return Err(ParseError::TooShort);
    }
    let digit = |index: usize| -> Result<i64, ParseError> {
        let byte = bytes[index];
        if byte.is_ascii_digit() {
            Ok(i64::from(byte - b'0'))
        } else {
            Err(ParseError::Invalid)
        }
    };
    let literal = |index: usize, expected: u8| -> Result<(), ParseError> {
        if bytes[index] == expected {
            Ok(())
        } else {
            Err(ParseError::Invalid)
        }
    };

    let year = digit(0)? * 1000 + digit(1)? * 100 + digit(2)? * 10 + digit(3)?;
    literal(4, b'-')?;
    let month = digit(5)? * 10 + digit(6)?;
    literal(7, b'-')?;
    let day = digit(8)? * 10 + digit(9)?;
    if !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&day) {
        return Err(ParseError::OutOfRange);
    }
    if !matches!(bytes[10], b'T' | b't' | b' ') {
        return Err(ParseError::Invalid);
    }
    let hour = digit(11)? * 10 + digit(12)?;
    literal(13, b':')?;
    let minute = digit(14)? * 10 + digit(15)?;
    literal(16, b':')?;
    let mut second = digit(17)? * 10 + digit(18)?;
    // RFC 3339 allows a leap second. Like chrono, keep it as the second
    // before plus one extra second of fraction.
    let mut nanos = 0u32;
    if second == 60 {
        second = 59;
        nanos = NANOS_PER_SECOND;
    }

    let mut rest = &input[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let (value, remaining) = parse_fraction(fraction)?;
        nanos += value;
        rest = remaining;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(ParseError::OutOfRange);
    }

    let (offset, rest) = parse_offset(rest)?;
    if !rest.is_empty() {
        return Err(ParseError::TooLong);
    }

    let local =
        days_from_civil(year, month, day) * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second;
    let secs = local - offset;
    // An offset can carry a four-digit local year into UTC year -1 or 10000,
    // which would serialize with a signed year that this parser refuses.
    if !(MIN_UNIX_SECONDS..=MAX_UNIX_SECONDS).contains(&secs) {
        return Err(ParseError::OutOfRange);
    }
    Ok(Timestamp { secs, nanos })
}

/// One to nine significant fraction digits, scaled to nanoseconds. Later
/// digits are consumed and ignored.
fn parse_fraction(input: &str) -> Result<(u32, &str), ParseError> {
    let digits = input.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return Err(if input.is_empty() {
            ParseError::TooShort
        } else {
            ParseError::Invalid
        });
    }
    let mut value = 0u32;
    for byte in input.bytes().take(digits.min(9)) {
        value = value * 10 + u32::from(byte - b'0');
    }
    for _ in digits.min(9)..9 {
        value *= 10;
    }
    Ok((value, &input[digits..]))
}

/// `Z`, `z` or `±HH:MM` (a U+2212 minus sign is accepted too), returned in
/// seconds east of UTC. The offset must stay below 24 hours.
fn parse_offset(input: &str) -> Result<(i64, &str), ParseError> {
    let (negative, rest) = match input.chars().next() {
        None => return Err(ParseError::TooShort),
        Some('Z' | 'z') => return Ok((0, &input[1..])),
        Some('+') => (false, &input[1..]),
        Some('-') => (true, &input[1..]),
        Some('\u{2212}') => (true, &input['\u{2212}'.len_utf8()..]),
        Some(_) => return Err(ParseError::Invalid),
    };
    let bytes = rest.as_bytes();
    if bytes.len() < 2 {
        return Err(ParseError::TooShort);
    }
    if !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return Err(ParseError::Invalid);
    }
    let hours = i64::from((bytes[0] - b'0') * 10 + (bytes[1] - b'0'));
    match bytes.get(2) {
        None => return Err(ParseError::TooShort),
        Some(b':') => {}
        Some(_) => return Err(ParseError::Invalid),
    }
    let minutes_bytes = &bytes[3..];
    if minutes_bytes.len() < 2 {
        return Err(ParseError::TooShort);
    }
    let minutes = match (minutes_bytes[0], minutes_bytes[1]) {
        (tens @ b'0'..=b'5', ones @ b'0'..=b'9') => i64::from((tens - b'0') * 10 + (ones - b'0')),
        (b'6'..=b'9', b'0'..=b'9') => return Err(ParseError::OutOfRange),
        _ => return Err(ParseError::Invalid),
    };
    let seconds = hours * 3600 + minutes * 60;
    if seconds >= SECONDS_PER_DAY {
        return Err(ParseError::OutOfRange);
    }
    Ok((if negative { -seconds } else { seconds }, &rest[5..]))
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The proleptic Gregorian date `days` after 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64, nanos: u32) -> Timestamp {
        Timestamp { secs, nanos }
    }

    #[test]
    fn civil_conversion_round_trips_every_day_of_the_supported_range() {
        // 0000-01-01 through 9999-12-31, plus a day either side for offsets.
        let first = days_from_civil(-1, 12, 31);
        let last = days_from_civil(10_000, 1, 1);
        let mut expected = (-1, 12, 31);
        for days in first..=last {
            let civil = civil_from_days(days);
            assert_eq!(civil, expected, "day {days}");
            assert_eq!(days_from_civil(civil.0, civil.1, civil.2), days);
            let (year, month, day) = expected;
            expected = if day < days_in_month(year, month) {
                (year, month, day + 1)
            } else if month < 12 {
                (year, month + 1, 1)
            } else {
                (year + 1, 1, 1)
            };
        }
    }

    #[test]
    fn known_instants_format_like_chrono() {
        // (unix seconds, nanos, chrono's serde / to_rfc3339 spelling)
        let cases = [
            (0, 0, "1970-01-01T00:00:00"),
            (-1, 0, "1969-12-31T23:59:59"),
            (951_782_400, 0, "2000-02-29T00:00:00"),
            (1_700_000_000, 0, "2023-11-14T22:13:20"),
            (253_402_300_799, 0, "9999-12-31T23:59:59"),
            (-62_167_219_200, 0, "0000-01-01T00:00:00"),
            (1_700_000_000, 100_000_000, "2023-11-14T22:13:20.100"),
            (1_700_000_000, 123_000_000, "2023-11-14T22:13:20.123"),
            (1_700_000_000, 123_456_000, "2023-11-14T22:13:20.123456"),
            (1_700_000_000, 123_456_789, "2023-11-14T22:13:20.123456789"),
            (1_700_000_000, 1_000, "2023-11-14T22:13:20.000001"),
            (1_700_000_000, 1, "2023-11-14T22:13:20.000000001"),
            (1_700_000_000, 999_999_999, "2023-11-14T22:13:20.999999999"),
        ];
        for (secs, nanos, expected) in cases {
            let stamp = ts(secs, nanos);
            assert_eq!(stamp.to_string(), format!("{expected}Z"));
            assert_eq!(stamp.to_rfc3339(), format!("{expected}+00:00"));
        }
    }

    #[test]
    fn parses_rfc3339_like_chrono() {
        let cases = [
            ("2023-11-14T22:13:20Z", "2023-11-14T22:13:20Z"),
            ("2023-11-14t22:13:20z", "2023-11-14T22:13:20Z"),
            ("2023-11-14 22:13:20Z", "2023-11-14T22:13:20Z"),
            ("2023-11-14T22:13:20+00:00", "2023-11-14T22:13:20Z"),
            ("2023-11-14T22:13:20-00:00", "2023-11-14T22:13:20Z"),
            ("2023-11-15T00:13:20+02:00", "2023-11-14T22:13:20Z"),
            ("2023-11-14T20:13:20-02:00", "2023-11-14T22:13:20Z"),
            ("2023-11-14T20:13:20\u{2212}02:00", "2023-11-14T22:13:20Z"),
            ("2023-11-14T22:13:20+23:59", "2023-11-13T22:14:20Z"),
            ("2023-11-14T22:13:20.5Z", "2023-11-14T22:13:20.500Z"),
            ("2023-11-14T22:13:20.000Z", "2023-11-14T22:13:20Z"),
            ("2023-11-14T22:13:20.123456Z", "2023-11-14T22:13:20.123456Z"),
            (
                "2023-11-14T22:13:20.1234567Z",
                "2023-11-14T22:13:20.123456700Z",
            ),
            (
                "2023-11-14T22:13:20.123456789987654321Z",
                "2023-11-14T22:13:20.123456789Z",
            ),
            ("2024-02-29T00:00:00Z", "2024-02-29T00:00:00Z"),
            ("2000-02-29T00:00:00Z", "2000-02-29T00:00:00Z"),
            ("0000-01-01T00:30:00-01:00", "0000-01-01T01:30:00Z"),
            ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
            ("9999-12-31T23:30:00+01:00", "9999-12-31T22:30:00Z"),
            (
                "9999-12-31T23:59:59.999999999Z",
                "9999-12-31T23:59:59.999999999Z",
            ),
            ("9999-12-31T23:59:60Z", "9999-12-31T23:59:60Z"),
            ("2016-12-31T23:59:60Z", "2016-12-31T23:59:60Z"),
            ("2016-12-31T23:59:60.25Z", "2016-12-31T23:59:60.250Z"),
            ("2017-01-01T00:59:60+01:00", "2016-12-31T23:59:60Z"),
        ];
        for (input, expected) in cases {
            let parsed = Timestamp::parse_rfc3339(input).unwrap();
            assert_eq!(parsed.to_string(), expected, "{input}");
        }
    }

    #[test]
    fn rejects_what_chrono_parse_from_rfc3339_rejects() {
        let cases = [
            ("", ParseError::TooShort),
            ("2023-11-14T22:13:2", ParseError::TooShort),
            ("2023-11-14T22:13:20", ParseError::TooShort),
            ("2023-11-14T22:13:20.", ParseError::TooShort),
            ("2023-11-14T22:13:20.Z", ParseError::Invalid),
            ("2023-11-14T22:13:20+02", ParseError::TooShort),
            ("2023-11-14T22:13:20+02:0", ParseError::TooShort),
            ("2023-11-14T22:13:20+0200", ParseError::Invalid),
            ("2023-11-14T22:13:20+24:00", ParseError::OutOfRange),
            ("2023-11-14T22:13:20+02:60", ParseError::OutOfRange),
            ("2023-11-14T22:13:20 Z", ParseError::Invalid),
            ("2023-11-14T22:13:20UTC", ParseError::Invalid),
            ("2023-11-14T22:13:20Z ", ParseError::TooLong),
            ("2023-11-14T22:13:20+02:00x", ParseError::TooLong),
            ("2023-11-14X22:13:20Z", ParseError::Invalid),
            ("2023/11/14T22:13:20Z", ParseError::Invalid),
            ("2023-1-14T22:13:20Z", ParseError::Invalid),
            ("+2023-11-14T22:13:20Z", ParseError::Invalid),
            ("2023-00-14T22:13:20Z", ParseError::OutOfRange),
            ("2023-13-14T22:13:20Z", ParseError::OutOfRange),
            ("2023-11-00T22:13:20Z", ParseError::OutOfRange),
            ("2023-02-29T22:13:20Z", ParseError::OutOfRange),
            ("1900-02-29T22:13:20Z", ParseError::OutOfRange),
            ("2023-11-31T22:13:20Z", ParseError::OutOfRange),
            ("2023-11-14T24:00:00Z", ParseError::OutOfRange),
            ("2023-11-14T22:60:20Z", ParseError::OutOfRange),
            ("2023-11-14T22:13:61Z", ParseError::OutOfRange),
            // Valid four-digit local times whose offset leaves UTC 0000..=9999.
            ("0000-01-01T00:30:00+01:00", ParseError::OutOfRange),
            ("0000-01-01T00:00:00.5+00:01", ParseError::OutOfRange),
            ("9999-12-31T23:30:00-01:00", ParseError::OutOfRange),
            ("9999-12-31T23:59:59-00:01", ParseError::OutOfRange),
        ];
        for (input, expected) in cases {
            assert_eq!(Timestamp::parse_rfc3339(input), Err(expected), "{input:?}");
        }
    }

    #[test]
    fn orders_by_instant_across_offsets_and_leap_seconds() {
        let parse = |s: &str| Timestamp::parse_rfc3339(s).unwrap();
        assert!(parse("2026-09-01T00:00:00+00:00") < parse("2026-09-02T00:00:00+00:00"));
        assert_eq!(
            parse("2026-09-01T02:00:00+02:00"),
            parse("2026-09-01T00:00:00Z")
        );
        assert!(parse("2026-09-01T01:00:00+02:00") < parse("2026-09-01T00:00:00Z"));
        assert!(parse("2026-09-01T00:00:00.000000001Z") > parse("2026-09-01T00:00:00Z"));
        assert!(parse("2016-12-31T23:59:59.999Z") < parse("2016-12-31T23:59:60Z"));
        assert!(parse("2016-12-31T23:59:60.999Z") < parse("2017-01-01T00:00:00Z"));
    }

    #[test]
    fn unix_seconds_and_now() {
        let stamp = Timestamp::parse_rfc3339("2023-11-14T22:13:20.75Z").unwrap();
        assert_eq!(stamp.unix_seconds(), 1_700_000_000);
        assert_eq!(
            Timestamp::from_unix(1_700_000_000, 750_000_000),
            Some(stamp)
        );
        assert_eq!(Timestamp::from_unix(0, NANOS_PER_SECOND), None);
        assert!(Timestamp::from_unix(MIN_UNIX_SECONDS, 0).is_some());
        assert!(Timestamp::from_unix(MAX_UNIX_SECONDS, NANOS_PER_SECOND - 1).is_some());
        assert_eq!(Timestamp::from_unix(MIN_UNIX_SECONDS - 1, 0), None);
        assert_eq!(Timestamp::from_unix(MAX_UNIX_SECONDS + 1, 0), None);
        let leap = Timestamp::parse_rfc3339("2016-12-31T23:59:60Z").unwrap();
        assert_eq!(leap.unix_seconds(), 1_483_228_799);

        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let now = Timestamp::now();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let secs = u64::try_from(now.unix_seconds()).unwrap();
        assert!((before..=after).contains(&secs));
        assert_eq!(Timestamp::parse_rfc3339(&now.to_rfc3339()), Ok(now));
        assert_eq!(Timestamp::parse_rfc3339(&now.to_string()), Ok(now));
    }

    #[test]
    fn every_timestamp_at_the_range_edges_round_trips() {
        let edges = [
            ts(MIN_UNIX_SECONDS, 0),
            ts(MIN_UNIX_SECONDS, 1),
            ts(MAX_UNIX_SECONDS, 0),
            ts(MAX_UNIX_SECONDS, NANOS_PER_SECOND - 1),
            ts(MAX_UNIX_SECONDS, NANOS_PER_SECOND),
            ts(MAX_UNIX_SECONDS, 2 * NANOS_PER_SECOND - 1),
            Timestamp::parse_rfc3339("0000-01-01T00:30:00-01:00").unwrap(),
            Timestamp::parse_rfc3339("9999-12-31T23:30:00+01:00").unwrap(),
        ];
        for stamp in edges {
            assert_eq!(Timestamp::parse_rfc3339(&stamp.to_string()), Ok(stamp));
            assert_eq!(Timestamp::parse_rfc3339(&stamp.to_rfc3339()), Ok(stamp));
            let json = serde_json::to_string(&stamp).unwrap();
            assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), stamp);
        }
        assert_eq!(ts(MIN_UNIX_SECONDS, 0).to_string(), "0000-01-01T00:00:00Z");
        assert_eq!(
            ts(MAX_UNIX_SECONDS, 2 * NANOS_PER_SECOND - 1).to_string(),
            "9999-12-31T23:59:60.999999999Z"
        );
    }

    #[test]
    fn serde_uses_the_z_spelling_and_the_rfc3339_parser() {
        let stamp = Timestamp::parse_rfc3339("2023-11-14T22:13:20.123Z").unwrap();
        assert_eq!(
            serde_json::to_string(&stamp).unwrap(),
            "\"2023-11-14T22:13:20.123Z\""
        );
        let back: Timestamp = serde_json::from_str("\"2023-11-15T00:13:20.123+02:00\"").unwrap();
        assert_eq!(back, stamp);
        let err = serde_json::from_str::<Timestamp>("\"2023-11-14T22:13:20\"").unwrap_err();
        assert!(err.to_string().contains("premature end of input"), "{err}");
        let err = serde_json::from_str::<Timestamp>("1700000000").unwrap_err();
        assert!(
            err.to_string()
                .contains("an RFC 3339 formatted date and time string"),
            "{err}"
        );
    }
}
