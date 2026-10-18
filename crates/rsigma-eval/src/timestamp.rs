//! Event timestamp parsing shared by the time-part modifiers and the
//! correlation engine, so both accept the same values.

use chrono::{DateTime, NaiveDateTime, Utc};

/// Epoch values above this are milliseconds rather than seconds.
const EPOCH_MILLIS_THRESHOLD: i64 = 1_000_000_000_000;

/// Normalize an epoch value to seconds, treating values above 10^12 as
/// milliseconds.
pub(crate) fn normalize_epoch(v: i64) -> i64 {
    if v > EPOCH_MILLIS_THRESHOLD {
        v / 1000
    } else {
        v
    }
}

/// Parse a timestamp string: RFC 3339, or `YYYY-MM-DD` followed by `T` or a
/// space and `HH:MM:SS` with an optional fraction, read as UTC.
pub(crate) fn parse_timestamp_str(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.to_utc());
    }
    // `%.f` also accepts a missing fraction.
    ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"]
        .iter()
        .find_map(|format| NaiveDateTime::parse_from_str(s, format).ok())
        .map(|naive| naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_supported_string_form() {
        let whole = 1720614600;
        for (input, secs) in [
            ("2024-07-10T12:30:00Z", whole),
            ("2024-07-10T12:30:00.500Z", whole),
            ("2024-07-10T14:30:00+02:00", whole),
            ("2024-07-10T12:30:00", whole),
            ("2024-07-10T12:30:00.500", whole),
            ("2024-07-10 12:30:00", whole),
            ("2024-07-10 12:30:00.500", whole),
        ] {
            let dt = parse_timestamp_str(input).unwrap_or_else(|| panic!("{input} parses"));
            assert_eq!(dt.timestamp(), secs, "{input}");
        }
        assert_eq!(
            parse_timestamp_str("2024-07-10 12:30:00.500")
                .unwrap()
                .timestamp_subsec_millis(),
            500
        );
    }

    #[test]
    fn rejects_other_strings() {
        for input in ["", "garbage", "2024-07-10", "12:30:00", "1720614600"] {
            assert_eq!(parse_timestamp_str(input), None, "{input}");
        }
    }

    #[test]
    fn epoch_milliseconds_become_seconds() {
        assert_eq!(normalize_epoch(1720614600), 1720614600);
        assert_eq!(normalize_epoch(1720614600500), 1720614600);
    }
}
