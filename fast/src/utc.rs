//! UTC timestamps for incident output.
//!
//! A bundle records a time as a Unix second count, because that is what a
//! clock gives and what a sort needs. An operator reads a calendar date, not
//! a number of seconds since 1970. This module converts one to the other
//! without pulling in a time-zone database: everything rand-fast writes is
//! UTC, so the only calendar work is turning a day count into a date, which
//! is a closed-form calculation.
//!
//! # Why not a dependency
//!
//! `chrono` and `time` are large, and both exist to solve problems this crate
//! does not have: local time zones, leap seconds, parsing, formatting
//! directives. Nine lines of day arithmetic produce exactly the string the
//! incident commands print, and the tests pin the leap-year boundaries that a
//! hand-rolled calendar gets wrong.

/// Renders Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Fractional seconds are dropped: a trigger is an interval measurement, and
/// printing milliseconds would imply a precision the recorder does not have.
/// Values outside the range of an `i64` second count saturate rather than
/// panic, which keeps a corrupted manifest from taking down a list.
pub(crate) fn timestamp(unix_seconds: f64) -> String {
    if !unix_seconds.is_finite() {
        return "invalid timestamp".to_string();
    }
    let seconds = unix_seconds.floor();
    let seconds = if seconds >= i64::MAX as f64 {
        i64::MAX
    } else if seconds <= i64::MIN as f64 {
        i64::MIN
    } else {
        seconds as i64
    };
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60
    )
}

/// The current wall clock as Unix seconds, when the clock is readable.
pub(crate) fn now_unix_seconds() -> Option<f64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs_f64())
}

/// Howard Hinnant's `civil_from_days`: proleptic Gregorian date for a day
/// count relative to 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the year.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (year + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_1970() {
        assert_eq!(timestamp(0.0), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp(-1.0), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn a_known_incident_time_round_trips_to_the_calendar() {
        // 2025-11-06T03:14:05Z, computed independently with `date -u`.
        assert_eq!(timestamp(1_762_398_845.9), "2025-11-06T03:14:05Z");
    }

    #[test]
    fn leap_days_and_year_boundaries_are_dates_not_offsets() {
        // 2000-02-29, the leap day a naive four-year rule still gets right but
        // a century rule gets wrong.
        assert_eq!(timestamp(951_782_400.0), "2000-02-29T00:00:00Z");
        // 2100-03-01: 2100 is not a leap year.
        assert_eq!(timestamp(4_107_542_400.0), "2100-03-01T00:00:00Z");
        assert_eq!(timestamp(1_767_225_599.0), "2025-12-31T23:59:59Z");
    }

    #[test]
    fn a_broken_timestamp_does_not_panic() {
        assert_eq!(timestamp(f64::NAN), "invalid timestamp");
        assert_eq!(timestamp(f64::INFINITY), "invalid timestamp");
        assert!(timestamp(1e30).starts_with("2"));
    }
}
