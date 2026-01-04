use std::ops::RangeInclusive;

/// Converts a string range from an IMAP UID FETCH command into a range of
/// u32 values.
///
/// The input string should be in the format `start:end`, where `start` and
/// `end` are u32 values.
///
/// If only one value is provided, the range will be from 1 to the provided
/// value.
///
/// # Examples
///
/// ```rust
/// let range = mailsis_utils::uid_fetch_range_str("1:10", 100);
/// assert_eq!(range, Some(1..=10));
/// ```
///
/// ```rust
/// let range = mailsis_utils::uid_fetch_range_str("10", 100);
/// assert_eq!(range, Some(10..=10));
/// ```
///
/// ```rust
/// let range = mailsis_utils::uid_fetch_range_str("1:*", 100);
/// assert_eq!(range, Some(1..=100));
/// ```
///
/// ```rust
/// let range = mailsis_utils::uid_fetch_range_str("*", 100);
/// assert_eq!(range, Some(100..=100));
/// ```
pub fn uid_fetch_range_str(input: &str, max_uid: u32) -> Option<RangeInclusive<u32>> {
    let (start_str, end_str_opt) = if let Some((start, end)) = input.split_once(':') {
        (start, Some(end))
    } else {
        (input, None)
    };

    uid_fetch_range(start_str, end_str_opt, max_uid)
}

pub fn uid_fetch_range(
    start: &str,
    end: Option<&str>,
    max_uid: u32,
) -> Option<RangeInclusive<u32>> {
    let start = if start == "*" {
        max_uid
    } else {
        start.parse::<u32>().ok()?
    };

    let end = match end {
        Some("*") => max_uid,
        Some(s) => s.parse::<u32>().ok()?,
        None => start,
    };

    Some(start.min(end)..=start.max(end))
}
