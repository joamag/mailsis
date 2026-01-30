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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uid_fetch_range_str_simple_range() {
        assert_eq!(uid_fetch_range_str("1:10", 100), Some(1..=10));
    }

    #[test]
    fn test_uid_fetch_range_str_single_uid() {
        assert_eq!(uid_fetch_range_str("10", 100), Some(10..=10));
    }

    #[test]
    fn test_uid_fetch_range_str_wildcard_end() {
        assert_eq!(uid_fetch_range_str("1:*", 100), Some(1..=100));
    }

    #[test]
    fn test_uid_fetch_range_str_wildcard_only() {
        assert_eq!(uid_fetch_range_str("*", 100), Some(100..=100));
    }

    #[test]
    fn test_uid_fetch_range_str_reversed_range() {
        assert_eq!(uid_fetch_range_str("10:1", 100), Some(1..=10));
    }

    #[test]
    fn test_uid_fetch_range_str_invalid_input() {
        assert_eq!(uid_fetch_range_str("abc", 100), None);
    }

    #[test]
    fn test_uid_fetch_range_str_invalid_end() {
        assert_eq!(uid_fetch_range_str("1:abc", 100), None);
    }

    #[test]
    fn test_uid_fetch_range_str_same_start_end() {
        assert_eq!(uid_fetch_range_str("5:5", 100), Some(5..=5));
    }

    #[test]
    fn test_uid_fetch_range_with_end() {
        assert_eq!(uid_fetch_range("1", Some("10"), 100), Some(1..=10));
    }

    #[test]
    fn test_uid_fetch_range_without_end() {
        assert_eq!(uid_fetch_range("5", None, 100), Some(5..=5));
    }

    #[test]
    fn test_uid_fetch_range_wildcard_start() {
        assert_eq!(uid_fetch_range("*", None, 50), Some(50..=50));
    }

    #[test]
    fn test_uid_fetch_range_wildcard_end() {
        assert_eq!(uid_fetch_range("1", Some("*"), 50), Some(1..=50));
    }

    #[test]
    fn test_uid_fetch_range_both_wildcards() {
        assert_eq!(uid_fetch_range("*", Some("*"), 50), Some(50..=50));
    }

    #[test]
    fn test_uid_fetch_range_invalid_start() {
        assert_eq!(uid_fetch_range("bad", None, 100), None);
    }

    #[test]
    fn test_uid_fetch_range_invalid_end() {
        assert_eq!(uid_fetch_range("1", Some("bad"), 100), None);
    }

    #[test]
    fn test_uid_fetch_range_max_uid_zero() {
        assert_eq!(uid_fetch_range_str("*", 0), Some(0..=0));
    }
}
