use std::{collections::HashMap, error::Error};

/// Checks whether a raw email contains a `MIME-Version:` header,
/// indicating it is a valid MIME message per RFC 2045.
///
/// Only the header section (lines before the first blank line) is inspected.
/// A `MIME-Version:` header appearing in the content (after the blank
/// line separator) is not considered valid.
///
/// # Examples
///
/// A message with a `MIME-Version` header is valid:
///
/// ```rust
/// assert!(mailsis_utils::is_mime_valid(
///     "MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nBody"
/// ));
/// ```
///
/// A message without a `MIME-Version` header is not valid:
///
/// ```rust
/// assert!(!mailsis_utils::is_mime_valid("Subject: Hello\r\n\r\nBody"));
/// ```
///
/// `MIME-Version` in the body (after the blank line) does not count:
///
/// ```rust
/// assert!(!mailsis_utils::is_mime_valid(
///     "Subject: Hello\r\n\r\nMIME-Version: 1.0"
/// ));
/// ```
pub fn is_mime_valid(raw: &str) -> bool {
    for line in raw.lines() {
        if line.trim().is_empty() {
            break;
        }
        if line.trim().starts_with("MIME-Version:") {
            return true;
        }
    }
    false
}

/// Parses the headers of a MIME email, returning a hashmap of the headers.
///
/// The parsing is done by splitting the raw email on the first empty line,
/// and splitting each line on the colon, separating the key and value.
///
/// Aligned with the RFC 2045, the headers are case-insensitive.
///
/// # Examples
///
/// ```rust
/// let expected = [("From", "test@example.com"), ("To", "test@example.com")]
///     .into_iter()
///     .map(|(k, v)| (k.to_string(), v.to_string()))
///     .collect::<std::collections::HashMap<_, _>>();
/// let headers = mailsis_utils::parse_mime_headers("From: test@example.com\r\nTo: test@example.com\r\n").unwrap();
/// assert_eq!(headers, expected);
/// ```
///
/// ```rust
/// let expected = [("From", "test@example.com"), ("To", "test@example.com")]
///     .into_iter()
///     .map(|(k, v)| (k.to_string(), v.to_string()))
///     .collect::<std::collections::HashMap<_, _>>();
/// let headers = mailsis_utils::parse_mime_headers("From: test@example.com\r\nTo: test@example.com\r\n\r\nBody of the email").unwrap();
/// assert_eq!(headers, expected);
/// ```
pub fn parse_mime_headers(raw: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut headers = HashMap::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(headers)
}

/// Parses headers from a raw email, returning an ordered list of headers
/// and a reference to the content after the blank-line separator.
///
/// Headers are preserved in their original order with case-preserved keys
/// and trimmed values. This supports duplicate headers (e.g. `Received`).
///
/// # Examples
///
/// ```rust
/// let (headers, content) = mailsis_utils::parse_raw_headers(
///     "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nHello!"
/// );
/// assert_eq!(headers.len(), 2);
/// assert_eq!(headers[0], ("From".to_string(), "alice@example.com".to_string()));
/// assert_eq!(content, "Hello!");
/// ```
pub fn parse_raw_headers(raw: &str) -> (Vec<(String, String)>, &str) {
    let mut headers = Vec::new();
    let mut pos = 0;

    for line in raw.lines() {
        let line_len = line.len();
        let end = pos + line_len;
        let consumed = if raw[end..].starts_with("\r\n") {
            end + 2
        } else if raw[end..].starts_with('\n') {
            end + 1
        } else {
            end
        };

        if line.trim().is_empty() {
            pos = consumed;
            break;
        }

        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_string(), value.trim().to_string()));
        } else {
            // Line is not a header (no colon) and not blank, treat as start of content
            break;
        }

        pos = consumed;
    }

    (headers, &raw[pos..])
}
