use std::{collections::HashMap, error::Error};

/// Checks if the email is a valid MIME email.
///
/// A valid MIME email contains a "MIME-Version:" header in the headers section.
pub async fn is_mime_valid(body: &str) -> bool {
    for line in body.lines() {
        if line.trim().is_empty() {
            break;
        }
        if line.trim().starts_with("MIME-Version:") {
            return true;
        }
    }
    false
}

/// Parses the headers of a MIME email.
///
/// Returns a hashmap of the headers.
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
pub fn parse_mime_headers(body: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut headers = HashMap::new();
    for line in body.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(headers)
}
