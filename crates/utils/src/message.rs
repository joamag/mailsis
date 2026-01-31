//! Core email message types used throughout the mail pipeline.
//!
//! This module defines [`EmailMessage`], the central representation of an
//! email with structured [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322)
//! headers, cached serialization, and connection metadata. It also defines
//! [`IncomingMessage`], the SMTP envelope wrapper received before
//! per-recipient routing.

use std::{collections::HashSet, net::IpAddr};

use uuid::Uuid;

use crate::parse_raw_headers;

/// Represents an email message for storage operations.
///
/// Headers are stored as an ordered `Vec` (preserving RFC 5322 order and
/// supporting duplicate headers such as `Received`). A cached `raw` field
/// holds the full serialized form; call [`rebuild`](Self::rebuild) after
/// modifying headers so that [`raw`](Self::raw) reflects the changes.
#[derive(Debug, Clone)]
pub struct EmailMessage {
    /// Unique message identifier, RFC 5322 message-id format.
    pub message_id: String,

    /// Sender address, RFC 5322 address format.
    pub from: String,

    /// Recipient address, RFC 5322 address format.
    pub to: String,

    /// IP address of the connecting SMTP client (for SPF verification).
    pub client_ip: Option<IpAddr>,

    /// HELO/EHLO domain presented by the connecting client (for SPF verification).
    pub helo_domain: Option<String>,

    /// Ordered list of MIME headers (case-preserved keys, trimmed values).
    headers: Vec<(String, String)>,

    /// Message body after the blank-line separator (RFC 5322 body).
    body: String,

    /// Cached full serialization (headers + blank line + body).
    /// Rebuilt via [`rebuild`](Self::rebuild) after header mutations.
    raw: String,

    /// Original raw body as received, never modified after construction.
    /// Used for byte-exact operations such as DKIM signature verification.
    original_raw: String,
}

impl EmailMessage {
    pub fn new(from: String, to: String, raw: String) -> Self {
        let message_id = Uuid::new_v4().to_string();
        let (headers, content) = parse_raw_headers(&raw);
        Self {
            message_id,
            from,
            to,
            headers,
            body: content.to_string(),
            raw: raw.clone(),
            original_raw: raw,
            client_ip: None,
            helo_domain: None,
        }
    }

    pub fn from_raw(from: &str, to: &str, raw: &str) -> Self {
        Self::new(from.to_string(), to.to_string(), raw.to_string())
    }

    pub fn with_id(
        message_id: String,
        from: String,
        to: String,
        subject: String,
        raw: String,
    ) -> Self {
        let (headers, content) = parse_raw_headers(&raw);
        let has_subject = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Subject"));
        let mut msg = Self {
            message_id,
            from,
            to,
            headers,
            body: content.to_string(),
            raw: raw.clone(),
            original_raw: raw,
            client_ip: None,
            helo_domain: None,
        };
        if !has_subject && !subject.is_empty() {
            msg.prepend_header("Subject", &subject);
            msg.rebuild();
        }
        msg
    }

    /// Returns the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns the email subject (convenience for `header("Subject")`).
    pub fn subject(&self) -> &str {
        self.header("Subject").unwrap_or_default()
    }

    /// Returns the full serialized email (headers + blank line + content).
    ///
    /// Returns the cached [`Self::raw`] field. Call [`rebuild`](Self::rebuild) after
    /// modifying headers to ensure this is up to date.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns the original raw email as received, before any transformer modifications.
    ///
    /// Use this for byte-exact operations such as DKIM signature verification,
    /// where the original byte sequence must be preserved.
    pub fn original_raw(&self) -> &str {
        &self.original_raw
    }

    /// Returns the message body after the header section (RFC 5322 body).
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Returns whether the message has any MIME headers.
    pub fn has_headers(&self) -> bool {
        !self.headers.is_empty()
    }

    /// Returns a reference to the ordered header list.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Prepends a header to the beginning of the header list.
    ///
    /// The cached [`raw`](Self::raw) field is **not** updated automatically, call
    /// [`rebuild`](Self::rebuild) once after all header modifications are done
    /// (e.g. after running all transformers via [`MessageTransformer::apply`]).
    pub fn prepend_header(&mut self, name: &str, value: &str) {
        self.headers
            .insert(0, (name.to_string(), value.to_string()));
    }

    /// Rebuilds the cached [`raw`](Self::raw) field from [`headers`](Self::headers) and [`body`](Self::body).
    ///
    /// Call this once after all header modifications are complete so that
    /// [`raw()`](Self::raw) returns the up-to-date serialized form.
    ///
    /// Pre-computes the exact byte length, allocates once, and writes all
    /// parts via `push_str`.
    pub fn rebuild(&mut self) {
        let headers_len: usize = self
            .headers
            .iter()
            .map(|(k, v)| k.len() + 2 + v.len() + 2)
            .sum();

        let capacity = headers_len + if self.headers.is_empty() { 0 } else { 2 } + self.body.len();

        let mut raw = String::with_capacity(capacity);

        for (key, value) in &self.headers {
            raw.push_str(key);
            raw.push_str(": ");
            raw.push_str(value);
            raw.push_str("\r\n");
        }

        if !self.headers.is_empty() {
            raw.push_str("\r\n");
        }

        raw.push_str(&self.body);

        self.raw = raw;
    }
}

/// An incoming email message with connection metadata.
///
/// Represents a message received over SMTP before it is split into
/// per-recipient [`EmailMessage`] instances for routing.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    /// Envelope sender address.
    pub from: String,

    /// Set of envelope recipient addresses.
    pub rcpts: HashSet<String>,

    /// Raw message data (headers + content).
    pub raw: String,

    /// IP address of the connecting SMTP client.
    pub client_ip: Option<IpAddr>,

    /// HELO/EHLO domain presented by the connecting client.
    pub helo_domain: Option<String>,
}

impl IncomingMessage {
    /// Creates an [`EmailMessage`] for a specific recipient from this incoming message.
    pub fn to_email_message(&self, rcpt: &str) -> EmailMessage {
        let mut message = EmailMessage::new(self.from.clone(), rcpt.to_string(), self.raw.clone());
        message.client_ip = self.client_ip;
        message.helo_domain = self.helo_domain.clone();
        message
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_email_message_new() {
        let message = EmailMessage::new(
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Subject: Hello\r\n\r\nBody text".to_string(),
        );

        assert_eq!(message.from, "sender@example.com");
        assert_eq!(message.to, "recipient@example.com");
        assert_eq!(message.subject(), "Hello");
        assert_eq!(message.body(), "Body text");
        assert_eq!(message.raw(), "Subject: Hello\r\n\r\nBody text");
    }

    #[test]
    fn test_email_message_from_raw() {
        let message = EmailMessage::from_raw(
            "sender@example.com",
            "recipient@example.com",
            "Subject: Test\r\n\r\nContent",
        );

        assert_eq!(message.subject(), "Test");
        assert_eq!(message.body(), "Content");
    }

    #[test]
    fn test_email_message_with_id() {
        let message = EmailMessage::with_id(
            "custom-id".to_string(),
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "My Subject".to_string(),
            "Body only".to_string(),
        );

        assert_eq!(message.message_id, "custom-id");
        assert_eq!(message.subject(), "My Subject");
        assert!(message.raw().contains("Subject: My Subject"));
        assert!(message.raw().contains("Body only"));
    }

    #[test]
    fn test_email_message_with_id_existing_subject() {
        let message = EmailMessage::with_id(
            "id".to_string(),
            "from@test.com".to_string(),
            "to@test.com".to_string(),
            "Ignored".to_string(),
            "Subject: Existing\r\n\r\nBody".to_string(),
        );

        assert_eq!(message.subject(), "Existing");
    }

    #[test]
    fn test_email_message_no_headers() {
        let message = EmailMessage::from_raw("from@test.com", "to@test.com", "Plain text body");

        assert!(!message.has_headers());
        assert_eq!(message.subject(), "");
        assert_eq!(message.body(), "Plain text body");
    }

    #[test]
    fn test_email_message_prepend_header_and_rebuild() {
        let mut message =
            EmailMessage::from_raw("from@test.com", "to@test.com", "Subject: Test\r\n\r\nBody");

        message.prepend_header("X-Custom", "value");
        message.rebuild();

        assert!(message.raw().starts_with("X-Custom: value\r\n"));
        assert!(message.raw().contains("Subject: Test"));
        assert!(message.raw().ends_with("Body"));
    }

    #[test]
    fn test_email_message_original_raw_preserved() {
        let mut message =
            EmailMessage::from_raw("from@test.com", "to@test.com", "Subject: Test\r\n\r\nBody");
        let original = message.original_raw().to_string();

        message.prepend_header("X-New", "header");
        message.rebuild();

        assert_eq!(message.original_raw(), original);
        assert_ne!(message.raw(), message.original_raw());
    }

    #[test]
    fn test_email_message_headers_accessor() {
        let message = EmailMessage::from_raw(
            "from@test.com",
            "to@test.com",
            "From: a@b.com\r\nTo: c@d.com\r\n\r\nBody",
        );

        assert_eq!(message.headers().len(), 2);
        assert_eq!(message.headers()[0].0, "From");
        assert_eq!(message.headers()[1].0, "To");
    }

    #[test]
    fn test_incoming_message_to_email_message() {
        let incoming = IncomingMessage {
            from: "sender@example.com".to_string(),
            rcpts: HashSet::from(["rcpt@example.com".to_string()]),
            raw: "Subject: Test\r\n\r\nBody".to_string(),
            client_ip: Some("127.0.0.1".parse().unwrap()),
            helo_domain: Some("mail.example.com".to_string()),
        };

        let message = incoming.to_email_message("rcpt@example.com");

        assert_eq!(message.from, "sender@example.com");
        assert_eq!(message.to, "rcpt@example.com");
        assert_eq!(message.raw(), "Subject: Test\r\n\r\nBody");
        assert_eq!(message.client_ip, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(message.helo_domain, Some("mail.example.com".to_string()));
    }

    #[test]
    fn test_incoming_message_to_email_message_without_metadata() {
        let incoming = IncomingMessage {
            from: "sender@example.com".to_string(),
            rcpts: HashSet::from(["rcpt@example.com".to_string()]),
            raw: "Hello".to_string(),
            client_ip: None,
            helo_domain: None,
        };

        let message = incoming.to_email_message("rcpt@example.com");

        assert_eq!(message.from, "sender@example.com");
        assert_eq!(message.to, "rcpt@example.com");
        assert_eq!(message.raw(), "Hello");
        assert!(message.client_ip.is_none());
        assert!(message.helo_domain.is_none());
    }

    #[test]
    fn test_incoming_message_to_email_message_different_recipient() {
        let incoming = IncomingMessage {
            from: "sender@example.com".to_string(),
            rcpts: HashSet::from([
                "alice@example.com".to_string(),
                "bob@example.com".to_string(),
            ]),
            raw: "Subject: Multi\r\n\r\nBody".to_string(),
            client_ip: Some("10.0.0.1".parse().unwrap()),
            helo_domain: Some("smtp.example.com".to_string()),
        };

        let msg_alice = incoming.to_email_message("alice@example.com");
        let msg_bob = incoming.to_email_message("bob@example.com");

        assert_eq!(msg_alice.to, "alice@example.com");
        assert_eq!(msg_bob.to, "bob@example.com");
        assert_eq!(msg_alice.from, msg_bob.from);
        assert_eq!(msg_alice.raw(), msg_bob.raw());
        assert_ne!(msg_alice.message_id, msg_bob.message_id);
    }

    #[test]
    fn test_incoming_message_to_email_message_parses_subject() {
        let incoming = IncomingMessage {
            from: "sender@example.com".to_string(),
            rcpts: HashSet::from(["rcpt@example.com".to_string()]),
            raw: "Subject: Important Update\r\n\r\nBody content".to_string(),
            client_ip: None,
            helo_domain: None,
        };

        let message = incoming.to_email_message("rcpt@example.com");

        assert_eq!(message.subject(), "Important Update");
    }

    #[test]
    fn test_incoming_message_to_email_message_generates_unique_ids() {
        let incoming = IncomingMessage {
            from: "sender@example.com".to_string(),
            rcpts: HashSet::from(["rcpt@example.com".to_string()]),
            raw: "Body".to_string(),
            client_ip: None,
            helo_domain: None,
        };

        let msg1 = incoming.to_email_message("rcpt@example.com");
        let msg2 = incoming.to_email_message("rcpt@example.com");

        assert_ne!(msg1.message_id, msg2.message_id);
    }
}
