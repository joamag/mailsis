use tracing::{debug, info};

use crate::{parse_mime_headers, EmailMessage};

/// Trait for message transformers that modify emails in the pipeline.
///
/// Transformers run after `EmailMessage` construction and before routing,
/// allowing in-place modification of message fields and body.
pub trait MessageTransformer: Send + Sync {
    /// Transforms an email message in place.
    fn transform(&self, message: &mut EmailMessage);

    /// Returns the name of this transformer.
    fn name(&self) -> &str;
}

/// Applies a list of transformers to a message in order.
pub fn apply_transformers(
    transformers: &[Box<dyn MessageTransformer>],
    message: &mut EmailMessage,
) {
    for transformer in transformers {
        debug!(transformer = transformer.name(), "Applying transformer");
        transformer.transform(message);
    }
}

/// Transformer that ensures every email has a `Message-ID` MIME header.
///
/// If the body already contains a `Message-ID` header, the struct's
/// `message_id` field is updated to match it. Otherwise, a new header
/// is prepended to the body using the existing `message_id` and the
/// configured domain.
pub struct MessageIdTransformer {
    domain: String,
}

impl MessageIdTransformer {
    /// Creates a new `MessageIdTransformer` with the given domain for generated IDs.
    pub fn new(domain: String) -> Self {
        info!(domain = %domain, "Message-ID transformer initialized");
        Self { domain }
    }

    /// Finds an existing Message-ID header value (case-insensitive lookup).
    fn find_message_id(body: &str) -> Option<String> {
        let headers = parse_mime_headers(body).ok()?;
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("message-id"))
            .map(|(_, v)| {
                v.trim()
                    .strip_prefix('<')
                    .and_then(|s| s.strip_suffix('>'))
                    .unwrap_or(v.trim())
                    .to_string()
            })
    }
}

impl MessageTransformer for MessageIdTransformer {
    fn transform(&self, message: &mut EmailMessage) {
        if let Some(existing_id) = Self::find_message_id(&message.body) {
            debug!(
                old_id = %message.message_id,
                mime_id = %existing_id,
                "Syncing message_id from existing MIME header"
            );
            message.message_id = existing_id;
        } else {
            let header = format!("Message-ID: <{}@{}>\r\n", message.message_id, self.domain);
            debug!(
                message_id = %message.message_id,
                "Injecting Message-ID header"
            );
            message.body = format!("{header}{}", message.body);
        }
    }

    fn name(&self) -> &str {
        "message_id"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_message_id_when_missing() {
        let transformer = MessageIdTransformer::new("example.com".to_string());
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Hello\r\n\r\nBody text",
        );
        let original_id = message.message_id.clone();

        transformer.transform(&mut message);

        assert!(message
            .body
            .starts_with(&format!("Message-ID: <{original_id}@example.com>\r\n")));
        assert_eq!(message.message_id, original_id);
    }

    #[test]
    fn test_sync_message_id_from_existing_header() {
        let transformer = MessageIdTransformer::new("example.com".to_string());
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Message-ID: <abc123@mail.example.com>\r\nSubject: Hello\r\n\r\nBody text",
        );

        transformer.transform(&mut message);

        assert_eq!(message.message_id, "abc123@mail.example.com");
        // Body unchanged
        assert!(message.body.starts_with("Message-ID:"));
    }

    #[test]
    fn test_sync_message_id_case_insensitive() {
        let transformer = MessageIdTransformer::new("example.com".to_string());
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "message-id: <lowercase@example.com>\r\nSubject: Test\r\n\r\nBody",
        );

        transformer.transform(&mut message);

        assert_eq!(message.message_id, "lowercase@example.com");
    }

    #[test]
    fn test_inject_into_plain_text_body() {
        let transformer = MessageIdTransformer::new("localhost".to_string());
        let mut message =
            EmailMessage::from_raw("sender@example.com", "rcpt@example.com", "Just plain text");
        let original_id = message.message_id.clone();

        transformer.transform(&mut message);

        assert!(message
            .body
            .starts_with(&format!("Message-ID: <{original_id}@localhost>\r\n")));
        assert!(message.body.ends_with("Just plain text"));
    }

    #[test]
    fn test_apply_transformers() {
        let transformers: Vec<Box<dyn MessageTransformer>> = vec![Box::new(
            MessageIdTransformer::new("example.com".to_string()),
        )];
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Test\r\n\r\nBody",
        );

        apply_transformers(&transformers, &mut message);

        assert!(message.body.contains("Message-ID:"));
    }

    #[test]
    fn test_message_id_without_angle_brackets() {
        let transformer = MessageIdTransformer::new("example.com".to_string());
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Message-ID: bare-id@example.com\r\nSubject: Test\r\n\r\nBody",
        );

        transformer.transform(&mut message);

        assert_eq!(message.message_id, "bare-id@example.com");
    }
}
