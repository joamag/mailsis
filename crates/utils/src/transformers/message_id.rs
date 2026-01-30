use tracing::{debug, info};

use crate::{EmailMessage, MessageTransformer, TransformFuture};

/// Transformer that ensures every email has a `Message-ID` MIME header.
///
/// If the body already contains a `Message-ID` header, the struct's
/// [`EmailMessage::message_id`] field is updated to match it. Otherwise, a new header
/// is prepended using the existing [`EmailMessage::message_id`] and the configured domain.
pub struct MessageIdTransformer {
    domain: String,
}

impl MessageIdTransformer {
    /// Creates a new [`MessageIdTransformer`] with the given domain for generated IDs.
    pub fn new(domain: String) -> Self {
        info!(domain = %domain, "Message-ID transformer initialized");
        Self { domain }
    }
}

impl MessageTransformer for MessageIdTransformer {
    fn transform<'a>(&'a self, message: &'a mut EmailMessage) -> TransformFuture<'a> {
        Box::pin(async move {
            if let Some(existing_id) = message.header("Message-ID") {
                let cleaned = existing_id
                    .strip_prefix('<')
                    .and_then(|s| s.strip_suffix('>'))
                    .unwrap_or(existing_id)
                    .to_string();
                debug!(
                    old_id = %message.message_id,
                    mime_id = %cleaned,
                    "Syncing message_id from existing MIME header"
                );
                message.message_id = cleaned;
            } else {
                let value = format!("<{}@{}>", message.message_id, self.domain);
                debug!(
                    message_id = %message.message_id,
                    "Injecting Message-ID header"
                );
                message.prepend_header("Message-ID", &value);
            }
        })
    }

    fn name(&self) -> &str {
        "message_id"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_inject_message_id_when_missing() {
        let transformer = MessageIdTransformer::new("example.com".to_string());
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Hello\r\n\r\nBody text",
        );
        let original_id = message.message_id.clone();

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message
            .raw()
            .starts_with(&format!("Message-ID: <{original_id}@example.com>\r\n")));
        assert_eq!(message.message_id, original_id);
    }

    #[tokio::test]
    async fn test_sync_message_id_from_existing_header() {
        let transformer = MessageIdTransformer::new("example.com".to_string());
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Message-ID: <abc123@mail.example.com>\r\nSubject: Hello\r\n\r\nBody text",
        );

        transformer.transform(&mut message).await;

        assert_eq!(message.message_id, "abc123@mail.example.com");
        // Body unchanged (no prepend_header called, no rebuild needed)
        assert!(message.raw().starts_with("Message-ID:"));
    }

    #[tokio::test]
    async fn test_sync_message_id_case_insensitive() {
        let transformer = MessageIdTransformer::new("example.com".to_string());
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "message-id: <lowercase@example.com>\r\nSubject: Test\r\n\r\nBody",
        );

        transformer.transform(&mut message).await;

        assert_eq!(message.message_id, "lowercase@example.com");
    }

    #[tokio::test]
    async fn test_inject_into_plain_text_body() {
        let transformer = MessageIdTransformer::new("localhost".to_string());
        let mut message =
            EmailMessage::from_raw("sender@example.com", "rcpt@example.com", "Just plain text");
        let original_id = message.message_id.clone();

        transformer.transform(&mut message).await;
        message.rebuild();

        assert!(message
            .raw()
            .starts_with(&format!("Message-ID: <{original_id}@localhost>\r\n")));
        assert!(message.raw().ends_with("Just plain text"));
    }

    #[tokio::test]
    async fn test_apply_transformers() {
        let transformers: Vec<Box<dyn MessageTransformer>> = vec![Box::new(
            MessageIdTransformer::new("example.com".to_string()),
        )];
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Test\r\n\r\nBody",
        );

        <MessageIdTransformer as MessageTransformer>::apply(&transformers, &mut message).await;

        assert!(message.raw().contains("Message-ID:"));
    }

    #[tokio::test]
    async fn test_message_id_without_angle_brackets() {
        let transformer = MessageIdTransformer::new("example.com".to_string());
        let mut message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Message-ID: bare-id@example.com\r\nSubject: Test\r\n\r\nBody",
        );

        transformer.transform(&mut message).await;

        assert_eq!(message.message_id, "bare-id@example.com");
    }
}
