//! Redis-backed message handler for email queue processing.
//!
//! Provides [`RedisQueueHandler`], a [`MessageHandler`](crate::MessageHandler)
//! implementation that serializes incoming emails as JSON and pushes them
//! onto a Redis list via `LPUSH`. This is feature-gated behind `redis`.

use serde::Serialize;
use tracing::{debug, error, info};

use crate::{
    handler::{HandlerError, HandlerFuture, MessageHandler},
    EmailMessage,
};

/// JSON-serializable representation of an email message for Redis.
#[derive(Debug, Serialize)]
struct RedisEmailMessage<'a> {
    message_id: &'a str,
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    raw: &'a str,
}

impl<'a> From<&'a EmailMessage> for RedisEmailMessage<'a> {
    fn from(msg: &'a EmailMessage) -> Self {
        Self {
            message_id: &msg.message_id,
            from: &msg.from,
            to: &msg.to,
            subject: msg.subject(),
            raw: msg.raw(),
        }
    }
}

/// Message handler that pushes emails as JSON to a Redis list.
pub struct RedisQueueHandler {
    client: redis::Client,
    queue: String,
}

impl RedisQueueHandler {
    /// Creates a new [`RedisQueueHandler`] with the given Redis URL and queue name.
    pub fn new(url: &str, queue: String) -> Result<Self, HandlerError> {
        let client = redis::Client::open(url).map_err(|e| {
            error!(url = %url, error = %e, "Failed to create Redis client");
            HandlerError::Connection(format!("Failed to create Redis client: {e}"))
        })?;
        info!(url = %url, queue = %queue, "Redis handler initialized");
        Ok(Self { client, queue })
    }
}

impl MessageHandler for RedisQueueHandler {
    fn handle<'a>(&'a self, message: &'a EmailMessage) -> HandlerFuture<'a> {
        Box::pin(async move {
            let redis_msg = RedisEmailMessage::from(message);
            let json = serde_json::to_string(&redis_msg).map_err(|e| {
                error!(
                    message_id = %message.message_id,
                    error = %e,
                    "Failed to serialize email to JSON"
                );
                HandlerError::Serialization(e.to_string())
            })?;

            debug!(
                message_id = %message.message_id,
                queue = %self.queue,
                size = json.len(),
                "Connecting to Redis"
            );

            let mut conn = self
                .client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to connect to Redis");
                    HandlerError::Connection(format!("Failed to connect to Redis: {e}"))
                })?;

            redis::cmd("LPUSH")
                .arg(&self.queue)
                .arg(&json)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| {
                    error!(
                        queue = %self.queue,
                        message_id = %message.message_id,
                        error = %e,
                        "Failed to LPUSH to Redis"
                    );
                    HandlerError::Storage(format!("Failed to push to Redis: {e}"))
                })?;

            info!(
                message_id = %message.message_id,
                queue = %self.queue,
                from = %message.from,
                to = %message.to,
                size = json.len(),
                "Pushed email to Redis"
            );

            Ok(())
        })
    }

    fn name(&self) -> &str {
        "redis"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_email_message_from_email() {
        let message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Hello\r\n\r\nBody content",
        );

        let redis_msg = RedisEmailMessage::from(&message);

        assert_eq!(redis_msg.message_id, message.message_id);
        assert_eq!(redis_msg.from, "sender@example.com");
        assert_eq!(redis_msg.to, "rcpt@example.com");
        assert_eq!(redis_msg.subject, "Hello");
        assert_eq!(redis_msg.raw, "Subject: Hello\r\n\r\nBody content");
    }

    #[test]
    fn test_redis_email_message_without_subject() {
        let message =
            EmailMessage::from_raw("sender@example.com", "rcpt@example.com", "Plain text only");

        let redis_msg = RedisEmailMessage::from(&message);

        assert_eq!(redis_msg.subject, "");
        assert_eq!(redis_msg.raw, "Plain text only");
    }

    #[test]
    fn test_redis_email_message_serializes_to_json() {
        let message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Test\r\n\r\nBody",
        );

        let redis_msg = RedisEmailMessage::from(&message);
        let json = serde_json::to_string(&redis_msg).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["from"], "sender@example.com");
        assert_eq!(parsed["to"], "rcpt@example.com");
        assert_eq!(parsed["subject"], "Test");
        assert_eq!(parsed["raw"], "Subject: Test\r\n\r\nBody");
        assert_eq!(parsed["message_id"], message.message_id);
    }

    #[test]
    fn test_redis_email_message_json_contains_all_fields() {
        let message = EmailMessage::from_raw("from@test.com", "to@test.com", "Subject: S\r\n\r\nB");

        let redis_msg = RedisEmailMessage::from(&message);
        let json = serde_json::to_string(&redis_msg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("message_id").is_some());
        assert!(parsed.get("from").is_some());
        assert!(parsed.get("to").is_some());
        assert!(parsed.get("subject").is_some());
        assert!(parsed.get("raw").is_some());
    }

    #[test]
    fn test_handler_name() {
        let handler =
            RedisQueueHandler::new("redis://localhost:6379", "queue".to_string()).unwrap();
        assert_eq!(handler.name(), "redis");
    }

    #[test]
    fn test_new_with_valid_url() {
        let result = RedisQueueHandler::new("redis://localhost:6379", "emails".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_with_invalid_url() {
        let result = RedisQueueHandler::new("://invalid", "emails".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_new_preserves_queue_name() {
        let handler =
            RedisQueueHandler::new("redis://localhost:6379", "custom_queue".to_string()).unwrap();
        assert_eq!(handler.queue, "custom_queue");
    }

    #[tokio::test]
    async fn test_handle_connection_failure() {
        // Use a port that should not have Redis running
        let handler =
            RedisQueueHandler::new("redis://localhost:59999", "test_queue".to_string()).unwrap();
        let message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Test\r\n\r\nBody",
        );

        let result = handler.handle(&message).await;
        assert!(result.is_err());
    }
}
