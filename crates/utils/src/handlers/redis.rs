use serde::Serialize;

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
    body: &'a str,
}

impl<'a> From<&'a EmailMessage> for RedisEmailMessage<'a> {
    fn from(msg: &'a EmailMessage) -> Self {
        Self {
            message_id: &msg.message_id,
            from: &msg.from,
            to: &msg.to,
            subject: &msg.subject,
            body: &msg.body,
        }
    }
}

/// Message handler that pushes emails as JSON to a Redis list.
pub struct RedisQueueHandler {
    client: redis::Client,
    queue: String,
}

impl RedisQueueHandler {
    /// Creates a new `RedisQueueHandler` with the given Redis URL and queue name.
    pub fn new(url: &str, queue: String) -> Result<Self, HandlerError> {
        let client = redis::Client::open(url)
            .map_err(|e| HandlerError::Connection(format!("Failed to create Redis client: {e}")))?;
        Ok(Self { client, queue })
    }
}

impl MessageHandler for RedisQueueHandler {
    fn handle<'a>(&'a self, message: &'a EmailMessage) -> HandlerFuture<'a> {
        Box::pin(async move {
            let redis_msg = RedisEmailMessage::from(message);
            let json = serde_json::to_string(&redis_msg)
                .map_err(|e| HandlerError::Serialization(e.to_string()))?;

            let mut conn = self
                .client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| {
                    HandlerError::Connection(format!("Failed to connect to Redis: {e}"))
                })?;

            redis::cmd("LPUSH")
                .arg(&self.queue)
                .arg(&json)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| HandlerError::Storage(format!("Failed to push to Redis: {e}")))?;

            Ok(())
        })
    }

    fn name(&self) -> &str {
        "redis"
    }
}
