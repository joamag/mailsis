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
