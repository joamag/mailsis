use std::{error::Error, fmt::Display, future::Future, path::PathBuf, pin::Pin, sync::Arc};

use tracing::{debug, error, info};

use crate::{EmailMessage, FileStorageEngine, StorageEngine};

/// Result type for handler operations.
pub type HandlerResult<T> = Result<T, HandlerError>;

/// Boxed future type for handler operations, enabling object safety.
pub type HandlerFuture<'a> = Pin<Box<dyn Future<Output = HandlerResult<()>> + Send + 'a>>;

/// Errors that can occur during message handling.
#[derive(Debug)]
pub enum HandlerError {
    /// A storage error occurred.
    Storage(String),
    /// A connection error occurred.
    Connection(String),
    /// A serialization error occurred.
    Serialization(String),
}

impl Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerError::Storage(msg) => write!(f, "Storage error: {msg}"),
            HandlerError::Connection(msg) => write!(f, "Connection error: {msg}"),
            HandlerError::Serialization(msg) => write!(f, "Serialization error: {msg}"),
        }
    }
}

impl Error for HandlerError {}

/// Trait for message handlers that process incoming emails.
///
/// Unlike `StorageEngine`, this trait only handles the inbound direction
/// (receiving/storing), making it suitable for both storage backends
/// and queue-based destinations like Redis.
pub trait MessageHandler: Send + Sync {
    /// Handles an incoming email message.
    fn handle<'a>(&'a self, message: &'a EmailMessage) -> HandlerFuture<'a>;

    /// Returns the name of this handler.
    fn name(&self) -> &str;
}

/// Message handler that stores emails using a `FileStorageEngine`.
pub struct FileStorageHandler {
    engine: Arc<FileStorageEngine>,
}

impl FileStorageHandler {
    /// Creates a new `FileStorageHandler` with the given base path and metadata flag.
    pub fn new(base_path: PathBuf, metadata: bool) -> Self {
        info!(
            path = %base_path.display(),
            metadata = metadata,
            "File storage handler initialized"
        );
        let engine = if metadata {
            FileStorageEngine::new(base_path)
        } else {
            FileStorageEngine::without_metadata(base_path)
        };
        Self {
            engine: Arc::new(engine),
        }
    }

    /// Returns a reference to the underlying storage engine.
    pub fn engine(&self) -> &Arc<FileStorageEngine> {
        &self.engine
    }
}

impl MessageHandler for FileStorageHandler {
    fn handle<'a>(&'a self, message: &'a EmailMessage) -> HandlerFuture<'a> {
        Box::pin(async move {
            debug!(
                message_id = %message.message_id,
                to = %message.to,
                "Storing email to filesystem"
            );
            self.engine.store(message).await.map_err(|e| {
                error!(
                    message_id = %message.message_id,
                    error = %e,
                    "Failed to store email to filesystem"
                );
                HandlerError::Storage(e.to_string())
            })?;
            info!(
                message_id = %message.message_id,
                from = %message.from,
                to = %message.to,
                "Stored email to filesystem"
            );
            Ok(())
        })
    }

    fn name(&self) -> &str {
        "file_storage"
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_file_storage_handler() {
        let temp_dir = TempDir::new().unwrap();
        let handler = FileStorageHandler::new(temp_dir.path().to_path_buf(), false);

        let message = EmailMessage::from_raw("sender@example.com", "rcpt@example.com", "Hello");
        let result = handler.handle(&message).await;
        assert!(result.is_ok());

        // Verify the file was stored
        let messages = handler.engine.list("rcpt@example.com").await.unwrap();
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn test_handler_error_display() {
        assert_eq!(
            HandlerError::Storage("test".to_string()).to_string(),
            "Storage error: test"
        );
        assert_eq!(
            HandlerError::Connection("test".to_string()).to_string(),
            "Connection error: test"
        );
        assert_eq!(
            HandlerError::Serialization("test".to_string()).to_string(),
            "Serialization error: test"
        );
    }
}
