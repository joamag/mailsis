//! Filesystem-backed message handler.
//!
//! Provides [`FileStorageHandler`], a [`MessageHandler`](crate::MessageHandler)
//! implementation that delegates to a [`FileStorageEngine`](crate::FileStorageEngine)
//! for storing emails as `.eml` files on disk.

use std::{path::PathBuf, sync::Arc};

use tracing::{debug, error, info};

use crate::{
    handler::{HandlerError, HandlerFuture, MessageHandler},
    EmailMessage, FileStorageEngine, StorageEngine,
};

/// Message handler that stores emails using a [`FileStorageEngine`].
pub struct FileStorageHandler {
    engine: Arc<FileStorageEngine>,
}

impl FileStorageHandler {
    /// Creates a new [`FileStorageHandler`] with the given base path and metadata flag.
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
    fn test_file_storage_handler_name() {
        let temp_dir = TempDir::new().unwrap();
        let handler = FileStorageHandler::new(temp_dir.path().to_path_buf(), false);
        assert_eq!(handler.name(), "file_storage");
    }

    #[test]
    fn test_file_storage_handler_engine_accessor() {
        let temp_dir = TempDir::new().unwrap();
        let handler = FileStorageHandler::new(temp_dir.path().to_path_buf(), false);
        let _engine = handler.engine();
    }

    #[tokio::test]
    async fn test_file_storage_handler_multiple_messages() {
        let temp_dir = TempDir::new().unwrap();
        let handler = FileStorageHandler::new(temp_dir.path().to_path_buf(), false);

        let msg1 = EmailMessage::from_raw("sender@example.com", "rcpt@example.com", "Message 1");
        let msg2 = EmailMessage::from_raw("sender@example.com", "rcpt@example.com", "Message 2");

        handler.handle(&msg1).await.unwrap();
        handler.handle(&msg2).await.unwrap();

        let messages = handler.engine.list("rcpt@example.com").await.unwrap();
        assert_eq!(messages.len(), 2);
    }

    #[tokio::test]
    async fn test_file_storage_handler_with_mime_message() {
        let temp_dir = TempDir::new().unwrap();
        let handler = FileStorageHandler::new(temp_dir.path().to_path_buf(), false);

        let message = EmailMessage::from_raw(
            "sender@example.com",
            "rcpt@example.com",
            "Subject: Test\r\nFrom: sender@example.com\r\n\r\nBody content",
        );

        handler.handle(&message).await.unwrap();

        let content = handler
            .engine
            .retrieve("rcpt@example.com", &message.message_id)
            .await
            .unwrap();
        assert!(content.contains("Subject: Test"));
        assert!(content.contains("Body content"));
    }
}
