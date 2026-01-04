use std::fmt::Display;
use std::io;
use std::path::PathBuf;

use chrono::Utc;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{parse_mime_headers, EmailMetadata};

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Errors that can occur during storage operations.
#[derive(Debug)]
pub enum StorageError {
    /// The message was not found.
    NotFound,
    /// An I/O error occurred.
    Io(io::Error),
    /// A storage engine error occurred.
    EngineError(String),
}

impl Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::NotFound => write!(f, "Message not found"),
            StorageError::Io(e) => write!(f, "I/O error: {e}"),
            StorageError::EngineError(msg) => write!(f, "Storage error: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            StorageError::NotFound
        } else {
            StorageError::Io(e)
        }
    }
}

/// Represents an email message for storage operations.
#[derive(Debug, Clone)]
pub struct EmailMessage {
    /// Unique message identifier.
    pub message_id: String,
    /// Sender address.
    pub from: String,
    /// Recipient address.
    pub to: String,
    /// Email subject.
    pub subject: String,
    /// Raw email body/content.
    pub body: String,
}

impl EmailMessage {
    pub fn new(from: String, to: String, body: String) -> Self {
        let message_id = Uuid::new_v4().to_string();
        let subject = parse_mime_headers(&body)
            .ok()
            .and_then(|h| h.get("Subject").cloned())
            .unwrap_or_default();
        Self {
            message_id,
            from,
            to,
            subject,
            body,
        }
    }

    pub fn with_id(message_id: String, from: String, to: String, subject: String, body: String) -> Self {
        Self {
            message_id,
            from,
            to,
            subject,
            body,
        }
    }
}

/// Trait for storage engines.
///
/// Implementations of this trait provide different storage backends,
/// such as filesystem, database, S3, etc.
pub trait StorageEngine: Send + Sync {
    /// Stores an email message for a recipient.
    ///
    /// Returns the message ID on success.
    fn store(
        &self,
        message: &EmailMessage,
    ) -> impl std::future::Future<Output = StorageResult<String>> + Send;

    /// Retrieves an email message by ID for a user.
    fn retrieve(
        &self,
        user: &str,
        message_id: &str,
    ) -> impl std::future::Future<Output = StorageResult<String>> + Send;

    /// Lists all message IDs for a user.
    fn list(
        &self,
        user: &str,
    ) -> impl std::future::Future<Output = StorageResult<Vec<String>>> + Send;

    /// Deletes a message by ID for a user.
    fn delete(
        &self,
        user: &str,
        message_id: &str,
    ) -> impl std::future::Future<Output = StorageResult<()>> + Send;

    /// Creates a mailbox for a user.
    fn create_mailbox(
        &self,
        user: &str,
        mailbox: &str,
    ) -> impl std::future::Future<Output = StorageResult<()>> + Send;
}

/// Filesystem-based storage engine.
///
/// Stores emails as .eml files in a directory structure:
/// `{base_path}/{user}/{message_id}.eml`
#[derive(Debug, Clone)]
pub struct FileStorageEngine {
    base_path: PathBuf,
    db_path: PathBuf,
    store_metadata: bool,
}

impl FileStorageEngine {
    /// Creates a new FileStorageEngine with the given base path.
    pub fn new(base_path: PathBuf) -> Self {
        let db_path = base_path.join("metadata.db");
        Self {
            base_path,
            db_path,
            store_metadata: true,
        }
    }

    /// Creates a FileStorageEngine without metadata storage.
    pub fn without_metadata(base_path: PathBuf) -> Self {
        Self {
            base_path,
            db_path: PathBuf::new(),
            store_metadata: false,
        }
    }

    /// Returns the path to a user's mailbox directory.
    fn user_path(&self, user: &str) -> PathBuf {
        let safe_user = user.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
        self.base_path.join(safe_user)
    }

    /// Returns the path to a specific message file.
    fn message_path(&self, user: &str, message_id: &str) -> PathBuf {
        self.user_path(user).join(format!("{message_id}.eml"))
    }

    /// Checks if the email body has valid MIME headers.
    async fn is_mime_valid(body: &str) -> bool {
        let start = body.chars().take(1024).collect::<String>();
        let headers = ["From:", "To:", "Subject:", "Date:", "MIME-Version:"];
        headers.iter().any(|h| start.contains(h))
    }
}

impl StorageEngine for FileStorageEngine {
    async fn store(&self, message: &EmailMessage) -> StorageResult<String> {
        let user_dir = self.user_path(&message.to);
        fs::create_dir_all(&user_dir).await?;

        let file_path = self.message_path(&message.to, &message.message_id);
        let mut file = File::create(&file_path).await?;

        // Add minimal headers if not a valid MIME message
        if !Self::is_mime_valid(&message.body).await {
            file.write_all(format!("From: {}\r\n", message.from).as_bytes())
                .await?;
            file.write_all(format!("To: {}\r\n", message.to).as_bytes())
                .await?;
            file.write_all(format!("Date: {}\r\n\r\n", Utc::now().to_rfc2822()).as_bytes())
                .await?;
        }
        file.write_all(message.body.as_bytes()).await?;

        // Store metadata if enabled
        if self.store_metadata {
            let metadata = EmailMetadata::new(
                message.message_id.clone(),
                message.from.clone(),
                message.to.clone(),
                message.subject.clone(),
                file_path,
            );
            metadata
                .store_sqlite(&self.db_path)
                .await
                .map_err(|e| StorageError::EngineError(e.to_string()))?;
        }

        Ok(message.message_id.clone())
    }

    async fn retrieve(&self, user: &str, message_id: &str) -> StorageResult<String> {
        let path = self.message_path(user, message_id);
        let content = fs::read_to_string(path).await?;
        Ok(content)
    }

    async fn list(&self, user: &str) -> StorageResult<Vec<String>> {
        let user_dir = self.user_path(user);

        // Return empty list if directory doesn't exist
        if !user_dir.exists() {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        let mut entries = fs::read_dir(&user_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "eml" {
                    if let Some(stem) = path.file_stem() {
                        messages.push(stem.to_string_lossy().to_string());
                    }
                }
            }
        }

        Ok(messages)
    }

    async fn delete(&self, user: &str, message_id: &str) -> StorageResult<()> {
        let path = self.message_path(user, message_id);
        fs::remove_file(path).await?;
        Ok(())
    }

    async fn create_mailbox(&self, user: &str, mailbox: &str) -> StorageResult<()> {
        let path = self.user_path(user).join(format!("{mailbox}.mbox"));
        fs::create_dir_all(path).await?;
        Ok(())
    }
}

impl Default for FileStorageEngine {
    fn default() -> Self {
        Self::new(PathBuf::from("mailbox"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_storage_store_and_retrieve() {
        let temp_dir = TempDir::new().unwrap();
        let engine = FileStorageEngine::without_metadata(temp_dir.path().to_path_buf());

        let message = EmailMessage::new(
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Hello, World!".to_string(),
        );

        let message_id = engine.store(&message).await.unwrap();
        let content = engine.retrieve("recipient@example.com", &message_id).await.unwrap();

        assert!(content.contains("Hello, World!"));
        assert!(content.contains("From: sender@example.com"));
    }

    #[tokio::test]
    async fn test_file_storage_list() {
        let temp_dir = TempDir::new().unwrap();
        let engine = FileStorageEngine::without_metadata(temp_dir.path().to_path_buf());

        let msg1 = EmailMessage::new(
            "sender@example.com".to_string(),
            "user@example.com".to_string(),
            "Message 1".to_string(),
        );
        let msg2 = EmailMessage::new(
            "sender@example.com".to_string(),
            "user@example.com".to_string(),
            "Message 2".to_string(),
        );

        let id1 = engine.store(&msg1).await.unwrap();
        let id2 = engine.store(&msg2).await.unwrap();

        let messages = engine.list("user@example.com").await.unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages.contains(&id1));
        assert!(messages.contains(&id2));
    }

    #[tokio::test]
    async fn test_file_storage_delete() {
        let temp_dir = TempDir::new().unwrap();
        let engine = FileStorageEngine::without_metadata(temp_dir.path().to_path_buf());

        let message = EmailMessage::new(
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Test message".to_string(),
        );

        let message_id = engine.store(&message).await.unwrap();
        assert!(engine.retrieve("recipient@example.com", &message_id).await.is_ok());

        engine.delete("recipient@example.com", &message_id).await.unwrap();
        assert!(matches!(
            engine.retrieve("recipient@example.com", &message_id).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_file_storage_list_empty() {
        let temp_dir = TempDir::new().unwrap();
        let engine = FileStorageEngine::without_metadata(temp_dir.path().to_path_buf());

        let messages = engine.list("nonexistent@example.com").await.unwrap();
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn test_file_storage_create_mailbox() {
        let temp_dir = TempDir::new().unwrap();
        let engine = FileStorageEngine::without_metadata(temp_dir.path().to_path_buf());

        engine.create_mailbox("user@example.com", "Drafts").await.unwrap();

        let mailbox_path = temp_dir.path().join("user_example_com").join("Drafts.mbox");
        assert!(mailbox_path.exists());
    }

    #[tokio::test]
    async fn test_storage_error_display() {
        assert_eq!(StorageError::NotFound.to_string(), "Message not found");
        assert_eq!(
            StorageError::EngineError("test".to_string()).to_string(),
            "Storage error: test"
        );
    }
}
