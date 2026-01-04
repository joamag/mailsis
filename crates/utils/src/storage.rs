use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::path::PathBuf;
use std::sync::RwLock;

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
    /// Unique message identifier, RFC 5322 message-id format.
    pub message_id: String,

    /// Sender address, RFC 5322 address format.
    pub from: String,

    /// Recipient address, RFC 5322 address format.
    pub to: String,

    /// Email subject, ASCII encoded.
    pub subject: String,

    /// Raw email body/content, ASCII encoded.
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

    pub fn with_id(
        message_id: String,
        from: String,
        to: String,
        subject: String,
        body: String,
    ) -> Self {
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
    /// Base path for storing email messages.
    base_path: PathBuf,

    /// Path to the metadata database.
    db_path: PathBuf,

    /// Whether to store metadata in the database.
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

/// In-memory storage engine.
///
/// Stores emails in memory using a HashMap structure.
/// Useful for testing and development.
///
/// Structure: `HashMap<user, HashMap<message_id, EmailMessage>>`
#[derive(Debug, Default)]
pub struct MemoryStorageEngine {
    /// Storage for messages: user -> (message_id -> message)
    messages: RwLock<HashMap<String, HashMap<String, EmailMessage>>>,

    /// Storage for mailboxes: user -> list of mailbox names
    mailboxes: RwLock<HashMap<String, Vec<String>>>,
}

impl MemoryStorageEngine {
    /// Creates a new empty MemoryStorageEngine.
    pub fn new() -> Self {
        Self {
            messages: RwLock::new(HashMap::new()),
            mailboxes: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the number of messages stored for a user.
    pub fn message_count(&self, user: &str) -> usize {
        let safe_user = Self::safe_user(user);
        self.messages
            .read()
            .unwrap()
            .get(&safe_user)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Returns the total number of messages stored across all users.
    pub fn total_message_count(&self) -> usize {
        self.messages
            .read()
            .unwrap()
            .values()
            .map(|m| m.len())
            .sum()
    }

    /// Clears all messages and mailboxes.
    pub fn clear(&self) {
        self.messages.write().unwrap().clear();
        self.mailboxes.write().unwrap().clear();
    }

    /// Normalizes a user identifier to a safe key.
    fn safe_user(user: &str) -> String {
        user.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    }
}

impl StorageEngine for MemoryStorageEngine {
    async fn store(&self, message: &EmailMessage) -> StorageResult<String> {
        let safe_user = Self::safe_user(&message.to);
        let mut messages = self.messages.write().unwrap();
        let user_messages = messages.entry(safe_user).or_default();
        user_messages.insert(message.message_id.clone(), message.clone());
        Ok(message.message_id.clone())
    }

    async fn retrieve(&self, user: &str, message_id: &str) -> StorageResult<String> {
        let safe_user = Self::safe_user(user);
        let messages = self.messages.read().unwrap();
        let user_messages = messages.get(&safe_user).ok_or(StorageError::NotFound)?;
        let message = user_messages
            .get(message_id)
            .ok_or(StorageError::NotFound)?;
        Ok(message.body.clone())
    }

    async fn list(&self, user: &str) -> StorageResult<Vec<String>> {
        let safe_user = Self::safe_user(user);
        let messages = self.messages.read().unwrap();
        match messages.get(&safe_user) {
            Some(user_messages) => Ok(user_messages.keys().cloned().collect()),
            None => Ok(Vec::new()),
        }
    }

    async fn delete(&self, user: &str, message_id: &str) -> StorageResult<()> {
        let safe_user = Self::safe_user(user);
        let mut messages = self.messages.write().unwrap();
        let user_messages = messages.get_mut(&safe_user).ok_or(StorageError::NotFound)?;
        user_messages
            .remove(message_id)
            .ok_or(StorageError::NotFound)?;
        Ok(())
    }

    async fn create_mailbox(&self, user: &str, mailbox: &str) -> StorageResult<()> {
        let safe_user = Self::safe_user(user);
        let mut mailboxes = self.mailboxes.write().unwrap();
        let user_mailboxes = mailboxes.entry(safe_user).or_default();
        if !user_mailboxes.contains(&mailbox.to_string()) {
            user_mailboxes.push(mailbox.to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{
        EmailMessage, FileStorageEngine, MemoryStorageEngine, StorageEngine, StorageError,
    };

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
        let content = engine
            .retrieve("recipient@example.com", &message_id)
            .await
            .unwrap();

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
        assert!(engine
            .retrieve("recipient@example.com", &message_id)
            .await
            .is_ok());

        engine
            .delete("recipient@example.com", &message_id)
            .await
            .unwrap();
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

        engine
            .create_mailbox("user@example.com", "Drafts")
            .await
            .unwrap();

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

    // MemoryStorageEngine tests

    #[tokio::test]
    async fn test_memory_storage_new() {
        let engine = MemoryStorageEngine::new();
        assert_eq!(engine.total_message_count(), 0);
    }

    #[tokio::test]
    async fn test_memory_storage_store_and_retrieve() {
        let engine = MemoryStorageEngine::new();

        let message = EmailMessage::new(
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Hello, World!".to_string(),
        );

        let message_id = engine.store(&message).await.unwrap();
        let content = engine
            .retrieve("recipient@example.com", &message_id)
            .await
            .unwrap();

        assert_eq!(content, "Hello, World!");
        assert_eq!(engine.message_count("recipient@example.com"), 1);
    }

    #[tokio::test]
    async fn test_memory_storage_store_multiple_users() {
        let engine = MemoryStorageEngine::new();

        let msg1 = EmailMessage::new(
            "sender@example.com".to_string(),
            "user1@example.com".to_string(),
            "Message for user1".to_string(),
        );
        let msg2 = EmailMessage::new(
            "sender@example.com".to_string(),
            "user2@example.com".to_string(),
            "Message for user2".to_string(),
        );

        engine.store(&msg1).await.unwrap();
        engine.store(&msg2).await.unwrap();

        assert_eq!(engine.message_count("user1@example.com"), 1);
        assert_eq!(engine.message_count("user2@example.com"), 1);
        assert_eq!(engine.total_message_count(), 2);
    }

    #[tokio::test]
    async fn test_memory_storage_list() {
        let engine = MemoryStorageEngine::new();

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
    async fn test_memory_storage_list_empty() {
        let engine = MemoryStorageEngine::new();

        let messages = engine.list("nonexistent@example.com").await.unwrap();
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn test_memory_storage_delete() {
        let engine = MemoryStorageEngine::new();

        let message = EmailMessage::new(
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Test message".to_string(),
        );

        let message_id = engine.store(&message).await.unwrap();
        assert_eq!(engine.message_count("recipient@example.com"), 1);

        engine
            .delete("recipient@example.com", &message_id)
            .await
            .unwrap();
        assert_eq!(engine.message_count("recipient@example.com"), 0);

        // Verify retrieve fails after delete
        assert!(matches!(
            engine.retrieve("recipient@example.com", &message_id).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_memory_storage_delete_nonexistent() {
        let engine = MemoryStorageEngine::new();

        // Delete from nonexistent user
        let result = engine.delete("user@example.com", "fake-id").await;
        assert!(matches!(result, Err(StorageError::NotFound)));

        // Store a message, then try to delete wrong ID
        let message = EmailMessage::new(
            "sender@example.com".to_string(),
            "user@example.com".to_string(),
            "Test".to_string(),
        );
        engine.store(&message).await.unwrap();

        let result = engine.delete("user@example.com", "wrong-id").await;
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[tokio::test]
    async fn test_memory_storage_retrieve_nonexistent() {
        let engine = MemoryStorageEngine::new();

        // Retrieve from nonexistent user
        let result = engine.retrieve("user@example.com", "fake-id").await;
        assert!(matches!(result, Err(StorageError::NotFound)));

        // Store a message, then try to retrieve wrong ID
        let message = EmailMessage::new(
            "sender@example.com".to_string(),
            "user@example.com".to_string(),
            "Test".to_string(),
        );
        engine.store(&message).await.unwrap();

        let result = engine.retrieve("user@example.com", "wrong-id").await;
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[tokio::test]
    async fn test_memory_storage_create_mailbox() {
        let engine = MemoryStorageEngine::new();

        engine
            .create_mailbox("user@example.com", "Inbox")
            .await
            .unwrap();
        engine
            .create_mailbox("user@example.com", "Drafts")
            .await
            .unwrap();

        // Creating the same mailbox again should not fail
        engine
            .create_mailbox("user@example.com", "Inbox")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_memory_storage_clear() {
        let engine = MemoryStorageEngine::new();

        let msg1 = EmailMessage::new(
            "sender@example.com".to_string(),
            "user1@example.com".to_string(),
            "Message 1".to_string(),
        );
        let msg2 = EmailMessage::new(
            "sender@example.com".to_string(),
            "user2@example.com".to_string(),
            "Message 2".to_string(),
        );

        engine.store(&msg1).await.unwrap();
        engine.store(&msg2).await.unwrap();
        assert_eq!(engine.total_message_count(), 2);

        engine.clear();
        assert_eq!(engine.total_message_count(), 0);
    }

    #[tokio::test]
    async fn test_memory_storage_with_id() {
        let engine = MemoryStorageEngine::new();

        let message = EmailMessage::with_id(
            "custom-id-123".to_string(),
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Test Subject".to_string(),
            "Test body content".to_string(),
        );

        let message_id = engine.store(&message).await.unwrap();
        assert_eq!(message_id, "custom-id-123");

        let content = engine
            .retrieve("recipient@example.com", "custom-id-123")
            .await
            .unwrap();
        assert_eq!(content, "Test body content");
    }

    #[tokio::test]
    async fn test_memory_storage_special_characters_in_user() {
        let engine = MemoryStorageEngine::new();

        let message = EmailMessage::new(
            "sender@example.com".to_string(),
            "user+tag@example.com".to_string(),
            "Test message".to_string(),
        );

        let message_id = engine.store(&message).await.unwrap();

        // Should be able to retrieve with the same user string
        let content = engine
            .retrieve("user+tag@example.com", &message_id)
            .await
            .unwrap();
        assert_eq!(content, "Test message");

        // The internal safe_user normalization should handle special chars
        assert_eq!(engine.message_count("user+tag@example.com"), 1);
    }
}
