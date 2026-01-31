//! SQLite-backed email metadata index.
//!
//! After an email is stored on disk, its envelope data (sender, recipient,
//! subject, file path) is recorded in a local SQLite database so that the
//! IMAP server can list and search messages without scanning the filesystem.

use std::{
    error::Error,
    path::{Path, PathBuf},
};

use rusqlite::{params, Connection};
use tokio::task::spawn_blocking;

#[derive(Clone, Debug)]
pub struct EmailMetadata {
    pub message_id: String,
    pub from: String,
    pub rcpt: String,
    pub subject: String,
    pub path: PathBuf,
}

impl EmailMetadata {
    pub fn new(
        message_id: String,
        from: String,
        rcpt: String,
        subject: String,
        path: PathBuf,
    ) -> Self {
        Self {
            message_id,
            from,
            rcpt,
            subject,
            path,
        }
    }

    pub async fn store_sqlite(
        &self,
        db: impl AsRef<Path>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let path = db.as_ref().to_path_buf();
        let metadata = self.clone();

        // spawns a blocking task to store the metadata in the database
        // this is done to avoid blocking the main thread
        spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let conn = Connection::open(path)?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS metadata (message_id TEXT PRIMARY KEY, _from TEXT, rcpt TEXT, subject TEXT, path TEXT)",
                [],
            )?;
            conn.execute(
                "INSERT INTO metadata (message_id, _from, rcpt, subject, path) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![metadata.message_id, metadata.from, metadata.rcpt, metadata.subject, metadata.path.to_string_lossy()],
            )?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    pub async fn retrieve_sqlite(
        db: impl AsRef<Path>,
        message_id: String,
    ) -> Result<EmailMetadata, Box<dyn Error + Send + Sync>> {
        let path = db.as_ref().to_path_buf();

        // Spawn a blocking task to retrieve the metadata from the database
        // this is done to avoid blocking the main thread
        spawn_blocking(
            move || -> Result<EmailMetadata, Box<dyn Error + Send + Sync>> {
                let conn = Connection::open(path)?;
                let mut stmt = conn.prepare(
                    "SELECT message_id, _from, rcpt, subject, path FROM metadata WHERE message_id = ?",
                )?;
                let row = stmt.query_row(params![message_id], |row| {
                    Ok(EmailMetadata {
                        message_id: row.get(0)?,
                        from: row.get(1)?,
                        rcpt: row.get(2)?,
                        subject: row.get(3)?,
                        path: PathBuf::from(row.get::<_, String>(4)?),
                    })
                })?;
                Ok(row)
            },
        )
        .await?
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_email_metadata_new() {
        let message_id = "test-message-id".to_string();
        let from = "sender@example.com".to_string();
        let rcpt = "recipient@example.com".to_string();
        let subject = "Test Subject".to_string();
        let path = PathBuf::from("/path/to/email.eml");

        let metadata = EmailMetadata::new(
            message_id.clone(),
            from.clone(),
            rcpt.clone(),
            subject.clone(),
            path.clone(),
        );

        assert_eq!(metadata.message_id, message_id);
        assert_eq!(metadata.from, from);
        assert_eq!(metadata.rcpt, rcpt);
        assert_eq!(metadata.subject, subject);
        assert_eq!(metadata.path, path);
    }

    #[test]
    fn test_email_metadata_clone() {
        let original = EmailMetadata::new(
            "test-id".to_string(),
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Test Subject".to_string(),
            PathBuf::from("/path/to/email.eml"),
        );

        let cloned = original.clone();

        assert_eq!(original.message_id, cloned.message_id);
        assert_eq!(original.from, cloned.from);
        assert_eq!(original.rcpt, cloned.rcpt);
        assert_eq!(original.subject, cloned.subject);
        assert_eq!(original.path, cloned.path);
    }

    #[tokio::test]
    async fn test_store_sqlite_success() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path();

        let metadata = EmailMetadata::new(
            "test-message-id".to_string(),
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Test Subject".to_string(),
            PathBuf::from("/path/to/email.eml"),
        );

        let result = metadata.store_sqlite(db_path).await;
        assert!(result.is_ok(), "Failed to store metadata: {result:?}");

        let conn = Connection::open(db_path).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT message_id, _from, rcpt, subject, path FROM metadata WHERE message_id = ?",
            )
            .unwrap();

        let row = stmt
            .query_row(params!["test-message-id"], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .unwrap();

        assert_eq!(row.0, "test-message-id");
        assert_eq!(row.1, "sender@example.com");
        assert_eq!(row.2, "recipient@example.com");
        assert_eq!(row.3, "Test Subject");
        assert_eq!(row.4, "/path/to/email.eml");
    }

    #[tokio::test]
    async fn test_store_sqlite_duplicate_id() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path();

        let metadata1 = EmailMetadata::new(
            "duplicate-id".to_string(),
            "sender1@example.com".to_string(),
            "recipient1@example.com".to_string(),
            "First Subject".to_string(),
            PathBuf::from("/path/to/email1.eml"),
        );

        let metadata2 = EmailMetadata::new(
            "duplicate-id".to_string(),
            "sender2@example.com".to_string(),
            "recipient2@example.com".to_string(),
            "Second Subject".to_string(),
            PathBuf::from("/path/to/email2.eml"),
        );

        let result1 = metadata1.store_sqlite(db_path).await;
        assert!(result1.is_ok(), "First insert should succeed: {result1:?}");

        let result2 = metadata2.store_sqlite(db_path).await;
        assert!(
            result2.is_err(),
            "Second insert should fail due to duplicate ID"
        );
    }

    #[tokio::test]
    async fn test_store_sqlite_multiple_entries() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path();

        let metadata1 = EmailMetadata::new(
            "id-1".to_string(),
            "sender1@example.com".to_string(),
            "recipient1@example.com".to_string(),
            "Subject 1".to_string(),
            PathBuf::from("/path/to/email1.eml"),
        );

        let metadata2 = EmailMetadata::new(
            "id-2".to_string(),
            "sender2@example.com".to_string(),
            "recipient2@example.com".to_string(),
            "Subject 2".to_string(),
            PathBuf::from("/path/to/email2.eml"),
        );

        let result1 = metadata1.store_sqlite(db_path).await;
        assert!(result1.is_ok(), "First insert failed: {result1:?}");

        let result2 = metadata2.store_sqlite(db_path).await;
        assert!(result2.is_ok(), "Second insert failed: {result2:?}");

        let conn = Connection::open(db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM metadata", [], |row| row.get(0))
            .unwrap();

        assert_eq!(count, 2, "Should have exactly 2 entries in the database");
    }

    #[tokio::test]
    async fn test_store_sqlite_with_special_characters() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path();

        let metadata = EmailMetadata::new(
            "test-id-with-special-chars".to_string(),
            "sender+tag@example.com".to_string(),
            "recipient.name@domain.co.uk".to_string(),
            "Subject with \"quotes\" and 'apostrophes'".to_string(),
            PathBuf::from("/path/with spaces/email.eml"),
        );

        let result = metadata.store_sqlite(db_path).await;
        assert!(
            result.is_ok(),
            "Failed to store metadata with special characters: {result:?}"
        );

        let conn = Connection::open(db_path).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT message_id, _from, rcpt, subject, path FROM metadata WHERE message_id = ?",
            )
            .unwrap();
        let row = stmt
            .query_row(params!["test-id-with-special-chars"], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .unwrap();

        assert_eq!(row.0, "test-id-with-special-chars");
        assert_eq!(row.1, "sender+tag@example.com");
        assert_eq!(row.2, "recipient.name@domain.co.uk");
        assert_eq!(row.3, "Subject with \"quotes\" and 'apostrophes'");
        assert_eq!(row.4, "/path/with spaces/email.eml");
    }

    #[tokio::test]
    async fn test_store_sqlite_invalid_path() {
        let metadata = EmailMetadata::new(
            "test-id".to_string(),
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Test Subject".to_string(),
            PathBuf::from("/path/to/email.eml"),
        );
        let invalid_path = PathBuf::from("/nonexistent/directory/database.db");
        let result = metadata.store_sqlite(&invalid_path).await;

        assert!(
            result.is_err(),
            "Should fail when trying to create database in nonexistent directory"
        );
    }

    #[tokio::test]
    async fn test_retrieve_sqlite_success() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path();

        let original_metadata = EmailMetadata::new(
            "retrieve-test-id".to_string(),
            "sender@example.com".to_string(),
            "recipient@example.com".to_string(),
            "Test Subject for Retrieval".to_string(),
            PathBuf::from("/path/to/email.eml"),
        );

        // First store the metadata
        let store_result = original_metadata.store_sqlite(db_path).await;
        assert!(
            store_result.is_ok(),
            "Failed to store metadata: {store_result:?}"
        );

        // Then retrieve it
        let retrieved_metadata =
            EmailMetadata::retrieve_sqlite(db_path, "retrieve-test-id".to_string()).await;
        assert!(
            retrieved_metadata.is_ok(),
            "Failed to retrieve metadata: {retrieved_metadata:?}"
        );

        let retrieved = retrieved_metadata.unwrap();
        assert_eq!(retrieved.message_id, original_metadata.message_id);
        assert_eq!(retrieved.from, original_metadata.from);
        assert_eq!(retrieved.rcpt, original_metadata.rcpt);
        assert_eq!(retrieved.subject, original_metadata.subject);
        assert_eq!(retrieved.path, original_metadata.path);
    }

    #[tokio::test]
    async fn test_retrieve_sqlite_not_found() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path();

        // Try to retrieve non-existent metadata
        let result = EmailMetadata::retrieve_sqlite(db_path, "non-existent-id".to_string()).await;
        assert!(
            result.is_err(),
            "Should fail when trying to retrieve non-existent metadata"
        );
    }
}
