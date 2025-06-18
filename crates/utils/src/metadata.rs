use std::error::Error;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use tokio::task::spawn_blocking;

#[derive(Clone)]
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

        spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let conn = Connection::open(path)?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS metadata (id TEXT PRIMARY KEY, sender TEXT, recipient TEXT, subject TEXT, path TEXT)",
                [],
            )?;
            conn.execute(
                "INSERT INTO metadata (id, sender, recipient, subject, path) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![metadata.message_id, metadata.from, metadata.rcpt, metadata.subject, metadata.path.to_string_lossy()],
            )?;
            Ok(())
        })
        .await??;
        Ok(())
    }
}
