use std::error::Error;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

#[derive(Clone)]
pub struct EmailMetadata {
    pub message_id: String,
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub path: PathBuf,
}

pub async fn store_metadata(
    db: impl AsRef<Path>,
    meta: &EmailMetadata,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = db.as_ref().to_path_buf();
    let meta = meta.clone();
    tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata (id TEXT PRIMARY KEY, sender TEXT, recipient TEXT, subject TEXT, path TEXT)",
            [],
        )?;
        conn.execute(
            "INSERT INTO metadata (id, sender, recipient, subject, path) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![meta.message_id, meta.sender, meta.recipient, meta.subject, meta.path.to_string_lossy()],
        )?;
        Ok(())
    })
    .await??;
    Ok(())
}
