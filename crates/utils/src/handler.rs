use std::{error::Error, fmt::Display, future::Future, pin::Pin};

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
/// Unlike [`StorageEngine`], this trait only handles the inbound direction
/// (receiving/storing), making it suitable for both storage backends
/// and queue-based destinations like Redis.
pub trait MessageHandler: Send + Sync {
    /// Handles an incoming email message.
    fn handle<'a>(&'a self, message: &'a crate::EmailMessage) -> HandlerFuture<'a>;

    /// Returns the name of this handler.
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

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
