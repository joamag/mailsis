//! Concrete [`MessageHandler`](crate::MessageHandler) implementations.
//!
//! Contains [`FileStorageHandler`] for filesystem persistence and
//! [`RedisQueueHandler`] (feature-gated behind `redis`) for queue-based
//! email processing.

pub mod file_storage;
#[cfg(feature = "redis")]
pub mod redis;

pub use file_storage::*;
#[cfg(feature = "redis")]
pub use redis::*;
