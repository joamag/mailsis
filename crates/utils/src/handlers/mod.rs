//! Delivery backends for routed email messages.
//!
//! After the router selects a destination for an incoming email, one of the
//! handlers here takes over: writing the message to the filesystem as an
//! `.eml` file, or pushing it onto a Redis queue (feature-gated behind
//! `redis`) for downstream consumers.

pub mod file_storage;
#[cfg(feature = "redis")]
pub mod redis;

pub use file_storage::*;
#[cfg(feature = "redis")]
pub use redis::*;
