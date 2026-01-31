//! Shared utilities for the Mailsis mail server.
//!
//! This crate provides the core building blocks used by the SMTP and IMAP
//! binaries: authentication engines, message types, routing, storage,
//! TLS configuration, and email transformers.

pub mod auth;
pub mod config;
pub mod exec;
pub mod file;
pub mod handler;
pub mod handlers;
pub mod imap;
pub mod message;
pub mod metadata;
pub mod mime;
pub mod router;
pub mod storage;
pub mod tls;
pub mod transformer;
pub mod transformers;

pub use auth::*;
pub use config::*;
pub use exec::*;
pub use file::*;
pub use handler::*;
pub use handlers::*;
pub use imap::*;
pub use message::*;
pub use metadata::*;
pub use mime::*;
pub use router::*;
pub use storage::*;
pub use tls::*;
pub use transformer::*;
pub use transformers::*;
