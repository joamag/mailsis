# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

*

### Changed

* Updated `README.md` references in multiple `Cargo.toml` files

### Fixed

*

## [0.2.0] - 2026-01-31

### Added

* Added per-rule `auth_required` override in routing configuration (per-recipient authentication at RCPT TO time)
* Added `MessageRouter::resolve_auth_required()` for recipient-based auth resolution with global fallback
* Added `MessageTransformer` trait for pluggable email transformation pipeline
* Added `MessageIdTransformer` that injects or syncs RFC 5322 `Message-ID` headers
* Added `EmailAuthTransformer` for SPF, DKIM, and DMARC verification with `Authentication-Results` header injection
* Added `TransformerConfig` enum for TOML-based transformer configuration
* Added per-rule transformer overrides in routing configuration (rule-level transformers override defaults)
* Added default transformers in `RoutingConfig` applied to all routed messages
* Added `IncomingMessage` struct for SMTP DATA aggregation with multi-recipient support
* Added `parse_raw_headers()` function for ordered header extraction from raw email
* Added structured logging with `tracing` and `tracing-subscriber` (env-filter support via `RUST_LOG`)
* Added detailed SMTP session logging: connection lifecycle, authentication, envelope (MAIL FROM/RCPT TO/DATA), routing dispatch, and handler registration
* Added internal logging to `FileStorageHandler` and `RedisQueueHandler` (initialization, success, errors)
* Added advanced Python SMTP client example (`smtp/examples/smtp_advanced.py`) with CLI options for addresses, content, attachments, TLS, auth, and priority
* Added module-level documentation to all Python examples (`smtp_client.py`, `smtp_advanced.py`, `imap_client.py`)
* Added Redis routing documentation to README with Docker usage examples
* Added modular authentication system with `AuthEngine` trait
* Added `MemoryAuthEngine` for in-memory credential storage
* Added `AuthError` enum for authentication error handling
* Added modular storage system with `StorageEngine` trait
* Added `FileStorageEngine` for filesystem-based email storage
* Added `MemoryStorageEngine` for in-memory email storage (useful for testing)
* Added `EmailMessage` struct for representing email messages
* Added `StorageError` enum for storage error handling
* Added IMAP credential verification (previously accepted any login)
* Added `RSET` command support to SMTP server
* Added Python SMTP client example (`smtp/examples/smtp_client.py`)
* Added `passwords/example.txt` file for test credentials
* Added unit tests for the SMTP server
* Added unit tests for `MemoryAuthEngine`
* Added unit tests for `FileStorageEngine`
* Added unit tests for `MemoryStorageEngine`
* Documented how to run the SMTP/IMAP servers and example clients in the README
* Added `MessageHandler` trait for pluggable email processing backends
* Added `FileStorageHandler` wrapping `FileStorageEngine` for the handler pipeline
* Added `RedisQueueHandler` for pushing JSON-serialized emails to a Redis list (feature-gated behind `redis`)
* Added `MessageRouter` with per-address, per-domain, and wildcard domain routing rules
* Added TOML-based configuration system (`config.toml`) for SMTP server settings, handlers, and routing
* Added `config.example.toml` with documented configuration examples

### Changed

* Restructured `EmailMessage` with structured headers (`Vec<(String, String)>`), separate `body` (RFC 5322 body), cached `raw` serialization, and immutable `original_raw` for DKIM verification
* Renamed `EmailMessage.body` field to `raw()` method and added `body()` for RFC 5322 body content after headers
* Moved `FileStorageHandler` from `handler.rs` to `handlers/file_storage.rs` module
* Moved `EmailAuthTransformer` and `MessageIdTransformer` into `transformers/` submodule
* `MessageTransformer::apply()` is now a static trait method that calls `rebuild()` once after all transformers run
* Replaced `println!`/`eprintln!` with structured `tracing` macros (`info!`, `debug!`, `warn!`, `error!`) in both SMTP and IMAP servers
* `AuthEngine::authenticate` now returns `AuthResult<()>` instead of `AuthResult<bool>`, with `AuthError::InvalidCredentials` for wrong password and `AuthError::UserNotFound` for non-existent users
* `MemoryAuthEngine::from_file` now returns `io::Result<Self>` and fails explicitly when the file cannot be read, instead of silently returning an empty credential store
* SMTP server now uses `AuthEngine` trait for authentication
* SMTP server now uses `StorageEngine` trait for email storage
* IMAP server now uses `AuthEngine` trait for authentication
* IMAP server now uses `StorageEngine` trait for email retrieval
* SMTP server now uses `MessageRouter` for configurable email routing instead of direct `FileStorageEngine` calls
* SMTP `MAIL FROM` and `RCPT TO` parsing is now case-insensitive (RFC 5321 compliance)
* Improved IMAP SELECT/EXAMINE error handling for non-existent mailboxes
* Performance: Avoid `to_uppercase()` allocation in SMTP prefix matching
* Performance: Pre-allocate email body buffer (64KB) and use fixed-size sliding window
* Performance: Remove unnecessary `line.clone()` in SMTP `read_command`
* Performance: Avoid String allocation in credential comparison
* Performance: Cache `crate_root` and `safe_username` in IMAP session

### Fixed

* Fixed deprecated `set_linger` usage in SMTP server
* Fixed IMAP returning OS error when mailbox directory doesn't exist
