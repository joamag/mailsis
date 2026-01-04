# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* Added modular authentication system with `AuthEngine` trait
* Added `MemoryAuthEngine` for in-memory credential storage
* Added `AuthError` enum for authentication error handling
* Added IMAP credential verification (previously accepted any login)
* Added `RSET` command support to SMTP server
* Added Python SMTP client example (`smtp/examples/smtp_client.py`)
* Added `users.txt` file for test credentials
* Added unit tests for the SMTP server
* Added unit tests for `MemoryAuthEngine`

### Changed

* `AuthEngine::authenticate` now returns `AuthResult<()>` instead of `AuthResult<bool>`, with `AuthError::InvalidCredentials` for wrong password and `AuthError::UserNotFound` for non-existent users
* SMTP server now uses `AuthEngine` trait for authentication
* IMAP server now uses `AuthEngine` trait for authentication
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
