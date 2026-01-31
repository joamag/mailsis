# Mailsis

Simple (yet efficient) [SMTP](https://datatracker.ietf.org/doc/html/rfc5321) and [IMAP](https://datatracker.ietf.org/doc/html/rfc3501) server.

**Mailsis has been written for educational purposes and shouldn't be taken too seriously.** Use it at your own risk!

## Description

Built on top of the powerful [Rust Programming Language](https://www.rust-lang.org/), Mailsis provides a safe and efficient implementation of the classic SMTP and IMAP protocols.

### Features

- Simple and efficient SMTP server
- Powerful IMAP server
- Authentication with [SASL](https://datatracker.ietf.org/doc/html/rfc4422)
- Mailbox storage, with support for multiple users
- File-system based, allowing for easy integration with existing systems

## SMTP Server

Run the SMTP server from the workspace root:

```bash
cargo run -p mailsis-smtp
```

Configuration is loaded from `config.toml` by default. To point to a different config file, set the `MAILSIS_CONFIG` environment variable before launching.

By default, the server listens on `127.0.0.1:2525`. You can override the bind address with `HOST` and `PORT` environment variables.

Authentication uses `passwords/example.txt`, and `smtp.auth_required` is `false` by default. Set it to `true` in the config to require credentials.

### Redis Routing

Mailsis SMTP can route incoming emails to a Redis queue instead of (or in addition to) local file storage. This requires the `redis` cargo feature and a running Redis instance.

Build with the `redis` feature:

```bash
cargo build -p mailsis-smtp --features redis
```

Start a Redis server (e.g. via Docker):

```bash
docker run -d --name redis -p 6379:6379 redis
```

Configure `config.toml` to define a Redis handler and routing rules:

```toml
[smtp.handlers.local]
type = "file_storage"
path = "mailbox"
metadata = true

[smtp.handlers.redis_queue]
type = "redis"
url = "redis://127.0.0.1:6379"
queue = "incoming_emails"

[smtp.routing]
default = "local"

# Route all emails for example.com to Redis
[[smtp.routing.rules]]
domain = "example.com"
handler = "redis_queue"
```

Run the SMTP server:

```bash
cargo run -p mailsis-smtp --features redis
```

Send an email to a routed address and verify it lands in Redis:

```bash
redis-cli LRANGE incoming_emails 0 -1

# Or, if Redis is running in Docker:
docker exec redis redis-cli LRANGE incoming_emails 0 -1
```

Each message is pushed as a JSON object with `message_id`, `from`, `to`, `subject`, and `body` fields. See `config.example.toml` for the full set of routing options (per-address, per-domain, and wildcard domain rules).

## IMAP Server

Run the IMAP server from the workspace root:

```bash
cargo run -p mailsis-imap
```

By default, the IMAP server listens on `127.0.0.1:1430`. You can override the bind address with `HOST` and `PORT` environment variables.

Authentication uses `passwords/example.txt` and messages are read from `mailbox/`.

## Examples

> Note: Start the SMTP/IMAP servers before running the example clients. The example credentials in `passwords/example.txt` include `sender@localhost:password` and `recipient@localhost:password`.

SMTP Python client (sends a test email with an attachment):

```bash
python smtp/examples/smtp_client.py
```

SMTP Rust clients:

```bash
cargo run -p mailsis-smtp --example smtp_client
```

```bash
cargo run -p mailsis-smtp --example smtp_raw
```

The `smtp_client` example validates TLS using `certs/ca.cert.pem`. The `smtp_raw` example can optionally take a file path to send as an attachment.

IMAP Python client (reads the latest email from INBOX):

```bash
python imap/examples/imap_client.py
```

## License

Mailsis is currently licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/).

## Build Automation

[![Build Status](https://github.com/joamag/mailsis/workflows/Main%20Workflow/badge.svg)](https://github.com/joamag/mailsis/actions)
[![crates Status](https://img.shields.io/crates/v/mailsis-smtp)](https://crates.io/crates/mailsis-smtp)
[![crates Status](https://img.shields.io/crates/v/mailsis-imap)](https://crates.io/crates/mailsis-imap)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/)
