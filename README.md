# Mailsis

Simple (yet efficient) SMTP and IMAP server.

## Features

- **SMTP Server**
  - Support for STARTTLS encryption
  - Basic email delivery functionality
  - Simple and efficient message handling

- **IMAP Server**
  - Secure communication with TLS support
  - Basic IMAP protocol implementation
  - Mailbox management capabilities

- **Security**
  - TLS/SSL support for secure communication
  - Built-in certificate management
  - Rust-based implementation for memory safety

## Requirements

- Rust 1.81 or later
- OpenSSL or equivalent for TLS support

## Installation

1. Clone the repository:

```bash
git clone https://github.com/joamag/mailsis.git
cd mailsis
```

1. Build the project:

```bash
cargo build --release
```

1. Run the server:

```bash
cargo run --release
```

## Configuration

The server uses TLS certificates for secure communication. By default, it looks for:

- `cert.pem` - The server certificate
- `key.pem` - The private key

Make sure these files are present in the project root directory or configure your own certificates.

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure to:

- Follow Rust coding standards
- Add tests for new features
- Update documentation as needed
- Keep the code clean and maintainable

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Author

João Magalhães - [joamag@gmail.com](mailto:joamag@gmail.com)

## Acknowledgments

- Built with [Tokio](https://tokio.rs/) for async runtime
- Uses [Rustls](https://github.com/rustls/rustls) for TLS implementation
- Inspired by the need for a simple, efficient email server
