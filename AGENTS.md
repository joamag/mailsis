# AGENTS.md file

This document describes how to work with the project.
Follow these notes when writing code or submitting pull requests.

## Setup

Install Python packages and the Rust toolchain:

```bash
rustup default nightly
rustup component add rustfmt
rustup component add clippy
```

## Formatting

Format all code before committing:

```bash
cargo fmt --all
cargo clippy --fix --allow-dirty --allow-staged --all-features --all-targets
black .
```

## Testing

Run the full test suite:

```bash
cargo test --all-targets --all-features
```

There are example Python scripts that can be used for testing of both IMAP and SMTP:

```bash
python imap/examples/imap_client.py
```

```bash
python imap/examples/smtp_client.py
```

## Coverage

Generate a line-level coverage report using `cargo-llvm-cov`:

```bash
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview
cargo llvm-cov --all-features --all-targets
```

Coverage runs automatically in CI on every push. The coverage summary is
printed in the CI logs for each Rust version.

Maintain at least 80% overall line coverage. Individual library modules
in `crates/utils/src/` should target 90%+ line coverage.

## Linting

Lint all code before committing:

```bash
cargo clippy --all-features --all-targets -- -D warnings -A unknown-lints
```

## Style Guide

- Always update `CHANGELOG.md` according to semantic versioning, mentioning your changes in the unreleased section.
- Write commit messages using [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
- Never bump the internal package version in `Cargo.toml` or `setup.py`. This is handled automatically by the release process.
- Rust files use LF line endings, while Python files use CRLF.
- Inline comments should be in the format `// <comment>` and start with uppercase.
- Inline comments should be written as in "Add support for X" rather than "Adds support for X" or "Added support for X".
- Always run the format and testing commands after changes.
- Maintain at least 80% overall line coverage. Library modules in `crates/utils/src/` should target 90%+ line coverage. Run `cargo llvm-cov --all-features --all-targets` to check.
- Document each Rust module with module-level documentation comments (`//!`).
- Try to avoid super single letter variable names like `e`, even in the context of `map` and `map_err` closures - use moa bit more descriptive names like `error`, `line`, `part`, etc.

## License

Mailsis is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/).
