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


## New Release

To create a new release follow the following steps:

- Make sure that both the tests pass and the code formatting are valid.
- Increment (look at `CHANGELOG.md` for semver changes) the `version` value in `smtp/Cargo.toml`, `imap/Cargo.toml` and `crates/util/Cargo.toml`.
- Move all the `CHANGELOG.md` Unreleased items that have at least one non empty item the into a new section with the new version number and date, and then create new empty sub-sections (Added, Changed and Fixed) for the Unreleased section with a single empty item.
- Create a commit with the following message `version: $VERSION_NUMBER`.
- Push the commit.
- Create a new tag with the value fo the new version number `$VERSION_NUMBER`.
- Create a new release on the GitHub repo using the Markdown from the corresponding version entry in `CHANGELOG.md` as the description of the release and the version number as the title. Do not include the title of the release (version and date) in the description.

## License

Mailsis is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/).
