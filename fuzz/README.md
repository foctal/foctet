# Fuzzing

This directory contains `cargo-fuzz` targets for parser hardening.

## Prerequisites

Install `cargo-fuzz` once:

```bash
cargo install cargo-fuzz
```

## Targets

- `frame_parser`: fuzzes `foctet_core::Frame::from_bytes`
- `archive_parser`: fuzzes archive decryption entry points

## Run

```bash
cd fuzz
cargo fuzz run frame_parser
cargo fuzz run archive_parser
```
