# Test Vectors (Draft v0)

This directory contains deterministic vectors for interoperability and regression checks.

## Stability Policy

- Vector file names are stable during Draft v0.
- Wire-level changes must update both `SPEC.md` and these vectors in the same change.
- Consumers should pin by repository commit for reproducible interop checks.

## Files

- `frame-v0.json`
  - `shared_secret_hex`: 32-byte hex
  - `session_salt_hex`: 32-byte hex
  - `frame_hex`: encoded frame bytes as hex
  - `plaintext_hex`: expected decrypted plaintext as hex
- `handshake-v0.json`
  - `client_private_hex`: 32-byte hex
  - `server_private_hex`: 32-byte hex
  - `client_public_hex`: 32-byte hex
  - `server_public_hex`: 32-byte hex
  - `session_salt_hex`: 32-byte hex
  - `shared_secret_hex`: 32-byte hex
  - `key_c2s_hex`: 32-byte hex
  - `key_s2c_hex`: 32-byte hex
- `archive-v0.json`
  - `recipient_private_hex`: 32-byte hex
  - `payload_hex`: hex
  - `single_archive_hex`: hex
  - `manifest_hex`: hex
  - `parts_hex`: array of hex strings

## Regeneration

```bash
cargo run -p foctet --example gen_vectors
```

## Verification

```bash
cargo test -p foctet --test test_vectors
cargo test -p foctet --test test_vector_schema
```
