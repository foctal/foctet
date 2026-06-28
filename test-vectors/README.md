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
- `rekey-v0.json` — one deterministic DH-ratchet rekey step (locks the in-session
  rekey key schedule: `derive_ratchet_root` then `dh_ratchet_step`)
  - `session_salt_hex`, `shared_secret_hex`: 32-byte hex (ratchet-root inputs)
  - `ratchet_root_hex`: 32-byte hex (`derive_ratchet_root` output)
  - `rekey_eph_private_hex`, `rekey_eph_public_hex`: 32-byte hex (the rekeying
    side's fresh ephemeral)
  - `peer_ratchet_public_hex`: 32-byte hex (the peer's current ratchet public)
  - `rekey_dh_hex`: 32-byte hex (`X25519(rekey_eph_private, peer_ratchet_public)`)
  - `new_key_id`: integer
  - `new_ratchet_root_hex`, `rekey_key_c2s_hex`, `rekey_key_s2c_hex`: 32-byte hex
    (`dh_ratchet_step` outputs)

The archive vector is generated with fixed `ArchiveBuildSecrets` so repeated regeneration is byte-for-byte stable across runs.

## Regeneration

```bash
cargo run -p foctet --example gen_vectors
```

The generator intentionally uses deterministic handshake/archive inputs. Do not copy those fixed secrets into production applications.

## Verification

```bash
cargo test -p foctet --test test_vectors
cargo test -p foctet --test test_vector_schema
```
