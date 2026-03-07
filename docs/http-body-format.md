# `application/foctet` Body Envelope (v0)

This document defines the first `application/foctet` envelope format for HTTP and other byte-oriented media.

## Scope

- One-shot sealed message format.
- Transport-agnostic binary body envelope.
- Self-contained encrypted body (no external metadata required for decryption).
- Single-recipient in current API, with recipient-table structure designed for multi-recipient extension.

## Media Type

- `application/foctet`

## Cryptographic Profile (v0)

- Key agreement: X25519 (ephemeral-static)
- KDF: HKDF-SHA256
- AEAD: XChaCha20-Poly1305
- Profile id: `0x01`

## Binary Layout

All lengths and counters encoded as unsigned LEB128 varints.

```
envelope = header || payload_ciphertext

header =
  magic[8]                       ; ASCII "FOCTETHB"
  version[1]                     ; 0x01
  profile_id[1]                  ; 0x01
  flags[1]                       ; v0: MUST be 0
  ephemeral_public_key_len[1]    ; v0: MUST be 32
  header_len[varint]             ; total header bytes, including this field
  recipient_count[varint]        ; v0 API emits 1
  payload_len[varint]            ; ciphertext bytes, includes AEAD tag
  ephemeral_public_key[32]
  payload_nonce[24]
  recipients[recipient_count]

recipient =
  key_id_len[varint]
  wrapped_key_len[varint]        ; v0: MUST be 48 (32-byte key + 16-byte tag)
  key_id[key_id_len]
  wrapped_key[wrapped_key_len]
```

The payload ciphertext begins at `header_len`.
The full `header` bytes are used as payload AEAD associated data (AAD).

## Sealing Model

1. Generate random content key (`32` bytes).
2. Generate ephemeral X25519 key pair.
3. Derive recipient wrapping key + wrap nonce from ECDH shared secret via HKDF.
4. Wrap content key with XChaCha20-Poly1305 (`aad = key_id`).
5. Build envelope header with ephemeral public key, recipient entry, and payload nonce.
6. Encrypt plaintext body with content key (`aad = full header`).

## Opening Model

1. Parse and validate header with strict limits.
2. For recipient entries, derive wrap material from recipient secret key and envelope ephemeral public key.
3. Attempt content-key unwrap (`aad = entry key_id`).
4. Decrypt payload ciphertext using unwrapped content key and full header as AAD.

## Hardening Requirements

Implementations should enforce strict parser limits:

- `max_header_bytes`
- `max_recipients`
- `max_key_id_len`
- `max_wrapped_key_len`
- `max_payload_len`

Inputs with oversized or inconsistent lengths must be rejected before allocation or decryption.
