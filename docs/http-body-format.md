# `application/foctet` Body Envelope (v0)

This document defines the first `application/foctet` envelope format for HTTP and other byte-oriented media.

## Scope

- One-shot sealed message format.
- Transport-agnostic binary body envelope.
- Decryption requires the recipient key and, for context-bound envelopes, the
  same external context used when sealing.
- Single-recipient in current API, with recipient-table structure designed for multi-recipient extension.
- Encrypts the body; the protected-context APIs also authenticate selected HTTP
  metadata without hiding it.

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
The payload AEAD associated data (AAD) is `header || context`. The low-level
`seal_body` / `open_body` helpers use an empty context. Context bytes are not
stored in the envelope; both endpoints must supply identical bytes. See
[HTTP context rules](http-canonicalization.md) for the HTTP representation.

## Sealing Model

1. Generate random content key (`32` bytes).
2. Generate ephemeral X25519 key pair.
3. Derive recipient wrapping key + wrap nonce from ECDH shared secret via HKDF.
4. Wrap content key with XChaCha20-Poly1305 (`aad = key_id`).
5. Build envelope header with ephemeral public key, recipient entry, and payload nonce.
6. Encrypt plaintext body with content key (`aad = header || context`).

## Opening Model

1. Parse and validate header with strict limits.
2. For recipient entries, derive wrap material from recipient secret key and envelope ephemeral public key.
3. Attempt content-key unwrap (`aad = entry key_id`).
4. Decrypt payload ciphertext using the unwrapped content key and `header || context` as AAD.

## Security Boundaries

The body envelope does not hide outer HTTP metadata:

- HTTP method
- URL / path / query
- response status code
- outer headers that are not embedded into the encrypted body by the application

The protected-context APIs authenticate selected metadata and use a replay store
to reject repeated requests. The low-level body helpers alone provide neither
HTTP metadata binding nor replay protection.

Applications should compose body envelopes with an authenticated outer channel such as HTTPS, authenticated WebTransport, or an already-authenticated Foctet transport session.

## Hardening Requirements

Implementations should enforce strict parser limits:

- `max_header_bytes`
- `max_recipients`
- `max_key_id_len`
- `max_wrapped_key_len`
- `max_payload_len`

Inputs with oversized or inconsistent lengths must be rejected before allocation or decryption.
