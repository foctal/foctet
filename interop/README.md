# Interop Reference

This directory contains non-Rust tooling for interoperability verification.

Use the [WASM SDK](../foctet-wasm/README.md) to seal and open Foctet data from
JavaScript or TypeScript. This directory contains a separate implementation
for checking the wire format against the committed test vectors.

## `verify_vectors.mjs` — independent vector verification

An implementation of the Draft v0 primitives on top of the
[@noble](https://paulmillr.com/noble/) cryptography libraries (pure-JS, zero
shared code with this workspace). It verifies the frame, handshake, and rekey
vectors in `test-vectors/` end to end:

- **`frame-v0.json`** — HKDF-SHA-256 traffic-key derivation, frame-header
  decoding, nonce construction, and a **full XChaCha20-Poly1305 AEAD open**
  with the header as AAD (plus negative controls: tampered ciphertext and
  tampered header must fail).
- **`handshake-v0.json`** — X25519 public-key and shared-secret derivation on
  both sides, the handshake key schedule, `ClientHello`/`ServerHello` wire
  decoding, transcript-binding recomputation, and **Ed25519 identity signature
  verification** for both hellos.
- **`rekey-v0.json`** — DH-ratchet root seeding, the rekey ephemeral DH, and
  one full `dh_ratchet_step` (advanced root + both direction keys).

Run it (Node 18+):

```bash
cd interop
npm ci
npm test
```

The maintainer-dispatched release rehearsal runs this verification before a
release. Run it locally when changing the vectors, wire format, or cryptographic
behavior.

## `minimal_decoder.js` / `minimal_decoder.ts`

A tiny, dependency-free Node.js decoder (with an equivalent TypeScript
source) for Draft v0 frame headers from hex bytes. Kept as the smallest
possible reference for the header layout; `verify_vectors.mjs` supersedes it
for actual verification.

Usage:

```bash
node interop/minimal_decoder.js <frame_hex>
```

Example with the repository vector:

```bash
node interop/minimal_decoder.js $(jq -r .frame_hex test-vectors/frame-v0.json)
```
