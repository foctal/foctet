# Interop Reference

This directory contains non-Rust tooling for interoperability verification.

## Which tool for which job

- **Full seal/open from JavaScript/TypeScript — use the WASM SDK
  (`foctet-wasm/`)**, not this directory. It exposes the body envelope
  (`sealBody`/`openBody`, context-bound variants) and the framed session
  (`FoctetSession` handshake + `sealMessage`/`openMessage`), with generated
  `.d.ts` typings. Its Node interop test (`foctet-wasm/tests/node_interop.cjs`)
  opens **Rust-produced** envelopes from `tests/interop_vector.json`, proving
  cross-language wire compatibility, and `foctet-wasm/tests/browser.rs` runs
  the same surface in a real headless browser.
- **Independent verification of the canonical vectors — use
  `verify_vectors.mjs`** (below). Unlike the WASM SDK, it is *not generated
  from the Rust implementation*, so it provides a genuinely independent check
  of the Draft v0 wire format and key schedule against the committed test
  vectors. That independence is the point: it catches a systematic
  encode/derive bug that a Rust-derived artifact would faithfully reproduce.

## `verify_vectors.mjs` — independent vector verification

A from-spec re-implementation of the Draft v0 primitives on top of the
[@noble](https://paulmillr.com/noble/) cryptography libraries (audited,
pure-JS, zero shared code with this workspace). It verifies every canonical
vector in `test-vectors/` end to end:

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

CI runs this on every push/PR (`interop-verify` job in
`.github/workflows/rust.yml`), so the vectors and the Rust implementation
cannot drift from the spec without an independent implementation noticing.

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
