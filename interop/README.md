# Interop Reference

This directory contains minimal non-Rust helpers for interoperability bring-up.

## Which tool for which job

- **Full seal/open from JavaScript/TypeScript — use the WASM SDK
  (`foctet-wasm/`)**, not this directory. It exposes the body envelope
  (`sealBody`/`openBody`, context-bound variants) and the framed session
  (`FoctetSession` handshake + `sealMessage`/`openMessage`), with generated
  `.d.ts` typings. Its Node interop test (`foctet-wasm/tests/node_interop.cjs`)
  opens **Rust-produced** envelopes from `tests/interop_vector.json`, proving
  cross-language wire compatibility, and `foctet-wasm/tests/browser.rs` runs
  the same surface in a real headless browser.
- **Independent header-level verification — use `minimal_decoder`** (below).
  Unlike the WASM SDK, it is *not generated from the Rust implementation*, so
  it provides a genuinely independent reading of the Draft v0 frame header
  layout against the committed test vectors. That independence is the point:
  it would catch a systematic encode/decode bug that a Rust-derived artifact
  would faithfully reproduce.

## `minimal_decoder.js` / `minimal_decoder.ts`

A tiny Node.js decoder, with an equivalent TypeScript source, for Draft v0
frame headers from hex bytes.

Usage:

```bash
node interop/minimal_decoder.js <frame_hex>
```

Example with the repository vector:

```bash
node interop/minimal_decoder.js $(jq -r .frame_hex test-vectors/frame-v0.json)
```

Notes:

- This script is intentionally minimal and performs header-level decoding only.
- It does not implement AEAD decryption — for that, use the WASM SDK above.
- A future goal is a fully independent implementation (header + AEAD) verifying
  the complete canonical vector suite (see `TODO.md` §6/§7).
