# Interop Reference

This directory contains minimal non-Rust helpers for interoperability bring-up.

## `minimal_decoder.js` / `minimal_decoder.ts`

A tiny Node.js decoder, with an equivalent TypeScript source, for Draft v0 frame headers from hex bytes.

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
- It does not implement AEAD decryption.
