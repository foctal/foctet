# foctet-wasm

WebAssembly / TypeScript bindings for [Foctet](../README.md) end-to-end
encryption. Exposes the `application/foctet` body envelope so browsers, Node.js,
Deno, Bun, and Cloudflare Workers can seal and open the **same wire format** as
the Rust implementation.

> **Status: experimental (Draft v0).** Body-only protection. See
> [`SECURITY.md`](../SECURITY.md) for the security posture and limitations.

## API

Generated TypeScript declarations (`foctet_wasm.d.ts`) accompany every build.

```ts
function version(): string;

class KeyPair {
  constructor();                                   // generate a fresh X25519 key pair
  static fromSecretKey(secretKey: Uint8Array): KeyPair;
  readonly publicKey: Uint8Array;                  // 32 bytes
  readonly secretKey: Uint8Array;                  // 32 bytes — handle with care
}

function sealBody(plaintext: Uint8Array, recipientPublicKey: Uint8Array, keyId: Uint8Array): Uint8Array;
function openBody(envelope: Uint8Array, recipientSecretKey: Uint8Array): Uint8Array;

// Bind an application context (e.g. HTTP method/path/message-id) into the AEAD.
function sealBodyWithContext(plaintext: Uint8Array, recipientPublicKey: Uint8Array, keyId: Uint8Array, context: Uint8Array): Uint8Array;
function openBodyWithContext(envelope: Uint8Array, recipientSecretKey: Uint8Array, context: Uint8Array): Uint8Array;
```

Fallible functions throw a JavaScript `Error` on malformed input; they never
abort the WASM instance.

## Build

Requires [`wasm-pack`](https://drager.github.io/wasm-pack/).

```sh
# Node.js / Cloudflare Workers
npm run build:node      # -> pkg-node/

# Browser (ES modules, no bundler)
npm run build:web       # -> pkg-web/

# Bundler (webpack/Vite/Rollup)
npm run build:bundler   # -> pkg/
```

## Test

```sh
npm test                # builds for Node and runs the interop test
```

The interop test (`tests/node_interop.cjs`) verifies a JS seal→open roundtrip,
context binding, and — crucially — that Node opens **Rust-produced** envelopes
from `tests/interop_vector.json`, proving cross-language wire compatibility.
Regenerate the fixture with:

```sh
cargo run -p foctet-wasm --example gen_interop_fixture > foctet-wasm/tests/interop_vector.json
```

## Scope and security

This is **body-only** protection: it encrypts and authenticates the payload (and
an optional associated `context`). It does not protect outer HTTP metadata —
carry it over an authenticated outer channel such as HTTPS. For HTTP replay
protection, build the protected-context bytes on the host (mirroring
`foctet-http`'s `foctet-http-ctx-v1` encoding) and pass them as `context`.

`KeyPair` exposes raw X25519 key bytes; store the secret key in a platform
keystore or Worker secret and never log it.
