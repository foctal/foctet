# foctet-wasm

WebAssembly / TypeScript bindings for [Foctet](../README.md) end-to-end
encryption. Exposes the `application/foctet` body envelope so browsers, Node.js,
Deno, Bun, and Cloudflare Workers can seal and open the **same wire format** as
the Rust implementation.

> **Status: experimental (Draft v0).** Provides the one-shot body envelope **and**
> a full framed session (authenticated handshake + ordered, replay-protected
> messages). See [`SECURITY.md`](../SECURITY.md) for the security posture and
> limitations.

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

### Framed session (handshake + messages)

For a full secure channel — not just one-shot envelopes — drive a `FoctetSession`.
WebAssembly performs the authenticated handshake and per-message seal/open; **your
JS owns the transport** (a browser `WebSocket`, a `WebTransport` stream or
datagram channel, etc.) and moves the `Uint8Array` blobs in order.

```ts
class IdentityKeyPair {
  constructor();                                   // generate an Ed25519 identity
  static fromSecretKey(secretKey: Uint8Array): IdentityKeyPair;
  readonly publicKey: Uint8Array;                  // 32 bytes — share to let the peer pin you
  readonly secretKey: Uint8Array;                  // 32 bytes — handle with care
}

class AuthConfig {
  // Pin the peer's identity and prove your own (recommended).
  static authenticated(localIdentity: IdentityKeyPair, peerPublicKey: Uint8Array): AuthConfig;
  // Tests, or use only inside an already-authenticated outer channel (e.g. mTLS).
  static unauthenticatedForTesting(): AuthConfig;
}

class DecodedMessage {
  readonly streamId: number;
  readonly flags: number;
  readonly keyId: number;
  readonly seq: bigint;
  readonly plaintext: Uint8Array;
}

class FoctetSession {
  // Message mode: reliable/ordered (raw WebSocket, WebTransport stream).
  static newInitiator(auth: AuthConfig): FoctetSession;
  static newResponder(auth: AuthConfig): FoctetSession;
  // Datagram mode: MTU-bounded, loss-tolerant (WebTransport datagrams).
  // maxDatagramSize = 0 uses the default (1200).
  static newDatagramInitiator(auth: AuthConfig, maxDatagramSize: number): FoctetSession;
  static newDatagramResponder(auth: AuthConfig, maxDatagramSize: number): FoctetSession;

  initialHandshakeMessage(): Uint8Array | undefined;   // initiator: send this first
  handleHandshakeMessage(message: Uint8Array): Uint8Array | undefined; // returns a reply to send, if any
  isEstablished(): boolean;
  peerAuthenticated(): boolean;

  // Message-mode sessions:
  sealMessage(streamId: number, flags: number, plaintext: Uint8Array): Uint8Array;
  openMessage(message: Uint8Array): DecodedMessage;
  // Datagram-mode sessions:
  sealDatagram(streamId: number, flags: number, plaintext: Uint8Array): Uint8Array;
  openDatagram(datagram: Uint8Array): DecodedMessage;
}
```

A session commits to one framing mode; the methods for the other mode throw. For
WebTransport datagrams, run the (reliable) handshake messages over a stream, then
send each `sealDatagram` result as a datagram.

Example over a browser `WebSocket` (binary frames), as the initiator:

```ts
const ws = new WebSocket(url);
ws.binaryType = "arraybuffer";

const auth = AuthConfig.authenticated(myIdentity, serverPublicKey);
const session = FoctetSession.newInitiator(auth);

ws.onopen = () => ws.send(session.initialHandshakeMessage()!);   // send ClientHello
ws.onmessage = (ev) => {
  const bytes = new Uint8Array(ev.data as ArrayBuffer);
  if (!session.isEstablished()) {
    const reply = session.handleHandshakeMessage(bytes);          // finish handshake
    if (reply) ws.send(reply);
    if (session.isEstablished()) {
      ws.send(session.sealMessage(0, 0, new TextEncoder().encode("hello")));
    }
  } else {
    const msg = session.openMessage(bytes);                       // application data
    console.log(new TextDecoder().decode(msg.plaintext));
  }
};
```

The same pattern works over `WebTransport`: send each `sealMessage` result as a
datagram or on a stream, and feed each received blob to `openMessage`. In-session
rekey is not yet carried over this message API — establish a fresh session rather
than reusing one indefinitely.

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

The **body envelope** functions provide body-only protection: they encrypt and
authenticate the payload (and an optional associated `context`), not the outer
HTTP metadata — carry that over an authenticated outer channel such as HTTPS. For
HTTP replay protection, build the protected-context bytes on the host (mirroring
`foctet-http`'s `foctet-http-ctx-v1` encoding) and pass them as `context`.

The **framed session** (`FoctetSession`) authenticates and protects the message
stream end to end once the handshake completes; prefer `AuthConfig.authenticated`
with a pinned peer identity so the handshake fails closed against an unexpected
peer. The JS transport it runs over should still be carried by an authenticated
outer channel (`wss://`, `https://`) unless you pin identities.

`KeyPair` and `IdentityKeyPair` expose raw key bytes because WebCrypto has no
portable non-extractable X25519/Ed25519 type; store secret keys in a platform
keystore or Worker secret and never log them. Host-backed (non-extractable) key
handling is not yet available across the WASM boundary.
