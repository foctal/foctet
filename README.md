[crates-badge]: https://img.shields.io/crates/v/foctet.svg
[crates-url]: https://crates.io/crates/foctet
[doc-url]: https://docs.rs/foctet/latest/foctet
[license-badge]: https://img.shields.io/crates/l/foctet.svg
[examples-url]: https://github.com/foctal/foctet/tree/main/foctet/examples

# foctet [![Crates.io][crates-badge]][crates-url] ![License][license-badge]

Transport-agnostic end-to-end encryption layer for secure data transfer.

> **Status: experimental (Draft v0) — not production-ready.** Foctet implements
> authenticated encrypted framing (byte-stream, datagram, and message shapes), a
> one-shot HTTP body envelope with versioned protected-context replay defense, a
> WASM/TypeScript body-envelope SDK, and encrypted archives. The wire format is
> still unstable. See [`SECURITY.md`](SECURITY.md) for the security posture and
> known limitations before deploying.

## Crates

- `foctet-core`: Framing, crypto, handshake/rekey state, replay protection.
- `foctet-http`: Thin HTTP adapter for `application/foctet` body envelopes.
- `foctet-archive`: Encrypted single-file and split archives with recipient key wrapping.
- `foctet-transport`: Layered transport integration helpers.
- `foctet-wasm`: WebAssembly / TypeScript bindings for the body envelope.
- `foctet`: Top-level re-export crate.

## Stability

- Current releases are `0.x`; breaking changes may occur while Draft v0 is finalized.
- Wire-level changes must update both `SPEC.md` and `test-vectors/`.
- Stable wire/API compatibility is planned for `v1`.

## Deployment Guide

See [`docs/recommended-deployments.md`](docs/recommended-deployments.md) for the recommended production composition patterns across transport E2EE, HTTP body envelopes, and archive/file delivery.

Security documentation:

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what Foctet defends against, residual risks, and explicit non-goals.
- [`docs/POLICIES.md`](docs/POLICIES.md) — versioning/compatibility/deprecation, key lifecycle and rotation, incident response.
- [`SECURITY.md`](SECURITY.md) — current security posture, known limitations, vulnerability reporting.

## Examples

- Repository examples: [examples][examples-url]
- Guided overview: [`docs/examples.md`](docs/examples.md)

## What Foctet Covers

Implemented and tested today:

- Transport-agnostic encrypted framing for **byte streams** and split send/recv
  transports (TCP, QUIC/WebTransport bidirectional streams, multiplexed WebSocket).
- A **datagram API** (`foctet_core::datagram`, one frame per datagram) with QUIC
  (`foctet_transport::quinn::QuinnDatagramChannel`), raw-UDP
  (`foctet_transport::udp::UdpDatagramTransport`), and browser-WebTransport
  (`foctet_transport::webtrans_browser::BrowserWebTransportDatagrams`, wasm32)
  adapters.
- A **message API** (`foctet_core::message`, one frame per reliable/ordered
  message) with a generic `MessageTransport` shape (`foctet_transport::message`).
- A **WASM/TypeScript SDK** (`foctet-wasm`) for the body envelope **and** the
  framed session (authenticated handshake, message + datagram modes, in-session
  DH-ratchet rekey), with generated `.d.ts` and Node/browser/bundler builds —
  verified against Rust-produced envelopes and in real headless Chrome in CI.
- **HTTP protected-context replay defense**: a versioned, domain-separated
  context schema (`foctet-http`'s `ProtectedContext`, `x-foctet-*` carrier
  headers) that binds method/path/query/message-id/timestamp/expiry into the
  AEAD, with an atomic `ReplayStore` (in-memory + Redis `SET NX PX` backends) and
  `axum` / Cloudflare Workers adapters.
- Encrypted archive formats for files and split-file delivery.
- Transport helpers for `quinn`, `webtrans`, `websock`, and `muxtls` (stream-only).

Not yet implemented (see [`SECURITY.md`](SECURITY.md)):

- A published npm package for the WASM SDK (the SDK, its framed session API,
  the Node interop test, and the headless-Chrome CI tests all exist; only the
  npm release is pending).
- Streaming **response**-body helpers for a specific framework — streaming
  request bodies are turn-key (`foctet_http::axum::open_request_stream`, and the
  framework-agnostic `HttpRequestStreamReader` for Workers), but producing a
  streaming response body is currently left to the application (write the sealer's
  stream header then each sealed chunk to the response stream).
- Additional operational guidance around long-lived deployments and package
  distribution (for example the npm release flow for the WASM SDK).
- The final v1 wire/API compatibility commitment and a normative, versioned wire
  spec.

## Transport Support Matrix

Foctet protects three transport **shapes**, each with a raw transport trait and a
secure channel. All channels share one application contract via the
`foctet_transport::SecureChannel` trait, and a shared conformance suite
(`foctet-transport/tests/conformance.rs`) runs the same checks against all three.

| Adapter | Shape | API (`foctet_transport`) | Feature | Native | Browser (wasm) | Verified by |
| --- | --- | --- | --- | --- | --- | --- |
| Any byte stream (TCP, …) | byte stream | `TokioTransportBuilder` / `FuturesTransportBuilder` | `runtime-tokio` / `runtime-futures` | ✅ | via futures-io | conformance suite (duplex) |
| QUIC bidirectional stream | byte stream | `quinn` | `transport-quinn` | ✅ | — | conformance suite (real connection) + example |
| WebTransport bidirectional stream | byte stream | `webtrans` | `transport-webtrans` | ✅ | — | conformance suite (real connection) + example |
| Multiplexed WebSocket | byte stream | `websock::*_secure_channel*` | `transport-websock-mux` | ✅ | — | conformance suite (real connection) + example |
| muxTLS | byte stream | `muxtls` | `transport-muxtls` | ✅ | — | conformance suite (real connection) + example |
| Raw WebSocket message | message | `websock::WebsockMessageTransport` | `transport-websock` | ✅ | ✅ (`websock-wasm`) | loopback roundtrip + conformance |
| Generic message | message | `MessageTransport` + `SecureMessageChannel` | — | ✅ | ✅ | conformance suite |
| QUIC datagram | datagram | `quinn::QuinnDatagramChannel` | `transport-quinn` | ✅ | — | real-connection roundtrip |
| Raw UDP datagram | datagram | `udp::UdpDatagramTransport` (opt-in anti-amplification) | `runtime-tokio` | ✅ | — | real-socket roundtrip |
| Generic datagram | datagram | `DatagramTransport` + `SecureDatagramChannel` | — | ✅ | — | conformance + rekey-over-datagram |
| Browser WebTransport datagram | datagram | `webtrans_browser::BrowserWebTransportDatagrams` | `transport-webtrans-browser` | — | ✅ | headless-Chrome roundtrip (mock duplex) |
| Browser session (JS owns the socket) | message / datagram | `foctet-wasm` `FoctetSession` | — | — | ✅ | headless-Chrome tests + native-tested inner logic |

Notes:

- The **browser-WebTransport datagram adapter** is duck-typed over the
  `WebTransport.datagrams` duplex (JS opens the connection and hands the duplex
  to wasm); its stream plumbing is exercised in headless Chrome against
  in-page WHATWG streams — an end-to-end test against a live HTTP/3 server is
  still open.
- The conformance suite runs the same checks over in-memory message/datagram
  channels, a byte-stream duplex, **and a real loopback connection for every
  advertised byte-stream backend** (quinn bi-streams, WebTransport bi-streams,
  muxTLS, WebSocket-mux), each with a self-signed localhost certificate and
  the native Foctet handshake.

## Quick Start

For async stream transports, the recommended path is `foctet-transport`:

```rust,ignore
use foctet_core::{IdentityKeyPair, PeerIdentity, RekeyThresholds, SessionAuthConfig};
use foctet_transport::TokioTransportBuilder;

let builder = TokioTransportBuilder::new();
let channel = builder
    .establish_initiator_with_auth(
        stream,
        RekeyThresholds::default(),
        SessionAuthConfig::new()
            .with_local_identity(IdentityKeyPair::generate())
            .with_peer_identity(PeerIdentity::new(peer_public_key))
            .require_peer_authentication(true),
    )
    .await?;
```

If you already derived or exchanged Foctet session state out of band, you can still inject an active `Session` directly.

For encrypted files and reproducible test fixtures, `foctet-archive` exposes archive builders for both normal and deterministic generation:

```rust,ignore
use foctet_archive::{
    ArchiveBuildSecrets, ArchiveOptions, create_archive_from_bytes_with_secrets,
};

let secrets = ArchiveBuildSecrets {
    archive_id: [0x91; 16],
    file_id: [0x92; 16],
    dek: [0x93; 32],
    wrap_ephemeral_secret_keys: vec![[0x94; 32]],
};

let (archive_bytes, meta) = create_archive_from_bytes_with_secrets(
    payload,
    &[recipient_public_key],
    ArchiveOptions::default(),
    &secrets,
)?;
```

Use the `*_with_secrets` archive APIs only for reproducible vectors and deterministic tests. Production archive creation should use the default random builders.

## Security Notes

See [`SECURITY.md`](SECURITY.md) for the full posture, threat model, and reporting process.

- Both the async (`FoctetFramed`) and synchronous (`SyncIo`) paths **fail closed on
  sequence/key-id exhaustion** — a frame is never emitted with a reused nonce — and
  reject invalid all-zero X25519 shared secrets.
- **Do not persist and restore live session state.** No persistence format exists
  yet; after a restart, establish a fresh session rather than reusing traffic keys
  with reset or uncertain outbound sequence state.
- **Replay state is committed only after AEAD authentication**, so a forged frame
  cannot desynchronize or DoS the receiver; the replay-window map is bounded.
- The native handshake is **authenticated by default**: an unauthenticated handshake
  requires an explicit `SessionAuthConfig::unauthenticated_for_testing()` opt-in,
  intended only for tests or for use inside an already-authenticated outer channel.
  Prefer authenticated handshakes with pinned peer keys for production.
- For HTTP, prefer the **protected-context APIs** (`HttpSealer::seal_request_with_context`
  / `HttpOpener::open_request_with_context`, plus the `axum` / Workers adapters):
  they bind request metadata (method/path/query/message-id/timestamp/expiry) into
  the AEAD and enforce single use through an atomic `ReplayStore`. Deploy with a
  durable store (`RedisReplayStore`) for multi-instance or serverless targets. The
  low-level `seal_body` / `open_body` and stateless `seal_request` / `open_request`
  paths remain replayable by design and must not be used for production HTTP. The
  `seal_body_with_context` / `open_body_with_context` primitives are the building
  block underneath, for callers that supply and validate their own context.
- Deterministic archive secrets intentionally disable build-time randomness. Reusing
  them across real payloads leaks equality and key-reuse signals, so reserve them for
  fixtures and interoperability tests.
