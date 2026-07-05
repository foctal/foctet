[crates-badge]: https://img.shields.io/crates/v/foctet.svg
[crates-url]: https://crates.io/crates/foctet
[doc-url]: https://docs.rs/foctet/latest/foctet
[license-badge]: https://img.shields.io/crates/l/foctet.svg
[examples-url]: https://github.com/foctal/foctet/tree/main/foctet/examples

# foctet [![Crates.io][crates-badge]][crates-url] ![License][license-badge]

Transport-agnostic end-to-end encryption layer for secure data transfer.

> **Status: experimental (Draft v0) — not production-ready.** Foctet provides
> authenticated encrypted framing, HTTP body envelopes, encrypted archives, and
> a WASM/TypeScript SDK. The wire format is still unstable. See
> [`SECURITY.md`](SECURITY.md) before deploying.

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

- **Byte-stream channels** over generic split I/O plus transport helpers for
  QUIC, WebTransport, WebSocket mux, and muxTLS.
- **Datagram channels** for QUIC datagrams, raw UDP, and browser WebTransport.
- **Message channels** for reliable, ordered message transports such as raw
  WebSocket.
- **HTTP body envelopes** with protected-context request binding and replay
  defense.
- **Encrypted archives** for single-file and split-file delivery.
- **WASM/TypeScript bindings** for body envelopes and framed sessions.

Current gaps:

- npm publishing for the WASM SDK
- framework-specific streaming response helpers
- final v1 wire/API compatibility commitment

## Transport Support

Foctet exposes three transport shapes:

- **byte stream**: `TokioTransportBuilder` / `FuturesTransportBuilder`, plus
  feature-gated adapters such as `quinn`, `webtrans`, `websock`, and `muxtls`
- **message**: `MessageTransport` + `SecureMessageChannel`
- **datagram**: `DatagramTransport` + `SecureDatagramChannel`

The browser-facing surface is `foctet-wasm` (`FoctetSession`) and the
wasm32-only `BrowserWebTransportDatagrams` adapter.

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

If you already derived or exchanged Foctet session state out of band, you can
still inject an active `Session` directly.

For archives, prefer the default randomized builders in `foctet-archive`.
Reserve the deterministic `*_with_secrets` APIs for reproducible vectors and
tests.

## Security Notes

See [`SECURITY.md`](SECURITY.md) for the full posture, threat model, and
reporting process.

- Both the async (`FoctetFramed`) and synchronous (`SyncIo`) paths **fail
  closed on sequence/key-id exhaustion**.
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
  the AEAD and enforce single use through a `ReplayStore`. The low-level
  stateless request helpers remain replayable by design and are not suitable
  for production HTTP.
- Deterministic archive secrets intentionally disable build-time randomness. Reusing
  them across real payloads leaks equality and key-reuse signals, so reserve them for
  fixtures and interoperability tests.
