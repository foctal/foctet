# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Security

- **Fix nonce reuse on synchronous sequence exhaustion (P0).** `SyncIo` now fails
  closed with `SequenceExhausted` instead of wrapping the sequence counter, so it
  can no longer reuse an XChaCha20-Poly1305 `(key_id, stream_id, seq)` nonce. This
  matches the async `FoctetFramed` policy.
- **Commit replay-window state only after AEAD authentication (P1).** All receive
  paths (`SyncIo::recv`, `SyncIo::recv_application_with_session`, and
  `FoctetFramed`'s decoder) now authenticate the ciphertext before recording the
  sequence number, preventing a forged high-sequence frame from desynchronizing or
  DoS-ing the receiver.
- **Authenticated-by-default native handshake (P1).** A default `SessionAuthConfig`
  now fails closed; an unauthenticated handshake requires an explicit
  `SessionAuthConfig::unauthenticated_for_testing()` /
  `allow_unauthenticated(true)` opt-in.
- **Bounded replay-window map (P2).** `ReplayProtector` caps the number of distinct
  `(key_id, stream_id)` windows (`DEFAULT_MAX_REPLAY_WINDOWS`), returning
  `ReplayCapacityExceeded` rather than growing unbounded.

### Added

- **Generic datagram transport abstraction.** `foctet_transport::datagram`:
  a backend-agnostic `DatagramTransport` trait and `SecureDatagramChannel<T>`
  that layers the core datagram endpoint over any datagram backend.
  `quinn::Connection` implements `DatagramTransport` (verified over a real
  connection), so the same secure-datagram code path works for future
  WebTransport/UDP backends.
- **Durable HTTP replay store interface.** `foctet-http` gains an
  `AsyncReplayStore` trait (intentionally `!Send`-friendly for Cloudflare
  Workers) with a blanket impl over the sync `ReplayStore`, async opener paths
  (`HttpOpener::open_request_with_async_store`, `AxumOpener` variant), and a
  Redis-backed `RedisReplayStore` (`redis` feature) using an atomic `SET NX PX`
  for multi-instance deployments.
- **WASM / TypeScript SDK (`foctet-wasm`).** New crate exposing a small,
  versioned `wasm-bindgen` API over the body envelope (`sealBody` / `openBody`,
  `sealBodyWithContext` / `openBodyWithContext`, `KeyPair`) with generated
  TypeScript declarations and `Uint8Array` values. Builds for Node, browser, and
  bundler targets via `wasm-pack`. A Node interop test opens Rust-produced
  envelopes (`tests/interop_vector.json`), proving cross-language wire
  compatibility.
- **Datagram API.** `foctet_core::datagram` (`DatagramEndpoint`, `DatagramConfig`,
  `DecodedDatagram`): one complete bounded frame per datagram, configurable max
  datagram size, per-`(key_id, stream_id)` fail-closed sequence allocation,
  authenticate-before-replay, and loss/reorder tolerance. A QUIC datagram adapter
  `foctet_transport::quinn::QuinnDatagramChannel` ships with a real-connection
  roundtrip test.
- **`foctet-http`: HTTP protected-context + anti-replay.** New versioned context
  schema (`ProtectedContext`, `ContextCarrier`, `ContextBinding`,
  `foctet-http-ctx-v1`) that binds method/path/query/status/message-id/timestamp/
  expiry into the body-envelope AEAD, plus a `ReplayStore` trait with atomic
  check-and-insert and an `InMemoryReplayStore`. New high-level APIs
  `HttpSealer::seal_request_with_context` / `HttpOpener::open_request_with_context`
  (and response variants), and an Axum adapter
  (`AxumOpener::open_request_with_context`, `AxumSealer::seal_response_with_context`).
  A captured envelope can no longer be replayed or moved onto a different route.
- **Cloudflare Workers context-binding parity.** `WorkersOpener::open_request_with_context`
  / `open_request_with_async_store` and `WorkersSealer::seal_response_with_context`
  bring the `worker::Request` / `worker::Response` adapters up to the same
  protected-context + anti-replay coverage as the Axum adapter (method, path,
  query, and headers are read from the real Worker request before the body is
  authenticated).
- `seal_body_with_context` / `open_body_with_context` /
  `open_body_for_key_id_with_context`: bind an application-supplied context into the
  body-envelope AEAD as associated data (foundation for HTTP context binding /
  anti-replay). Empty context is byte-identical to the previous output.
- `SessionAuthConfig::unauthenticated_for_testing` / `allow_unauthenticated` /
  `allows_unauthenticated`.
- `ReplayProtector::with_max_windows` / `tracked_windows`;
  `DEFAULT_MAX_REPLAY_WINDOWS`; `CoreError::ReplayCapacityExceeded`.
- `SECURITY.md` documenting the security posture, threat model, reporting process,
  supported versions, and known limitations.

### Changed

- README and SPEC corrected to reflect the implemented surface: stream-oriented
  only; UDP/datagram and TypeScript/WASM SDK are not implemented; in-session rekey
  is symmetric traffic-key rotation, not post-compromise security.
