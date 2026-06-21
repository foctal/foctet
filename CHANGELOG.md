# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Security

- **Centralize fail-closed outbound sequence allocation (P0 follow-up).** The
  blocking stream, async framed stream, datagram, and discrete-message paths now
  share one internal sequence allocator, so `SequenceExhausted` behavior cannot
  drift between transport shapes. Session-state restoration is explicitly
  unsupported until a design can preserve every outbound counter atomically.

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
- **Fail closed on outbound plaintext length overflow (P1).** `encrypt_frame`
  now rejects plaintext whose ciphertext length (plaintext + AEAD tag) would
  overflow the frame header's `u32 ct_len` field, instead of silently
  truncating it. Shared by every sync (`SyncIo`) and async (`FoctetFramed`)
  send path via a new internal `checked_ciphertext_len` helper.
- **Handshake read timeout for the Tokio transport path (P1).**
  `TokioTransportBuilder::establish_initiator_with_timeout` /
  `establish_responder_with_timeout` (plus `_with_auth_and_timeout` and
  `_with_default_timeout` convenience variants, `DEFAULT_HANDSHAKE_TIMEOUT`)
  bound how long the native handshake can block on a stalled or hostile peer,
  failing with the new `CoreError::HandshakeTimeout` instead of hanging
  forever. The `quinn`/`websock`/`webtrans`/`muxtls` adapters all build on
  `TokioTransportBuilder`, so they can opt in by switching call sites.
- **`cargo-audit` advisory scan in CI; fixed the vulnerabilities it found.**
  Bumped `quinn-proto` (0.11.13 → 0.11.14, fixes a high-severity Quinn DoS,
  RUSTSEC-2026-0037), `rustls-webpki` (0.103.9 → 0.103.13, fixes several
  certificate-validation advisories), `rand` (0.9.2 → 0.9.4), and `rkyv`
  (0.8.15 → 0.8.16) in `Cargo.lock` — all compatible patch/minor bumps, no API
  changes. Added a `security-audit` CI job (`.github/workflows/rust.yml`,
  via `rustsec/audit-check`) that fails the build on any future vulnerability
  finding; it scans advisories only, not licenses (that's `cargo-deny`,
  still open below).
- **Negative protocol test coverage: control/data flag confusion and rekey
  collisions (P1).** New regression tests proving the `IS_CONTROL` header
  flag (not payload shape) is authoritative for control-vs-data dispatch, and
  that the rekey state machine rejects a stale `old_key_id`, a replayed
  `Rekey` message, a forged transcript binding, and a handshake message
  replayed onto an already-active session.
- **Optional selected-header binding for HTTP protected contexts (request
  side).** `ContextBinding::with_bound_headers` authenticates the presence
  and exact value bytes of named headers (e.g. a tenant ID) into the same
  AEAD associated data as method/path/query, so an on-path party swapping a
  bound header — without touching the ciphertext, route, or carrier headers —
  fails authentication instead of silently reattributing the request. Purely
  additive: empty by default, byte-identical associated data to before when
  unused. Response-side header binding is not covered yet.
- **Ready-made Axum extractor for protected, replay-checked requests.**
  `ProtectedHttpState` trait + `ProtectedRequest` (`foctet-http/src/axum.rs`)
  let a handler take a decrypted, context-authenticated, single-use-checked
  `http::Request<Vec<u8>>` directly as a parameter via Axum's `FromRequest`,
  instead of calling the opener and replay store manually in every handler.
  `AxumError` now implements `IntoResponse`, mapping to a status code without
  ever echoing the source error's detail in the response body.
- **Raw-UDP datagram adapter.** `UdpDatagramTransport`
  (`foctet-transport/src/udp.rs`, `runtime-tokio` feature) implements the
  generic `DatagramTransport` trait over a connected `tokio::net::UdpSocket`,
  so `SecureDatagramChannel` works over plain UDP the same way it already
  does over QUIC datagrams. Verified with a real-socket roundtrip test.

### Added

- **Message transport shape: secure discrete-message channels (P1, §3.2).**
  Completes the transport-shape matrix (byte stream + datagram + message). New
  `foctet_core::message::MessageEndpoint` (`MessageConfig`, `DecodedMessage`,
  `DEFAULT_MAX_MESSAGE_SIZE` = 16 MiB) seals exactly one Foctet frame per
  *reliable, ordered, message-bounded* unit — the right shape for **raw
  WebSocket messages**, where each message is a discrete frame rather than a
  byte in an opaque stream. Unlike the datagram endpoint it is not MTU-bounded;
  unlike the byte-stream framing it preserves message boundaries with no length
  prefix or reassembly. Replay state is committed only after AEAD
  authentication, and per-`(key_id, stream_id)` sequence allocation fails closed
  on exhaustion. `foctet_transport` adds the generic `MessageTransport` trait
  (`!Send`-friendly for browser bindings) and `SecureMessageChannel<T>` that
  layers `MessageEndpoint` over any message backend, mirroring
  `DatagramTransport` / `SecureDatagramChannel`. Covered by core codec tests and
  an in-memory secure-channel roundtrip/replay/key-rotation test.
- **Centralized `ProtocolLimits` for the stream transports (P1, §2.4).** A new
  `foctet_core::limits::ProtocolLimits` gathers the DoS-relevant stream bounds
  (max inbound ciphertext length, retained previous keys, replay-window size,
  and the distinct-replay-window cap) that `FoctetFramed` and `SyncIo` had
  hardcoded as scattered magic numbers. Both expose `with_limits(...)` and a
  `limits()` accessor; the existing `with_max_ciphertext_len` /
  `with_max_retained_keys` setters now route through it. This also makes the
  replay-window size and window cap configurable on the stream paths for the
  first time (previously fixed at the defaults). Defaults are unchanged
  (`DEFAULT_MAX_CIPHERTEXT_LEN` = 16 MiB, `DEFAULT_MAX_RETAINED_KEYS` = 2,
  `DEFAULT_REPLAY_WINDOW`, `DEFAULT_MAX_REPLAY_WINDOWS`), so behavior is
  identical unless explicitly overridden. Datagram (`DatagramConfig`) and body
  (`BodyEnvelopeLimits`) keep their shape-specific limit types.
- **Generic datagram transport abstraction.** `foctet_transport::datagram`:
  a backend-agnostic `DatagramTransport` trait and `SecureDatagramChannel<T>`
  that layers the core datagram endpoint over any datagram backend.
  `quinn::Connection` implements `DatagramTransport` (verified over a real
  connection), so the same secure-datagram code path works for future
  WebTransport/UDP backends.

### Security

- **Secret-material hygiene for key types (P1, §2.5).** Long-term and traffic
  secrets no longer leak through `Debug` or non-constant-time comparison:
  - `TrafficKeys`, `EphemeralKeyPair`, `IdentityKeyPair`
    (`foctet-core`) and `HttpOpenOptions` (`foctet-http`) now have hand-written
    `Debug` impls that render secret bytes as `<redacted>` instead of the raw
    array, so a stray `{:?}` in application logs can no longer disclose a
    traffic key, ephemeral scalar, identity secret, or recipient secret key.
  - `TrafficKeys` and `IdentityKeyPair` equality is now **constant-time** over
    the secret bytes (via `subtle::ConstantTimeEq`), replacing the derived
    `PartialEq`/`Eq` that short-circuited on the first differing byte.
  - `HttpOpenOptions` stores the recipient secret in a `Zeroizing` wrapper so it
    is wiped on drop, and no longer derives `PartialEq`/`Eq`.
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
- **Breaking:** raw secret-key extraction is now explicitly named and zeroizing.
  `IdentityKeyPair::secret_key_bytes() -> [u8; 32]` is renamed to
  `expose_secret_key_bytes() -> Zeroizing<[u8; 32]>`, and
  `HttpOpenOptions::recipient_secret_key() -> [u8; 32]` to
  `expose_recipient_secret_key() -> Zeroizing<[u8; 32]>`. The `expose_` prefix
  makes secret extraction greppable, and the `Zeroizing` return type wipes the
  caller's copy on drop. Callers that need the raw array can dereference
  (`*opts.expose_recipient_secret_key()`).
