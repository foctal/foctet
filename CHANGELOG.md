# Changelog

All notable changes to this project are documented in this file.

## [0.3.0] - 2026-07-05

### Added

- **Centralized protocol limits expanded (P1, §2.4).** `ProtocolLimits` now
  also carries `max_plaintext_len` (enforced on every async/sync send path
  before encryption), `max_buffered_tx_bytes` (bounds the async framed
  transport's outbound queue; exceeding it fails with the new
  `CoreError::OutboundBufferLimitExceeded` instead of growing memory
  unboundedly — a rejected send consumes no sequence number), and
  `handshake_timeout` (the transport builders' `DEFAULT_HANDSHAKE_TIMEOUT` now
  aliases `foctet_core::DEFAULT_HANDSHAKE_TIMEOUT`). Control-plane input is
  hard-bounded by the new `MAX_CONTROL_MESSAGE_LEN` (rejected in
  `ControlMessage::decode` before inspection), and the distinct-inbound-stream
  bound via `max_replay_windows` is documented on the struct.

- **Connection-level handshake rate limiting (P1, §2.4).**
  `foctet_transport::HandshakeRateLimiter` — a shareable token bucket
  (sustained rate + burst) consulted before any handshake work; fails fast
  with the new `CoreError::HandshakeRateLimited`. Integrated convenience:
  `TokioTransportBuilder::establish_responder_with_auth_timeout_and_limiter`.
  Drop-cancellation semantics of all `establish_*` futures are now documented
  (`rate_limit` module docs).

- **In-session rekey over the WASM session API (P1, §5).** `FoctetSession`
  gains `forceRekey()` / `canRekey` / `handleControlMessage()` /
  `activeKeyId`: the alternating DH-ratchet rekey now runs over the wasm
  message *and* datagram modes (rekey control messages travel over the
  reliable channel; the framing endpoint adopts the rotated key and retains
  previous generations, so in-flight / reordered old-key frames still open).
  `Session::can_rekey()` accessor added in core. Tested natively and in
  headless Chrome.

- **Observability hooks without secrets (P2, §7).** New
  `foctet_core::observe` module: a `SessionObserver` trait receives
  `SessionEvent`s (`HandshakeCompleted`, `RekeyInitiated`, `RekeyApplied`,
  `ControlRejected`) carrying only public metadata — never key bytes or
  plaintext (`Session::with_observer` / `set_observer`). Replay-protection
  rejections are surfaced as counters (`ReplayProtector::rejections`,
  `replay_rejections()` on `FoctetFramed`, `SyncIo`, `MessageEndpoint`,
  `DatagramEndpoint`) for replay/flooding monitoring.

- **Independent (non-Rust) verification of the canonical vectors (P1/P2,
  §6/§7).** `interop/verify_vectors.mjs` re-implements the Draft v0 key
  schedule, frame AEAD (full XChaCha20-Poly1305 open with header-as-AAD, plus
  tamper negative controls), handshake transcript bindings, Ed25519 identity
  verification, and the DH-ratchet rekey step on the `@noble`
  libraries — zero shared code with the Rust workspace — and checks every
  committed vector. Runs in CI (`interop-verify` job), replacing the
  header-only `minimal_decoder` as the independent check.

- **Browser WebTransport datagram adapter (P1, §3.3).**
  `foctet_transport::webtrans_browser::BrowserWebTransportDatagrams`
  (`transport-webtrans-browser` feature, wasm32) implements
  `DatagramTransport` over a `WebTransport.datagrams` duplex handed in from
  JS, duck-typed via `js-sys` reflection (avoids web-sys's unstable-APIs cfg;
  clamps to the browser's `maxDatagramSize`). Verified in headless Chrome
  against in-page WHATWG streams end to end through
  `SecureDatagramChannel` (roundtrip both directions + oversize fail-closed);
  wasm build gated in CI.

- **Miri in CI (P2, §6).** New `miri` job runs the parser / state-machine /
  crypto-framing test modules of `foctet-core` (replay bitmap shifting,
  TLV/control/frame parsing, sequence allocation, AEAD framing) under Miri on
  nightly.

- **Out-of-order rekey negative test (P1, §2.6).** A `Rekey` naming the *next*
  expected `old_key_id` (skipping ahead, internally consistent binding) is
  rejected, session state is unchanged, and the genuine in-order rekey still
  applies (`session.rs::rekey_delivered_ahead_of_order_is_rejected_and_state_is_unchanged`).

- **Documentation hardening (P1/P2).** SPEC: version stamp
  (`foctet-spec/0.3-draft`, decoupled from crate versions), RFC 2119
  conformance language, normative §5.1.1 datagram MTU/path-change/
  fragmentation policy (no fragmentation, fail-closed, ≤1200-byte raw-UDP
  guidance), and the handshake outline promoted to normative (binding hash
  definitions in place of the "(draft)" markers). `ContextBinding::with_authority`
  now documents the required authority normalization steps; axum module docs
  give recommended body limits and streaming backpressure tuning; the
  WebSocket module documents its mux/backpressure contract; SECURITY.md
  finalizes the vulnerability-report channels, response SLA
  (ack ≤ 7 d / triage ≤ 14 d / fix or advisory ≤ 90 d), and scope.

- **Two-process transport examples + real-environment runbook (`tests.md`).**
  `quinn_split` and `websock_split` gained a `--role server|client|loopback`
  (plus `--addr`, `--tls-cert`/`--tls-key`, and a client `--wrong-identity` flag
  for the identity-mismatch negative test), so the QUIC and WebSocket adapters
  can be exercised across two processes / two hosts instead of only an in-process
  loopback. The axum body-echo client gained `--replay` (re-sends the identical
  sealed request to demonstrate the HTTP 409 replay rejection). `tests.md` is a
  step-by-step runbook with exact commands, expected output, and negative tests
  for every real-environment area; the verified flows (QUIC, WebSocket, axum
  replay, WASM browser) are marked as such.

### Fixed

- **Silent duplicate delivery from `AsyncSecureChannel::send_data` (P0).** The
  async send future re-encrypted and re-sent the same plaintext under the next
  sequence number every time the underlying transport flush returned
  `Poll::Pending`, so any backend whose flush can suspend (e.g. the multiplexed
  WebSocket adapter, which waits for a flush acknowledgement) delivered every
  payload two or more times. Because each duplicate carried a fresh valid
  sequence number it also passed replay protection. Backends whose flush
  completes immediately (in-memory duplex, quinn, muxtls, WebTransport) never
  exhibited it, which is why the in-process test suite stayed green. The send
  future now latches after enqueueing so the payload is encrypted exactly once.
  Caught by the new real-backend conformance suite; regression-tested with a
  suspending-flush mock (`secure_channel.rs::send_data_is_not_duplicated_when_flush_suspends`).

- **WASM session abort on `Instant::now()` (P1, §5).** Creating or rekeying a
  `Session` called `std::time::Instant::now()`, which aborts the module on
  `wasm32-unknown-unknown` (no monotonic clock). This crashed the WASM
  `FoctetSession` handshake at runtime even though native tests passed. The
  session now uses an internal monotonic-clock abstraction: native targets keep
  `std::time::Instant`; on `wasm32` the *age-based* rekey threshold is disabled
  (frame-count and byte-count thresholds still apply). Caught by the new
  in-browser harness; verified in Node and a real browser engine.

### Added

- **Threat model + operational policies documentation (P2, §7).** New
  `docs/THREAT_MODEL.md` (system/adversary model; defenses and residual risks
  for MITM, replay, reordering/truncation, rollback/downgrade, endpoint/relay/
  storage compromise, DoS, metadata leakage, key loss, and the WASM boundary;
  explicit non-goals) and `docs/POLICIES.md` (wire/profile/crate versioning
  and the Draft-v0 compatibility rules, the normative no-negotiation rule for
  v0, key lifecycle/rotation/backup guidance per key kind, and
  incident-response playbooks). SPEC §0/§3/§5.1 and SECURITY.md refreshed to
  match the shipped surface (Durable Object store, rekey-over-datagram,
  raw-UDP anti-amplification, WASM session, headless-browser CI) and to link
  the new documents.

- **Headless-browser test suite in CI (P1, §5).** New
  `foctet-wasm/tests/browser.rs` runs `wasm-bindgen-test` tests inside a real
  headless Chrome: body-envelope roundtrip, context-binding enforcement, the
  full authenticated `FoctetSession` handshake with bidirectional messages and
  replay rejection, and a datagram-mode roundtrip with wrong-mode rejection.
  Run locally with `wasm-pack test --headless --chrome foctet-wasm`; the new
  `wasm-browser-test` CI job runs it on every push/PR with the runner's
  version-matched Chrome + chromedriver. This closes the "browser-runner
  integration test in CI" gap (the browser harness page remains for manual
  runs and Rust→JS interop).

- **Fuzzing in CI with a seeded corpus + time budget (P1, §6).** New
  `.github/workflows/fuzz.yml` runs all seven fuzz targets weekly (and on
  manual dispatch with an adjustable budget) under a per-target libFuzzer time
  budget, uploading crash artifacts on failure. Seed inputs live in
  `fuzz/seeds/<target>/` — valid frames, envelopes, archives, and control
  messages generated by the new `gen_fuzz_seeds` example with the same fixed
  keys the targets hard-code, so AEAD-open/key-unwrap paths are exercised from
  the first execution.

- **Real-backend byte-stream conformance tests (P1, §3.1).** The shared
  conformance suite (`foctet-transport/tests/conformance.rs`) now also runs over
  a real loopback connection for every advertised byte-stream backend — QUIC
  bidirectional streams (quinn), WebTransport bidirectional streams, muxtls, and
  multiplexed WebSocket (websock-mux) — each brought up with a self-signed
  localhost certificate and the native Foctet handshake. This closes the "run
  the shared suite against every advertised byte-stream backend" gap and is what
  exposed the duplicate-send bug above.

- **In-browser WASM runtime harness (P1, §5).**
  `foctet-wasm/examples/browser/index.html` exercises the SDK in a real browser
  engine: body-envelope roundtrip, context binding, Rust→JS wire compatibility
  (the same `interop_vector.json` fixture as the Node test), and a full in-page
  `FoctetSession` authenticated handshake + message exchange. Serve via
  `npm run browser` (builds `pkg-web/` and starts a static server). Documented in
  `tests.md` as the manual browser real-environment test pending a headless CI
  runner.

### Deprecated

- **Stateless full-HTTP-request seal/open APIs (P0, §1.3).** The body-only
  helpers that protect a whole HTTP *request* without replay defense or
  HTTP-context binding are now `#[deprecated]` (since 0.3.0) in favor of the
  context-bound path. A captured request sealed with these is replayable by
  design. Affected: `HttpSealer::seal_request`, `HttpOpener::open_request`,
  `raw::{seal,open}_http_request[_with_limits]`, `AxumOpener::open_request` and
  `open_axum_request_body[_with_limits]`, and `WorkersOpener::open_request` with
  `open_worker_request[_with_limits]`. Migrate to
  `seal_request_with_context` / `open_request_with_context` (or the Axum/Workers
  `*_with_context` adapters) backed by a `ReplayStore`. The lower-level
  `seal_body` / `open_body` primitives are unchanged for callers that supply
  their own context and anti-replay.

### Added

- **More fuzz targets + a transport support matrix (P1, §6/§3.1).** New fuzz
  targets cover the untrusted-input parsers beyond `frame`/`archive`:
  `control_message`, `handshake` (the state machine fed arbitrary control
  messages), `body_envelope`, `stream_body` (streaming header + incremental
  decoder), and `datagram_message` (datagram/message frame open). The README gains
  a **Transport Support Matrix** documenting each adapter's shape, API, feature
  flag, native/browser availability, and what verifies it.
- **Unified `SecureChannel` shape trait + conformance suite (P1, §3.1/§3.2).**
  The three transport shapes now share one application contract: the new
  `foctet_transport::SecureChannel` trait (`send_payload`/`recv_payload`) is
  implemented by the byte-stream channels (`TokioTransportChannel`,
  `FuturesTransportChannel`), `SecureMessageChannel`, and
  `SecureDatagramChannel`, so generic code runs over any shape. A
  `ByteStreamTransport` marker names the byte-stream shape alongside
  `MessageTransport` / `DatagramTransport`. A shared conformance suite
  (`tests/conformance.rs`) runs the same checks (bidirectional round trip,
  ordering, larger payload) against all three shapes, keeping them behaviourally
  consistent.
- **Turn-key streaming-body framework wiring (P1, §4).** `foctet_core::StreamFrameDecoder`
  (+ `StreamItem`) reassembles a streaming body's self-delimiting frames from
  arbitrarily split byte chunks, so the stream works over any byte transport. On
  top of it, `foctet_http::HttpRequestStreamReader` is a framework-agnostic,
  push-based reader that validates the protected context (freshness + single-use
  replay) when the header arrives and yields decrypted plaintext chunks, with
  `finish()` rejecting a truncated/cancelled upload (new `HttpError::StreamIncomplete`).
  `foctet_http::axum::open_request_stream` drives it directly from an axum request
  body (a callback per plaintext chunk, no whole-body buffering); Cloudflare
  Workers use the same reader over a `ReadableStream`.
- **Canonical DH-ratchet rekey test vector (P1, §2.3).** `test-vectors/rekey-v0.json`
  captures one deterministic ratchet step (`derive_ratchet_root` then
  `dh_ratchet_step`), generated by `gen_vectors` and regression-checked by
  `test_vectors::rekey_ratchet_vector_matches`, so the in-session rekey key
  schedule (HKDF labels and wiring) cannot change without an explicit, reviewed
  vector update — a fixed compatibility reference for future changes.
- **Browser (Rust/wasm) WebSocket message transport (P1, §3.4).**
  `WebsockMessageTransport` is now generic over the `websock` crate's
  cross-platform `WebSocketConnection` trait, so the same adapter drives a
  `SecureMessageChannel` over both the native (`websock-tungstenite`) connection
  and the **browser** (`websock-wasm`) `WebSocket` — a Rust/wasm front-end needs
  no JavaScript glue. The `transport-websock` feature was split into the
  cross-platform `transport-websock` (raw message transport, wasm-compatible) and
  the native-only `transport-websock-mux` (multiplexed byte-stream helpers, Tokio
  runtime); `foctet-transport` now compiles for `wasm32-unknown-unknown` under
  `transport-websock`, and CI gates that build. **Breaking:** the multiplexed
  `*_secure_channel*` helpers now require the `transport-websock-mux` feature.
- **Rekey over datagrams (P1, §3.3).** `SecureDatagramChannel::rekey_from_session`
  (and the message channel's equivalent) adopts a session's rotated DH-ratchet
  key after the rekey completes over a reliable control channel — the QUIC-style
  separation where key updates ride a reliable stream and data rides datagrams.
  Because each key has a `key_id` and the datagram endpoint retains previous
  keys, an old-key datagram that arrives reordered or delayed *after* a rekey
  still decrypts (verified by a cross-rekey reordering test). The datagram module
  documents the flow.
- **Streaming (chunked) HTTP bodies (P1, §4).** New `foctet_core::body_stream`
  (`StreamSealer` / `StreamOpener`) seals a body as an ordered sequence of
  per-chunk-authenticated frames instead of one buffered envelope: one
  ECIES-wrapped content key per stream, a unique `prefix||index` nonce per chunk,
  and AAD binding the stream header, chunk index, a flags byte, and the caller
  context. Exactly one authenticated `FINAL` chunk provides truncation/extension
  resistance (`is_finished()` must be `true` to accept the stream), sequential
  indices reject reorder/gap/duplicate, and an aborted stream simply never
  finalizes (safe cancellation). `foctet_http::stream::{HttpStreamSealer,
  HttpStreamOpener}` wraps it with the HTTP protected context plus freshness and
  single-use replay enforcement (the message id is consumed once per stream).
- **Channel binding in the WASM `AuthConfig` (P1, §2.1/§5).** `foctet-wasm`'s
  `AuthConfig` gains `boundToChannel(channelBinding)` (no Foctet identity; MITM
  resistance from an authenticated outer channel) and `withChannelBinding(..)`
  (additive to any config), so browser/JS `FoctetSession`s get the same
  transcript channel binding as native sessions.
- **Opt-in anti-amplification for the raw-UDP datagram adapter (P1, §3.3).**
  `UdpDatagramTransport::with_anti_amplification(factor)` (with
  `DEFAULT_AMPLIFICATION_FACTOR` = 3, matching QUIC) refuses to send once the
  cumulative bytes sent would exceed `factor ×` the bytes received from an
  unvalidated peer (returning `io::ErrorKind::WouldBlock`), so a spoofed source
  address cannot turn the endpoint into a reflector/amplifier.
  `mark_peer_validated()` lifts the limit once the peer proves it can receive
  (e.g. when the Foctet handshake over the path completes). Off by default, so
  existing behavior is unchanged; counters are atomic and shared across clones.
- **Pluggable handshake signer for hardware-backed identities (P1, §2.5).** New
  `HandshakeSigner` trait (`public_key()` + `sign()`, `Send + Sync`) is the seam
  for non-extractable long-term identity keys — implement it for an HSM, cloud
  KMS, TPM, or OS keystore so the Ed25519 private key never enters process
  memory. `IdentityKeyPair` implements it for the in-process case;
  `SessionAuthConfig::with_local_signer(..)` accepts any signer, and
  `with_local_identity(..)` is unchanged. **Breaking:** `SessionAuthConfig` now
  stores `Option<Arc<dyn HandshakeSigner>>` and no longer derives `Eq`/`PartialEq`
  (its `Debug` shows only the signer's public key); `HandshakeAuth::sign` takes
  `&dyn HandshakeSigner` (an `&IdentityKeyPair` argument still coerces);
  `SessionAuthConfig::local_identity()` is replaced by `local_signer()` /
  `local_identity_public_key()`.
- **Typed authenticated-peer result (P1, §2.1).** `Session::authenticated_peer()`
  returns an `Option<AuthenticatedPeer>` naming the peer's verified Ed25519
  identity public key — the typed counterpart to the `peer_authenticated()`
  boolean. `AuthenticatedPeer` exposes `identity_public_key()` and a
  constant-time `matches(&PeerIdentity)`. A handshake authenticated only by a
  `ChannelBinding` (no Foctet identity) returns `None`, since no peer identity
  was proven.
- **Channel binding to an authenticated outer channel (P1, §2.1).** New
  `ChannelBinding` + `SessionAuthConfig::bound_to_channel(..)` /
  `with_channel_binding(..)` (`foctet-core`). The binding value (e.g. a TLS
  exporter per RFC 5705) is folded into the handshake transcript hash on both
  sides, so a man-in-the-middle that terminates the outer channel and relays the
  Foctet handshake computes a different transcript and fails closed — letting an
  authenticated outer channel substitute for a Foctet Ed25519 identity.
  `bound_to_channel` is the typed, production-named alternative to
  `unauthenticated_for_testing`. The transcript is byte-identical to before when
  no binding is set (an extra length-prefixed, domain-separated hash input only;
  no change to key derivation, the AEAD, or signatures), and the binding flows
  through the transport builders automatically.
- **Framed Foctet session over WebAssembly (P1, §5).** `foctet-wasm` now exposes
  `FoctetSession` — the full authenticated handshake plus ordered,
  replay-protected per-message `sealMessage`/`openMessage` — not just the
  one-shot body envelope. WebAssembly performs the cryptography and handshake
  state machine while the JS side owns the transport (a browser `WebSocket`,
  `WebTransport` stream, or datagram channel), exchanging `Uint8Array` blobs.
  Adds `IdentityKeyPair` (Ed25519), `AuthConfig` (pinned-peer `authenticated` or
  explicit `unauthenticatedForTesting`), and `DecodedMessage`. The handshake
  fails closed against an unexpected peer. Inner logic is native-tested; the
  `wasm32-unknown-unknown` build is verified. In-session rekey is not yet carried
  over this message API.
  - A session can run in **message mode** (`newInitiator`/`newResponder`,
    `sealMessage`/`openMessage` — reliable WebSocket / WebTransport stream) or
    **datagram mode** (`newDatagramInitiator`/`newDatagramResponder`,
    `sealDatagram`/`openDatagram` — MTU-bounded WebTransport datagrams via
    `DatagramEndpoint`, configurable `maxDatagramSize`). A session is locked to
    one mode so the two framings can never share a `(key_id, stream_id)` nonce
    space.
- **Raw-WebSocket message transport (P1, §3.4).** `WebsockMessageTransport`
  (`foctet-transport`, `transport-websock`) implements `MessageTransport` over a
  `websock` crate connection, carrying exactly one Foctet frame per **binary**
  WebSocket message — the first concrete `MessageTransport` backend beyond the
  in-memory test double. Pair it with `SecureMessageChannel`. Verified by a real
  plain-WebSocket loopback roundtrip test.
- **Runtime-agnostic handshake timeout (P1, §2.4).**
  `FuturesTransportBuilder::establish_initiator_with_auth_and_timeout` /
  `establish_responder_with_auth_and_timeout` bound the native handshake by a
  caller-supplied timer *future* (e.g. `tokio::time::sleep`, an async-io timer, a
  browser timer), racing it against the handshake with a `std`-only `poll_fn` and
  failing with `CoreError::HandshakeTimeout`. This gives the futures path parity
  with the existing Tokio `Duration`-based timeout.

### Changed

- **Rekey is now a forward-secret DH ratchet (P1, §2.3).**
  In-session rekey no longer re-derives keys from the one handshake shared secret
  (which gave no post-compromise security). Each rekey performs a Diffie-Hellman
  ratchet step: the rekeying side generates a fresh ephemeral X25519 key, mixes
  `X25519(new_ephemeral, peer_ratchet_public)` into a root-key chain
  (`derive_ratchet_root` / `dh_ratchet_step`), and the handshake shared secret is
  discarded after seeding the root. Rekeys **alternate** between the peers
  (enforced by a turn flag: out-of-turn `force_rekey` returns the new
  `CoreError::RekeyNotPermitted`; threshold-driven rekey defers instead of
  failing), so the root chain cannot fork and both peers' keys rotate — giving
  forward secrecy and, across an alternating rekey, post-compromise security in
  both directions. **Breaking:** the `Rekey` control message carries
  `ratchet_public` instead of `rekey_salt`; `derive_rekey_traffic_keys` is removed
  in favor of `derive_ratchet_root` + `dh_ratchet_step`.
- **`TrafficKeys` is now non-`Clone`; share keys via `KeyHandle` (P1, §2.5).**
  Traffic-key secret bytes now exist in exactly one place and are zeroized when
  it drops, instead of being copied into every owner. Shared ownership goes
  through the new `KeyHandle` (`Arc<TrafficKeys>`): it derefs to `TrafficKeys`,
  clones cheaply (refcount only), and delegates `Debug`/`Eq` to the redacted,
  constant-time `TrafficKeys` impls. **Breaking:** `Session::active_keys()` /
  `active_and_previous_keys()` / `key_ring()` now return `KeyHandle`(s), and the
  endpoint constructors (`FoctetFramed::new` / `SyncIo::new` / `from_tokio` /
  `from_futures`, `MessageEndpoint::{new,with_config}`,
  `DatagramEndpoint::{new,with_config}`) and `install_active_keys` take a
  `KeyHandle`. Wrap a freshly derived key set with `KeyHandle::new(..)` (or
  `.into()`). The transport `SecureMessageChannel`/`SecureDatagramChannel` and
  quinn adapters' `install_active_keys` take `KeyHandle` to match.
- **CI release-hardening gates (P1, §6).** The Rust workflow now enforces
  `cargo fmt --all -- --check`, runs `cargo test --workspace --all-features
  --locked`, adds an MSRV job (`rust-version = "1.88"`, declared on every
  published crate) and a `cargo-deny` license/source/advisory job (`deny.toml`),
  and pins all third-party actions to immutable commit SHAs. Every cargo
  invocation now passes `--locked` for reproducible builds.
- **Documentation accuracy (P1, §1.3).** `README.md` and `SECURITY.md` were
  corrected to match the shipped surface — datagram (QUIC + raw-UDP), the
  `foctet-wasm` body-envelope SDK, and the HTTP protected-context + durable
  (Redis) replay layer are now described as implemented, with the remaining gaps
  (browser-WebTransport datagram, Cloudflare KV/Durable Object store, npm
  publish) stated explicitly.

### Security

- **Patch dependency advisories (§6).** Bumped `quinn-proto` → 0.11.15
  (RUSTSEC-2026-0037, endpoint DoS), `rkyv` → 0.8.16 (RUSTSEC-2026-0122,
  use-after-free in `*::clear`), and `rustls-webpki` → 0.103.13
  (RUSTSEC-2026-0049 / -0098 / -0099 / -0104, CRL/name-constraint flaws). The
  dev-only, unmaintained `rustls-pemfile` advisory (RUSTSEC-2025-0134, no safe
  upgrade) is explicitly tracked in `deny.toml`.

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
