# Foctet — Road to Production-Ready

Tracking document for taking Foctet from **Draft v0 / experimental** to a
**stable, independently reviewed, general-purpose production E2EE SDK** that can
protect arbitrary TCP/UDP/QUIC/WebSocket/WebTransport payloads, HTTP bodies
(axum, Cloudflare Workers), and files.

- Source of requirements: `REVIEW.md` (production-readiness review,
  2026-06-22) + `SPEC.md`.
- Legend: `[x]` done · `[ ]` not started · `[~]` partial.
- Priorities follow the review: **P0** (release-blocking), **P1** (required for
  v1), **P2** (hardening / scope clarity).
- "Done" means: implemented, documented, **and** covered by tests.

---

## 0. Current state (snapshot)

**Implemented & tested surface today:**

- Stream-oriented authenticated framing (`foctet-core`): `FoctetFramed` (async,
  tokio/futures) and `SyncIo` (blocking), profile `0x01`
  (X25519 + HKDF-SHA-256 + XChaCha20-Poly1305), header-as-AAD.
- Native handshake + symmetric rekey state machine (`session.rs`), Ed25519
  identity auth with pinned peer (`auth.rs`).
- Replay windows per `(key_id, stream_id)` (`replay.rs`).
- One-shot `application/foctet` body envelope (`body.rs`) + optional context
  binding.
- Encrypted archives, single & split (`foctet-archive`).
- HTTP body adapters for axum + Workers (`foctet-http`), whole-buffer.
- Transport helpers for quinn / webtransport / websocket / muxtls
  (**bidirectional streams only**).
- Vectors, property tests, 2 fuzz targets, and CI (Clippy, default-feature
  workspace tests, wasm check, advisory scan).

**Recently fixed (see `CHANGELOG.md` → Unreleased):**

- [x] **P0** SyncIo nonce reuse on sequence exhaustion → fail-closed.
- [x] **P1** Replay state committed only after AEAD authentication (all paths).
- [x] **P1** Native handshake authenticated-by-default (explicit opt-in for
  unauthenticated).
- [x] **P2** Bounded replay-window map.
- [x] Body-envelope context-binding primitive (`*_with_context`).
- [x] `SECURITY.md`; README/SPEC claims corrected.
- [x] **2026-07 implementation batch:** `ProtocolLimits` completed (plaintext /
  buffered-tx / control-size / handshake-timeout / distinct-stream bounds),
  handshake rate limiting + cancellation docs, WASM in-session rekey,
  observability hooks + replay counters, browser-WebTransport datagram
  adapter (headless-Chrome tested), independent `@noble`-based vector
  verification in CI, Miri CI job, out-of-order-rekey negative test, and a
  docs batch (normative SPEC pass + `foctet-spec/0.3-draft` stamp, datagram
  MTU policy, authority normalization, body-limit/backpressure guidance,
  WebSocket mux/backpressure contract, SECURITY response SLA).

**Not production-ready until every P0 and P1 below is `[x]` and externally
reviewed.** Do not use "production-ready" / "v1 stable" wording before
§8 release gates are all green.

---

## 1. P0 — Release-blocking

### 1.1 Synchronous nonce reuse — **DONE**
- [x] `SyncIo::send_with_key` uses `checked_add` → `SequenceExhausted`
      (`foctet-core/src/io.rs`).
- [x] Regression test at counter near `u64::MAX` proving no wrapped frame
      emitted (`io.rs::sync_send_fails_closed_on_sequence_exhaustion`).
- [x] Follow-up: unify sequence allocation into one shared internal type so sync
      and async cannot diverge again (`OutboundSequence` is also used by the
      datagram and message endpoints).

### 1.2 HTTP body envelopes — replay protection & HTTP-context binding
Core schema + replay store + axum integration done; durable store + default-
enforcement remain.
- [x] Core AEAD context primitive: `seal_body_with_context` /
      `open_body_with_context` / `open_body_for_key_id_with_context`.
- [x] **Versioned HTTP protected-context schema** (canonical, length-delimited,
      domain-separated `foctet-http-ctx-v1`) in `foctet-http/src/context.rs`,
      authenticating:
  - [x] protocol label + version + direction (request vs response)
  - [x] method, path, query (authority opt-in via `ContextBinding`)
  - [x] response status (responses)
  - [x] timestamp + expiry with clock-skew validation
  - [x] cryptographically random 16-byte message ID
  - [x] optional idempotency key; response→request message-id binding
  - [x] selected-header binding, **requests only**: `ContextBinding::with_bound_headers`
        (`foctet-http/src/context.rs`) authenticates the presence and raw value
        bytes of named headers; absent headers are bound too, so removing one
        also fails authentication. Purely additive — empty by default,
        byte-identical AAD to before when unused. Responses not covered yet
        (`ProtectedContext::for_response` doesn't take a `ContextBinding`;
        threading one through would mean changing `seal_response_with_context`
        / `open_response_with_context` and their Axum/Workers wrappers).
- [x] Build context bytes from `http::Request`/`Response` parts and feed through
      `*_with_context` (`HttpSealer::seal_request_with_context` /
      `HttpOpener::open_request_with_context`, + response variants).
- [x] **`ReplayStore` trait** with atomic check-and-insert + `ReplayCheck`;
      `InMemoryReplayStore` (TTL eviction + capacity bound).
- [x] Authenticate-before-replay ordering (store consulted only after AEAD).
- [x] Axum adapter: `AxumOpener::open_request_with_context`,
      `AxumSealer::seal_response_with_context` (body bounded by `max_body_bytes`).
- [x] Tests: replay rejected, route substitution rejected, expired rejected,
      response roundtrip, carrier header roundtrip, store capacity/eviction.
- [x] **Async/durable store interface:** `AsyncReplayStore` trait (`!Send`-friendly
      for Workers) + blanket impl over sync `ReplayStore`; async opener path
      (`HttpOpener::open_request_with_async_store`, `AxumOpener` variant).
- [x] **Redis durable backend** (`RedisReplayStore`, `redis` feature) via atomic
      `SET NX PX`; compile-checked (needs a live Redis to run).
- [x] Cloudflare Durable Object adapter. **Done** (`foctet-http/src/workers.rs`,
      `workers` feature): `DurableObjectReplayStore` implements `AsyncReplayStore`
      by routing each message ID to its own deterministically-named Durable
      Object; the DO's single-threaded, strongly-consistent storage makes the
      read-then-write atomic, so exactly one concurrent request gets `201` and
      replays get `409`. The DO class delegates to
      `check_and_insert_in_durable_object` (fetch handler) and
      `expire_durable_object_replay_entry` (alarm handler, deletes the one
      retained entry at expiry). Raw KV is intentionally NOT used: `get`-then-`put`
      has no conditional/NX write and would reintroduce a replay race. Verified by
      the `wasm32-unknown-unknown` workers build in CI (no live Wrangler run).
- [~] Make context-bound APIs the **enforced default**; consider deprecating the
      stateless `seal_request`/`open_request` for production use. **Done:** the
      stateless full-request family is `#[deprecated]` (see §1.3). **Still open:**
      a hard enforcement (removing the stateless full-request constructors, or
      gating them behind an explicit `allow-stateless` opt-in) is deferred to the
      API-freeze decision so downstream callers get a deprecation cycle first.
- [x] Workers adapter parity (`WorkersOpener::open_request_with_context` /
      `open_request_with_async_store`, `WorkersSealer::seal_response_with_context`
      in `foctet-http/src/workers.rs`), reconstructing `http::request::Parts`
      (method/URI/headers) from `worker::Request` so the same protected-context
      binding used by Axum applies to Workers.
- [x] Optional selected-header binding + authority normalization guidance.
      Header binding done for requests (see §1.2 above); authority
      normalization guidance now documented on
      `ContextBinding::with_authority` (`foctet-http/src/context.rs`):
      lowercase host, punycode form, default-port stripping, and
      server-side reconstruction source — with the explicit recommendation to
      leave the binding off when those can't be guaranteed.
- **Gate:** block production HTTP/Workers recommendations until durable store +
  default-enforcement land.

### 1.3 Production-safe API and documentation defaults
- [x] Make protected-context + atomic durable replay protection the clearly
      recommended and difficult-to-misuse HTTP production path; retain
      stateless APIs only with explicit replayability documentation or a
      deliberate API-surface decision. **Done:** the stateless full-request
      family is now `#[deprecated]` (since 0.3.0) pointing at the `*_with_context`
      path — `HttpSealer::seal_request` / `HttpOpener::open_request`,
      `raw::{seal,open}_http_request[_with_limits]`, `AxumOpener::open_request` +
      `open_axum_request_body[_with_limits]`, and `WorkersOpener::open_request` +
      `open_worker_request[_with_limits]`. The lower-level `seal_body`/`open_body`
      primitives stay (documented as caller-supplies-own-context). Module docs
      now label the two protection levels.
- [x] Correct README/SECURITY deployment claims: datagram and body-envelope WASM
      support now exist, while their adapter/operational limitations remain.
      Also describe the implemented HTTP protected-context/replay layer and its
      durable-store requirement accurately. **Done:** README header + "What
      Foctet Covers" + Security Notes and SECURITY.md status/known-limitations
      rewritten to match the shipped surface (datagram/UDP, WASM SDK, HTTP
      protected context + Redis durable store), and to call out the remaining
      gaps (browser-WebTransport datagram, Cloudflare KV/DO store, npm publish,
      independent review).

---

## 2. P1 — Required for v1 (protocol & core)

### 2.1 Native handshake authentication — **DONE (revisit at API-freeze)**
- [x] Fail-closed default; explicit `unauthenticated_for_testing()` /
      `allow_unauthenticated()`.
- [x] Downgrade/MITM negative tests (`session.rs`).
- [x] All transport convenience helpers route through explicit opt-in.
- [x] Introduce a typed `ChannelBinding` abstraction so an outer-channel binding
      (e.g. TLS exporter / channel id) can substitute for Foctet identity auth,
      instead of the current boolean opt-in. **Done** (`foctet-core/src/auth.rs`,
      `session.rs`): `ChannelBinding` + `SessionAuthConfig::bound_to_channel(..)`
      (typed, production-named alternative to `unauthenticated_for_testing`) and
      `with_channel_binding(..)` (additive to identity auth). The binding is
      folded into the handshake transcript hash (`client_hello_binding` /
      `server_hello_binding`) length-prefixed under a domain separator, so a
      relay across a different outer channel fails closed; it is byte-identical
      to before when no binding is set (existing vectors unchanged — extra hash
      input only, no KDF/AEAD/signature change). Tests: matching binding
      completes an identity-less handshake, mismatch fails, one-sided fails,
      binding strengthens an identity-authenticated handshake. Flows through the
      transport builders automatically (they already take `SessionAuthConfig`).
      Typed `AuthenticatedPeer` result type **done**:
      `Session::authenticated_peer() -> Option<AuthenticatedPeer>` returns the
      verified Ed25519 identity public key (typed form of `peer_authenticated()`;
      `None` for a channel-binding-only handshake since no peer *identity* was
      proven). `AuthenticatedPeer` exposes `identity_public_key()` +
      `matches(&PeerIdentity)` (constant-time). Tested. Channel binding is now
      also surfaced through the WASM `AuthConfig`
      (`AuthConfig.boundToChannel(..)` and `.withChannelBinding(..)` in
      `foctet-wasm`, tested). **Done.**
- [ ] Consider removing/renaming the no-auth transport convenience constructors
      at API-freeze (currently they call `unauthenticated_for_testing()`).

### 2.2 Replay state after authentication — **DONE**
- [x] Reordered in `io.rs` (`recv`, `recv_application_with_session`) and
      `frame.rs::try_decode`.
- [x] Forged-high-sequence-then-valid regression tests (sync + async).

### 2.3 Rekey vs post-compromise security — **DH ratchet implemented (review pending)**
- [x] Target decided + implemented: an authenticated **ephemeral-DH ratchet**
      replaces symmetric rekey. SPEC §3.2/§7.1.2, SECURITY.md, README updated to
      describe FS + alternating-PCS honestly with the review caveat.
- [x] Fresh forward-secret DH step per rekey: `force_rekey` generates a fresh
      ephemeral, `dh = X25519(new_eph, peer_ratchet_pub)`, advanced via
      `crypto::dh_ratchet_step` (`HKDF(salt=root, ikm=dh)` → new root + c2s/s2c);
      root seeded by `derive_ratchet_root`. `Rekey` control carries
      `ratchet_public` (replaces `rekey_salt`); handshake shared secret is no
      longer retained.
- [x] Transcript binding + concurrency/collision rules: `rekey_binding` binds
      `ratchet_public`; rekeys **alternate** via a `can_rekey` turn flag (only the
      side whose turn it is may initiate; out-of-turn → `RekeyNotPermitted`;
      threshold-driven rekey defers instead of failing), so the root chain cannot
      fork and both sides' keys rotate. Receiver rejects bad `old_key_id`,
      non-sequential `new_key_id`, or a mismatched binding. Tested
      (`dh_ratchet_alternates_and_rotates_both_sides_keys`,
      `rekey_with_a_jumped_new_key_id_is_rejected`, replayed/stale/forged).
- [~] Out-of-order rekey delivery + vectors: the control channel is ordered
      (stream), so in-order is assumed and enforced by the turn flag; datagram
      delivery is out of scope here (see §3.3 rekey-over-datagram). Canonical
      ratchet **test vectors** added: `test-vectors/rekey-v0.json` (one
      deterministic `derive_ratchet_root` + `dh_ratchet_step` step), generated by
      `gen_vectors` and regression-checked by `test_vectors::rekey_ratchet_vector_matches`
      + schema-checked, so the rekey key schedule (HKDF labels/wiring) cannot
      silently change. **Still open:** out-of-order *delivery* handling only
      becomes relevant once rekey rides datagrams.
- [ ] **Independent cryptographic review** of this ratchet **before** the PCS
      guarantee is claimed for high assurance (the one remaining gate; the
      construction is the alternating DH-ratchet, not improvised per-message).

### 2.4 Centralized protocol limits (P2 in review, do early)
- [x] One public `ProtocolLimits`. **Done** for the stream shape, now covering
      every bound the review asked for: max inbound ciphertext length,
      **max outbound plaintext length** (`max_plaintext_len`, enforced on every
      async/sync send path before encryption), **buffered outbound bytes**
      (`max_buffered_tx_bytes`, bounds `FoctetFramed`'s `tx` queue — exceeding
      it fails with `CoreError::OutboundBufferLimitExceeded` and consumes no
      sequence number), retained previous keys, replay-window size, the
      distinct-replay-window cap (which is also the documented bound on
      **distinct inbound stream IDs**, one window per `(key_id, stream_id)`),
      and the **handshake deadline** (`handshake_timeout`;
      `foctet_transport::DEFAULT_HANDSHAKE_TIMEOUT` aliases
      `foctet_core::DEFAULT_HANDSHAKE_TIMEOUT`). **Control-message size** is
      hard-bounded by `MAX_CONTROL_MESSAGE_LEN`, rejected in
      `ControlMessage::decode` before inspection. All defaults documented;
      tests for enforcement + no-nonce-consumed-on-reject.
- [~] Apply consistently. `FoctetFramed` + `SyncIo` take `with_limits(...)` /
      expose `limits()`; plaintext/tx bounds enforced on all their send paths.
      **Still open (deliberate):** datagram (`DatagramConfig`) and HTTP/body
      (`BodyEnvelopeLimits`) keep their own shape-specific limit types
      (different in kind — MTU-bounded / whole-buffer); archive APIs not wired.
- [x] Replay-window count cap (`DEFAULT_MAX_REPLAY_WINDOWS`) — first piece, now
      configurable on the stream paths via `ProtocolLimits::max_replay_windows`.
- [x] Bound outbound plaintext/frame length before `u32` ct_len conversion
      (`crypto::checked_ciphertext_len` in `foctet-core/src/crypto.rs`,
      shared by `encrypt_frame`, used by every sync/async send path).
      Still pending: the broader `ProtocolLimits` unification above.
- [x] Handshake read **timeout** + connection-level rate limit + cancellation.
      Timeout done for the Tokio path: `TokioTransportBuilder::establish_*_with_timeout`
      / `establish_*_with_auth_and_timeout` / `establish_*_with_default_timeout`
      (`DEFAULT_HANDSHAKE_TIMEOUT` = 10s) in `foctet-transport/src/tokio.rs`,
      using `tokio::time::timeout` and a new `CoreError::HandshakeTimeout`;
      `quinn`/`websock`/`webtrans`/`muxtls` all build on this builder so they
      gain it once their call sites switch to the timeout variants. The
      runtime-agnostic `FuturesTransportBuilder` has parity via
      `establish_initiator_with_auth_and_timeout` /
      `establish_responder_with_auth_and_timeout` (caller-supplied timer
      future raced against the handshake; stalled-handshake tests). **Rate
      limit done:** `foctet_transport::HandshakeRateLimiter`
      (`rate_limit.rs`) — a shareable token bucket (sustained rate + burst)
      consulted before any handshake work, failing fast with
      `CoreError::HandshakeRateLimited`; integrated via
      `establish_responder_with_auth_timeout_and_limiter`; tested (burst,
      refill, shared bucket, clamping). **Cancellation done:** all
      `establish_*` futures are drop-cancellable (state lives in the future);
      documented in the `rate_limit` module docs.

### 2.5 Key-material ergonomics
- [x] Make secret-bearing types non-`Clone` where practical; zeroizing wrappers.
      Secret-leak hardening done: `TrafficKeys`, `EphemeralKeyPair`,
      `IdentityKeyPair` (`foctet-core`) and `HttpOpenOptions` (`foctet-http`)
      redact secret bytes in `Debug`; `TrafficKeys`/`IdentityKeyPair` equality is
      constant-time via `subtle::ConstantTimeEq`; `HttpOpenOptions` keeps its
      recipient secret in a `Zeroizing` wrapper. **Done:** `TrafficKeys` is now
      **non-`Clone`** — the secret key bytes exist in exactly one place and are
      zeroized when it drops. Shared ownership goes through a new
      `KeyHandle(Arc<TrafficKeys>)` (`Deref<Target=TrafficKeys>`, cheap `Clone`
      that only bumps the refcount, `Debug`/`Eq` delegate to the redacted /
      constant-time `TrafficKeys` impls). The session key ring + `previous_keys`,
      and the stream/sync (`FoctetFramed`/`SyncIo`), datagram, and message
      endpoints now all hold `KeyHandle`s instead of owned `TrafficKeys` copies;
      `Session::active_keys()`/`key_ring()` and the endpoint
      `new`/`with_config`/`install_active_keys` APIs take/return `KeyHandle`
      (downstream-visible). Verified: full workspace tests + clippy + wasm +
      rustdoc + cargo-deny all green.
- [x] Stop returning raw secret-key byte copies.
      `IdentityKeyPair::secret_key_bytes()` → `expose_secret_key_bytes()` and
      `HttpOpenOptions::recipient_secret_key()` → `expose_recipient_secret_key()`
      now return `Zeroizing<[u8; 32]>` (wiped on drop) under an `expose_`-prefixed,
      greppable name. The internal `key_for`-style raw copies are immediately
      wrapped in `Zeroizing` at the AEAD call sites (`crypto.rs`).
- [x] Key-provider / keystore abstraction: separate key *handles* from bytes;
      optional hardware-backed path. **Done in two parts:** (1) traffic keys are
      shared by `KeyHandle` (refcount, secret bytes single-owner, see above);
      (2) the long-term **identity** signing is now behind a `HandshakeSigner`
      trait (`public_key()` + `sign()`, `Send + Sync`, never exposes key bytes).
      `IdentityKeyPair` implements it for the in-process case;
      `SessionAuthConfig::with_local_signer(..)` accepts any signer (HSM, cloud
      KMS, TPM, OS keystore) while `with_local_identity(..)` is unchanged for the
      software path. `SessionAuthConfig` now stores `Option<Arc<dyn
      HandshakeSigner>>` (dropped its unused `Eq`/`PartialEq` derives, hand-wrote
      a `Debug` that shows only the signer's public key); `HandshakeAuth::sign`
      takes `&dyn HandshakeSigner` (existing `&IdentityKeyPair` callers coerce).
      Verified end-to-end by an external-signer handshake test. **Still open
      (optional):** key IDs with an explicit rotation *policy* type (rotation
      itself works via the rekey state machine).
- [x] Document that session state MUST NOT be restored with reset counters under
      the same traffic key; gate persistence until designed safely.

### 2.6 Negative / protocol tests (expand)
- [x] nonce exhaustion (have basic), malformed/forged frames.
- [x] Control/data flag confusion: `decode_control` rejects a data frame whose
      plaintext happens to be valid `ControlMessage` bytes
      (`frame::tests::decode_control_rejects_a_frame_without_the_control_flag`);
      `handle_incoming_with_session` surfaces the same bytes as application
      data rather than acting on them
      (`...handle_incoming_with_session_ignores_control_shaped_bytes_without_the_flag`)
      — the `IS_CONTROL` header flag, not payload shape, is authoritative.
- [x] Rekey collision / stale `old_key_id` / replayed rekey / forged transcript
      binding / unexpected control message for current state, all in
      `session.rs::tests`:
      `replayed_rekey_message_is_rejected_after_a_real_rekey`,
      `rekey_message_with_stale_old_key_id_is_rejected`,
      `rekey_message_with_forged_transcript_binding_is_rejected`,
      `control_message_unexpected_for_current_state_is_rejected`.
- [x] Out-of-order rekey delivery (a `Rekey` for the *next* expected
      `old_key_id`, not just a stale one): rejected with the session state
      unchanged and the genuine in-order rekey still applying afterwards
      (`session.rs::rekey_delivered_ahead_of_order_is_rejected_and_state_is_unchanged`).
      Rollback at the ratchet level is covered by the replayed-rekey and
      stale-`old_key_id` tests (a rekey can never re-apply or roll the chain
      back), matching §2.3's alternating-DH-ratchet design.

---

## 3. P1 — Transports (finish each; don't broaden claims)

### 3.1 Byte-stream conformance suite
- [x] One shared conformance suite run against the three transport **shapes** via
      the unified `SecureChannel` trait. **Done:** `foctet-transport/tests/conformance.rs`
      runs the same checks (bidirectional round trip, ordering, large payload)
      over an in-memory message channel, an in-memory datagram channel, and a
      byte-stream channel (`TokioTransportBuilder` over `tokio::io::duplex`), so
      the shapes stay behaviourally consistent.
- [x] Per-adapter runnable integration tests. **Done:** the shared suite now
      also runs over a **real loopback connection for every advertised
      byte-stream backend** — quinn bi-streams, WebTransport bi-streams, muxtls,
      and websock-mux — each with a self-signed localhost certificate and the
      native Foctet handshake (`foctet-transport/tests/conformance.rs`,
      feature-gated per adapter). Individual real-connection roundtrips for the
      other shapes already existed (quinn datagram, raw-UDP, websock message).
      This is what exposed (and now regression-guards) the async
      duplicate-send-on-suspended-flush bug fixed in `secure_channel.rs`.
- [x] Publish an explicit **transport support matrix**. **Done:** README
      "Transport Support Matrix" table (adapter × shape × API × feature × native ×
      browser × what verifies it), with notes on the browser-WebTransport gaps and
      the conformance-suite coverage.

### 3.2 Transport shape split
- [x] `DatagramTransport` trait + generic `SecureDatagramChannel<T>`
      (`foctet_transport::datagram`); `quinn::Connection` implements it
      (verified over a real connection).
- [x] `MessageTransport` (raw WebSocket messages) shape trait + generic
      `SecureMessageChannel<T>` (`foctet_transport::message`), backed by
      `foctet_core::message::MessageEndpoint` (reliable, ordered, message-bounded;
      not MTU-capped; replay-after-auth; per-`(key_id, stream_id)` fail-closed
      sequence). In-memory `MessageTransport` roundtrip/replay/key-rotation tests.
      Concrete `WebsockMessageTransport` over the `websock` crate's raw
      connection now exists (`foctet-transport/src/websock.rs`), verified with a
      real plain-WebSocket loopback roundtrip
      (`websock::tests::secure_message_channel_over_raw_websocket`). It is now
      **generic over `websock::WebSocketConnection`**, so the same adapter runs on
      native (`websock-tungstenite`) **and the browser** (`websock-wasm`): the
      `transport-websock` feature was split from the native-only
      `transport-websock-mux`, `foctet-transport` compiles for
      `wasm32-unknown-unknown` with `transport-websock` (a Rust/wasm front-end can
      run a `SecureMessageChannel` over a browser `WebSocket` with no JS glue),
      and CI gates that wasm build.
- [x] `ByteStream` shape trait + unified channel abstraction. **Done**
      (`foctet-transport/src/shape.rs`): `ByteStreamTransport` is the byte-stream
      marker (any `futures_io::AsyncRead + AsyncWrite + Unpin`), the third shape
      alongside `MessageTransport`/`DatagramTransport`. More usefully, the new
      `SecureChannel` trait (`send_payload`/`recv_payload`) unifies the three at
      the application-payload level and is implemented by `TokioTransportChannel`,
      `FuturesTransportChannel`, `SecureMessageChannel`, and
      `SecureDatagramChannel` — so generic code and the shared conformance suite
      (§3.1) run over any shape.

### 3.3 Datagram support
- [x] Datagram encoder/decoder: `foctet_core::datagram::DatagramEndpoint`
      (`seal`/`open`), `DatagramConfig`, `DecodedDatagram`.
- [x] Exactly one bounded frame per datagram; app-configured max datagram size
      (`DEFAULT_MAX_DATAGRAM_SIZE`, clamped to transport MTU by the adapter).
- [x] Authenticate before committing replay state; replay-window resource caps;
      per-`(key_id, stream_id)` fail-closed sequence allocation.
- [x] quinn datagram adapter (`QuinnDatagramChannel`) + real-connection
      roundtrip test; core loss/reorder/duplicate/oversize/forgery tests.
- [x] Generic `DatagramTransport` trait + `SecureDatagramChannel<T>` (§3.2) so
      non-quinn datagram backends share one interface.
- [x] Raw-UDP adapter: `UdpDatagramTransport` (`foctet-transport/src/udp.rs`,
      `runtime-tokio` feature) implements `DatagramTransport` over a
      *connected* `tokio::net::UdpSocket`. Session negotiation, peer
      discovery/pinning (via `UdpSocket::connect`, since the trait carries no
      destination address) and MTU/fragmentation are documented as the caller's
      responsibility; **anti-amplification is now an opt-in built-in** (see the
      §3.3 item below). Otherwise this adapter only moves bytes, unlike
      QUIC/WebTransport which provide connection + peer auth for free. Verified
      with a real-socket roundtrip test (`udp::tests::roundtrip_over_real_udp_sockets`).
- [x] Browser WebTransport datagram adapter. **Done**
      (`foctet_transport::webtrans_browser::BrowserWebTransportDatagrams`,
      `transport-webtrans-browser` feature, wasm32): implements
      `DatagramTransport` over the `WebTransport.datagrams` duplex handed in
      from JS, duck-typed via `js-sys` reflection (avoids web-sys's
      unstable-APIs cfg flag; anything shaped
      `{ readable, writable, maxDatagramSize? }` works), clamping to the
      browser-reported `maxDatagramSize`. Verified in **real headless Chrome**
      end to end through `SecureDatagramChannel` against in-page WHATWG
      streams (roundtrip both directions + oversize fail-closed;
      `foctet-wasm/tests/browser.rs`); the wasm build is a CI gate. An E2E
      test against a live HTTP/3 server remains out of CI scope.
- [x] MTU/path-change handling and fragmentation policy. **Done** as a
      normative policy (SPEC §5.1.1): Foctet does not fragment — oversize
      payloads fail closed (`FrameTooLarge`) before sending; the maximum is
      configuration clamped to the transport's reported limit (QUIC /
      WebTransport), with ≤1200-byte guidance for raw UDP (no PMTUD of its
      own); on path-MTU drops, QUIC/WebTransport surface send failures and
      callers lower the configured size or re-establish — silent truncation
      and Foctet-layer fragmentation are prohibited (reassembly would be a
      pre-auth DoS surface).
- [x] Rekey-over-datagram story. **Done** (documented + glued + tested): the DH
      ratchet rekey is driven by `Session` control messages over a **reliable
      control channel** (QUIC-style separation — a lost ratchet message would
      desync), then `SecureDatagramChannel::rekey_from_session(&session)` (and the
      message channel's equivalent) adopts the rotated key. The datagram endpoint
      retains previous keys, and datagrams carry their `key_id`, so an old-key
      datagram reordered/delayed across a rekey still decrypts. Proven by
      `datagram::tests::datagrams_decrypt_across_a_rekey_including_a_reordered_old_key_datagram`
      (sends under key 0, rekeys, sends under key 1, then delivers the key-0
      datagram *after* the rekey and both open). Module docs explain the flow.
- [x] Anti-amplification guidance/limits for datagram adapters. **Done** for the
      raw-UDP adapter: opt-in `UdpDatagramTransport::with_anti_amplification(factor)`
      (`DEFAULT_AMPLIFICATION_FACTOR` = 3, QUIC-style) refuses to send once
      cumulative sent would exceed `factor ×` cumulative received from an
      unvalidated peer (returns `WouldBlock`), so a spoofed source address cannot
      be amplified/reflected; `mark_peer_validated()` lifts the limit once the
      peer proves it can receive (e.g. handshake completion). Off by default
      (no behavior change). Counters are atomic + shared across clones. Verified
      by `udp::tests::anti_amplification_caps_sends_until_validated`. QUIC's own
      adapter needs none (QUIC enforces this itself).

### 3.4 WebSocket / WebTransport specifics
- [~] Test real WebSocket message framing + a browser client; define
      mux/backpressure behavior. The message *shape* exists
      (`foctet_transport::message::{MessageTransport, SecureMessageChannel}`, §3.2)
      **and** a concrete native impl `WebsockMessageTransport` over the `websock`
      crate's raw connection (one Foctet frame per binary WebSocket message),
      verified with a real plain-WebSocket loopback roundtrip in
      `foctet-transport/src/websock.rs`. For the **browser**, there are now two
      paths: (1) the wasm `FoctetSession` (§5, `foctet-wasm/src/session.rs`) where
      JS owns the `WebSocket` and exchanges `Uint8Array` blobs; and (2) a
      **Rust/wasm** path — `WebsockMessageTransport` is generic over
      `websock::WebSocketConnection`, compiles for `wasm32` under
      `transport-websock` (browser `websock-wasm` backend), and drives a
      `SecureMessageChannel` directly from Rust with no JS glue (CI-gated wasm
      build). A **headless browser-runner runtime test** now exists at the
      crypto layer: `foctet-wasm/tests/browser.rs` runs the full
      `FoctetSession` handshake + message exchange in real headless Chrome
      (CI job `wasm-browser-test`). **Mux/backpressure definition done:**
      `foctet-transport/src/websock.rs` module docs now state the normative
      contract — one raw connection ⇔ one session (logical `stream_id` mux
      shares the connection's ordering/flow control, head-of-line blocking
      acknowledged; real per-stream mux via `websock-tungstenite-mux`),
      backpressure delegated to socket readiness with at most one buffered
      in-flight message per direction, inbound size bounded by
      `MessageConfig::max_message_size` pre-allocation. **Still open:** a
      browser test driving a real `WebSocket` connection end-to-end (needs a
      live server next to the headless-browser harness).
- [~] Browser WebTransport: the wasm `FoctetSession` (§5) protects data over
      both WebTransport **streams** (message mode: `newInitiator`/`sealMessage`)
      and WebTransport **datagrams** (datagram mode:
      `newDatagramInitiator`/`sealDatagram`, MTU-bounded via
      `DatagramEndpoint`, configurable `maxDatagramSize`). JS owns the transport;
      a session is locked to one framing mode so message/datagram traffic can
      never share a `(key_id, stream_id)` nonce space. The datagram-mode
      session now has a **headless-Chrome runtime test**
      (`foctet-wasm/tests/browser.rs::datagram_session_roundtrip`, CI job
      `wasm-browser-test`); the native WebTransport byte-stream adapter is
      covered by the real-connection conformance suite (§3.1); and the
      **Rust/wasm datagram adapter** (§3.3, `BrowserWebTransportDatagrams`)
      is exercised in headless Chrome through `SecureDatagramChannel` against
      in-page WHATWG streams. In-session **rekey** now also runs over the wasm
      session (message + datagram modes, headless-Chrome tested). **Still
      open:** a browser test driving a real WebTransport connection
      end-to-end (needs a live HTTP/3 server next to the harness).

---

## 4. P1 — HTTP & Workers (depends on §1.2)

- [x] Axum adapter that requires verified protected context + bounds body size:
      `AxumOpener::open_request_with_context` (+ async-store variant) done, bounded
      by `max_body_bytes`. Ready-made extractor layer added:
      `ProtectedHttpState` trait + `ProtectedRequest` (`axum::extract::FromRequest`)
      in `foctet-http/src/axum.rs` — implement the trait on your Axum `State` and
      handlers take `ProtectedRequest` directly, no manual opener/store
      plumbing per handler. `AxumError` now implements `IntoResponse` (maps to
      a status code only — `Replayed` → 409, `OpenFailed`/`ContextExpired` →
      401, malformed context → 400 — never echoes the source error's detail
      back to the caller). Scoped to the synchronous `ReplayStore` only:
      axum's `FromRequest` requires the extraction future to be `Send`, which
      `AsyncReplayStore`'s future is deliberately not (so it stays usable from
      `!Send` Workers); a durable/networked store like `RedisReplayStore`
      still needs the existing manual
      `AxumOpener::open_request_with_async_store` call in the handler.
- [x] Durable replay store interface (`AsyncReplayStore`) + Redis backend for
      multi-instance deployments (see §1.2).
- [x] Safe default body limits: Axum opener bounds via `max_body_bytes`.
      **Docs done** (`foctet-http/src/axum.rs` module docs): recommended
      values (1–4 MiB one-shot; switch to streaming ≥ 16 MiB), the
      `max_body_bytes × concurrency` memory budget with a concurrency-limit
      pairing, and reject-early ordering (context verified before body work).
- [x] Streaming HTTP mode: per-chunk AEAD, unique nonces, final authenticated
      manifest/length, cancellation, context/replay binding. **Done.** Core
      primitive `foctet_core::body_stream` (`StreamSealer`/`StreamOpener`): one
      ECIES-wrapped content key per stream; each chunk AEAD'd under a unique
      `prefix||index` nonce with AAD `header||index||flags||context`; exactly one
      authenticated `FINAL` chunk gives truncation/extension resistance
      (`is_finished()` must be true to accept); sequential indices reject
      reorder/gap/dup; an aborted stream simply never finalizes (cancellation =
      discard). HTTP layer `foctet_http::stream::{HttpStreamSealer,
      HttpStreamOpener}` binds the protected context and enforces freshness +
      single-use via `ReplayStore` (message id consumed once per stream).
      9 tests (roundtrip, truncation, extension, reorder, wrong-context,
      tampered, wrong-recipient, HTTP roundtrip+replay, HTTP truncation).
      **Turn-key framework wiring done:** `foctet_core::StreamFrameDecoder`
      reassembles the self-delimiting wire frames from arbitrary byte splits
      (HTTP body data frames / Workers `ReadableStream` reads); the
      framework-agnostic `foctet_http::HttpRequestStreamReader` (push-based) feeds
      that into the opener, building it on the header (freshness + single-use
      replay) and yielding plaintext chunks, with `finish()` rejecting a
      truncated/cancelled body (`HttpError::StreamIncomplete`); and the axum
      helper `foctet_http::axum::open_request_stream` drives it from an axum body
      stream (callback per plaintext chunk, no whole-body buffering — natural
      backpressure via the caller's consumption rate). Workers uses the same
      framework-agnostic reader. Tested: decoder arbitrary-split reassembly,
      reader split-body decode + replay rejection + truncation rejection, and a
      real axum streaming-upload roundtrip. Backpressure *tuning* guidance now
      documented (`foctet-http/src/axum.rs` module docs: 64–256 KiB chunk-size
      sweet spot, overhead vs granularity trade-off).
- [ ] End-to-end Workers test under `wrangler`: key lookup, durable replay store,
      failure handling, response binding, key rotation, operational guide.

---

## 5. P1 — WASM / TypeScript SDK (`foctet-wasm`)

- [x] Supported JS environments: Node, browser (web), bundler targets via
      `wasm-pack` (`build:node` / `build:web` / `build:bundler`). Workers uses the
      Node/bundler output.
- [x] Minimal versioned WASM API via `wasm-bindgen` with `Uint8Array` values and
      generated `.d.ts`; fallible calls throw instead of panicking
      (errors constructed only on the wasm side; native tests cover inner logic).
- [x] Body envelope subset incl. context binding (`sealBody`/`openBody`,
      `sealBodyWithContext`/`openBodyWithContext`, `KeyPair`).
- [x] Node interop test decrypts the **same Rust-produced envelopes**
      (`tests/interop_vector.json`) — real cross-language wire compatibility.
- [ ] Publish the npm package (currently a private dev harness;
      `pkg-*` are build artifacts).
- [x] Browser-runner integration test in CI (wasm-bindgen-test / headless).
      **Done:** `foctet-wasm/tests/browser.rs` runs 4 `wasm-bindgen-test`
      tests inside a real headless Chrome (body-envelope roundtrip, context
      binding enforced, full authenticated `FoctetSession` handshake +
      bidirectional messages + replay rejection, datagram-mode roundtrip +
      wrong-mode rejection). Locally: `wasm-pack test --headless --chrome
      foctet-wasm` (if wasm-pack's auto-downloaded chromedriver mismatches the
      installed Chrome, point `CHROMEDRIVER` at a matching driver from Chrome
      for Testing). CI: the `wasm-browser-test` job uses the runner's
      preinstalled, version-matched Chrome + chromedriver. Verified locally:
      4/4 pass in headless Chrome 149.
- [x] Framed-session / handshake APIs over WASM. **Done**
      (`foctet-wasm/src/session.rs`): `FoctetSession` runs the native
      authenticated handshake (`newInitiator`/`newResponder` + `AuthConfig`,
      pinned-peer or explicit unauthenticated) and then per-message
      `sealMessage`/`openMessage` (one Foctet frame per message, replay-after-auth).
      WASM does the crypto/handshake; **JS owns the transport** (browser
      WebSocket/WebTransport), exchanging `Uint8Array` blobs. Also exposes
      `IdentityKeyPair` (Ed25519) and `DecodedMessage`. Inner logic is
      native-tested (handshake roundtrip, peer pinning, replay, fail-closed,
      unexpected-peer rejection); the `wasm32-unknown-unknown` build is verified.
      **In-session rekey done:** `forceRekey()` / `canRekey` /
      `handleControlMessage()` / `activeKeyId` carry the alternating
      DH-ratchet rekey over both wasm framing modes (rekey messages travel on
      the reliable channel; the endpoint adopts rotated keys and retains
      previous generations so in-flight/reordered old-key frames still open;
      `Session::can_rekey()` added in core). Tested natively (turn
      alternation, old-key frame across rekey, datagram reorder across rekey)
      and in headless Chrome.
- [~] Host-backed / non-extractable key handling where the platform allows it;
      document zeroization limits across the boundary. **Documented** as
      unavailable: WebCrypto has no portable non-extractable X25519/Ed25519 key
      type, so `KeyPair`/`IdentityKeyPair` expose raw bytes (README "Scope and
      security"). Revisit if/when a platform offers a usable non-extractable path.
- [x] Replace `interop/minimal_decoder.ts` (header-only) references with the SDK.
      **Done** (`interop/README.md`): full seal/open from JS/TS now points at
      the `foctet-wasm` SDK (Node + headless-browser tested); the minimal
      decoder is kept, explicitly repositioned as the *independent*
      header-level check (it is not generated from the Rust implementation,
      so it can catch systematic encode/decode bugs a Rust-derived artifact
      would reproduce — a stepping stone toward the §7 independent-vector
      verification).

---

## 6. P1 — Security assurance & supply chain (CI)

- [x] `cargo-audit` (advisory scan) in CI; fail on vulnerable deps
      (`security-audit` job in `.github/workflows/rust.yml`). Fixed the
      vulnerabilities it found in `Cargo.lock` at the time
      (`quinn-proto`, `rustls-webpki`, `rand`, `rkyv` bumped to patched
      versions); one `unmaintained`-only warning remains on a dev-dependency
      (`rustls-pemfile`, used by transport examples/tests), which `cargo
      audit` does not fail the build on by default. **Re-checked 2026-06-22 via
      `cargo deny`:** patched a new batch of advisories by bumping
      `quinn-proto` → 0.11.15 (RUSTSEC-2026-0037), `rkyv` → 0.8.16
      (RUSTSEC-2026-0122), and `rustls-webpki` → 0.103.13 (RUSTSEC-2026-0049 /
      -0098 / -0099 / -0104). The `rustls-pemfile` unmaintained advisory
      (RUSTSEC-2025-0134, no safe upgrade, dev-only) is explicitly ignored in
      `deny.toml`.
- [x] License/source policy (`cargo-deny`). **Done:** `deny.toml` (permissive
      license allow-list, registry-only sources, advisory + ban checks,
      `allow-wildcard-paths` for the fuzz harness) + a `cargo-deny` CI job.
      Verified locally: `advisories ok, bans ok, licenses ok, sources ok`.
- [x] Restore `cargo fmt --all -- --check` and add it as a required CI gate.
      **Done:** formatting drift fixed across `foctet-http`/`foctet-transport`/
      `foctet-wasm` and a dedicated `fmt` job added.
- [x] Run `cargo test --workspace --all-features` in CI. **Done:** the `test` job
      now runs `--all-features --locked`, plus the `foctet-core` feature-combo
      matrix.
- [x] Reproducible locked builds; committed `Cargo.lock` checks. **Done:** every
      cargo invocation in CI passes `--locked` (fails if `Cargo.lock` is stale or
      missing). `Cargo.lock` is committed.
- [x] MSRV policy + CI job. **Done:** `rust-version = "1.88"` declared in the
      workspace and inherited by all published members (1.85 fails on `time`'s
      1.88 requirement via the `rcgen` TLS deps; 1.88 verified to build
      all-features). New `msrv` CI job pins 1.88.0 and runs `cargo check
      --workspace --all-features --locked`.
- [x] Pin third-party GitHub Actions to reviewed immutable commit SHAs and
      maintain an update process. **Done:** `actions/checkout` (v4.3.1),
      `rustsec/audit-check` (v2.0.0), and `EmbarkStudios/cargo-deny-action`
      (v2.0.9) are pinned to commit SHAs with the tag in a trailing comment.
- [~] Miri / sanitizers where applicable. **Miri done:** new `miri` CI job
      runs the parser / state-machine / crypto-framing modules of
      `foctet-core` (replay bitmap shifting, TLV/control/frame parsing,
      sequence allocation, AEAD framing — 28 tests, ~1 min) under Miri on
      nightly; the full suite (handshakes, Ed25519) is impractically slow
      under Miri. Sanitizers (ASan/TSan) not wired — the workspace is
      `#![forbid(unsafe_code)]` throughout, so their marginal value over Miri
      is low; revisit if unsafe or FFI ever lands.
- [x] Fuzz targets beyond frame/archive + fuzzing in CI. **Added**
      (`fuzz/fuzz_targets/`): `control_message` (control-plane parser),
      `handshake` (state machine: any decodable control fed to a fresh
      responder + initiator), `body_envelope` (one-shot envelope parse/AEAD),
      `stream_body` (streaming header parser + incremental
      `StreamFrameDecoder`), `datagram_message` (datagram + message frame
      open). Replay behaviour is exercised inside the datagram/message open
      paths; transport framing via the frame/datagram/message targets. All
      compile-gated by `clippy --workspace --all-targets` on every PR.
      **CI wiring done:** `.github/workflows/fuzz.yml` runs every target on a
      weekly schedule (and `workflow_dispatch`, budget overridable) with a
      per-target libFuzzer time budget, seeded from the committed corpus
      `fuzz/seeds/<target>/` (valid frames/envelopes/archives/control messages
      generated by `foctet/examples/gen_fuzz_seeds.rs`, sealed with the
      targets' fixed keys so deep open paths run); crash artifacts are uploaded
      on failure. An HTTP-adapter-specific target remains intentionally out of
      scope (header parsing is the `http` crate's job).
- [~] Coverage of all transport integrations; mutation/negative protocol tests.
      Every advertised byte-stream backend runs the real-connection
      conformance suite (§3.1); datagram (QUIC, raw-UDP, browser-WT) and
      message (WebSocket native+browser) shapes have real roundtrips; the
      negative-protocol matrix (§2.6) is extensive. **Still open:** systematic
      mutation testing (e.g. `cargo-mutants`) as a test-suite-strength gauge.
- [x] Cross-implementation (independent decoder) interop tests. **Done:**
      `interop/verify_vectors.mjs` re-implements the Draft v0 key schedule,
      frame AEAD (full XChaCha20-Poly1305 open, header-as-AAD, tamper
      negatives), handshake transcript bindings + Ed25519 identity
      verification, and the DH-ratchet step on the audited `@noble` libraries
      (zero shared code with this workspace), verifying every committed vector
      — 38 checks, run in CI (`interop-verify` job). Supersedes the
      header-only `minimal_decoder` (kept as a minimal reference).
- [x] Vulnerability disclosure policy + security contact. **Done:**
      `SECURITY.md` now names the channels (GitHub private vulnerability
      reporting as canonical, maintainer email fallback), a response SLA
      (acknowledge ≤ 7 days, triage ≤ 14 days, fix/advisory ≤ 90 days with
      coordinated disclosure), and an explicit in/out-of-scope list.
- [ ] **Independent cryptographic design & implementation review** (mandatory
      before v1; covers protocol, Rust impl, WASM/JS boundary, HTTP mode).

---

## 7. P2 — Stability, spec, scope

- [x] Complete **normative** spec matching code + vectors; version it.
      **Done:** the spec carries an independent version stamp
      (`foctet-spec/0.3-draft`, §0 — bumped only on normative change, moving
      `test-vectors/` in the same commit) and an RFC 2119/8174 conformance
      statement (unmarked sections are normative; violating a MUST is
      non-conforming). The remaining "(draft)" markers are gone: §6.3 Flags
      and §8.2 Native Handshake are normative (the handshake section now
      specifies the transcript-binding hashes, the channel-binding mix, the
      all-zero-DH rejection, and the auth-required-by-default rule), and
      §5.1.1 adds the normative datagram MTU/fragmentation policy. §0
      implementation-status matches the shipped surface. Vector layouts are
      pinned by the independent verifier (§6).
- [x] Version-negotiation / compatibility / deprecation policy. **Done:**
      `docs/POLICIES.md` §1 — what versions exist (wire / profile / crates),
      the Draft-v0 rules (breaking allowed, vectors must move with the wire,
      deprecation cycle before removal), the normative no-negotiation rule for
      v0 with downgrade-resistant negotiation requirements for future
      versions, and the v1 compatibility commitment.
- [x] Canonical vector suite verified by an **independent** implementation (not
      generated and checked within the same Rust workspace). **Done:**
      `interop/verify_vectors.mjs` on `@noble` — full AEAD, handshake,
      identity-auth, and rekey-ratchet verification of every committed vector,
      in CI. See §6 for details.
- [x] Full threat model doc: active MITM, endpoint compromise, relay compromise,
      replay, rollback, metadata leakage, DoS, key loss. **Done:**
      `docs/THREAT_MODEL.md` (v1.0) — system/adversary model, ten threat
      sections each with implemented defenses *and residual risks* (including
      reordering/truncation/splicing, the WASM/JS boundary, and key loss),
      explicit non-goals, and assurance status. Referenced from SPEC §3 and
      SECURITY.md.
- [x] Key lifecycle / rotation / incident-response / supported-version policy.
      **Done:** `docs/POLICIES.md` §2 (per-key-kind lifecycle table, session
      vs long-lived key rules, rotation and multi-recipient backup guidance)
      and §3 (incident-response playbooks per key type, replay-store
      compromise, monitoring signals). Supported versions: §1.2/§1.4.
- [x] Observability hooks (without exposing secrets). **Done:**
      `foctet_core::observe` — `SessionObserver` receives `SessionEvent`s
      (`HandshakeCompleted` with role + peer-auth flag, `RekeyInitiated`,
      `RekeyApplied`, `ControlRejected`) carrying only public metadata, wired
      via `Session::with_observer`/`set_observer` (synchronous, keep cheap);
      plus replay-rejection counters (`ReplayProtector::rejections`,
      `replay_rejections()` on `FoctetFramed` / `SyncIo` / `MessageEndpoint` /
      `DatagramEndpoint`) as the replay/flooding monitoring signal. Tested
      (`session.rs::observer_sees_handshake_rekey_and_rejections_without_secrets`).

---

## 8. Release gates for "production-ready" / v1

All must be true before using either phrase:

- [~] Every P0 and P1 finding fixed and regression-tested. Remaining P1s:
      npm publish (§5), Workers `wrangler` E2E (§4), browser live-server E2E
      (§3.4), and the independent review items.
- [x] Spec complete, normative, versioned, and matches code + vectors
      (`foctet-spec/0.3-draft`, RFC 2119 conformance language, no remaining
      draft markers; vectors pinned by the independent verifier).
- [ ] Authenticated peer identity or explicit authenticated-channel binding is
      mandatory for production constructors (the `unauthenticated_for_testing`
      convenience constructors still exist pending the §2.1 API-freeze
      decision).
- [x] HTTP has authenticated protected context + replay defense (protected
      context + atomic durable stores; stateless family deprecated).
- [x] Advertised transport matrix has real implementations + integration/
      conformance tests (README matrix; real-connection conformance for every
      byte-stream backend; real roundtrips for datagram/message shapes incl.
      the browser-WT datagram adapter in headless Chrome).
- [~] WASM/TypeScript truly shipped + tested, or excluded from the claim —
      tested (Node interop + headless Chrome in CI, incl. rekey), but not yet
      **shipped** to npm.
- [ ] Independent security review complete; findings resolved or publicly tracked.
- [x] cargo-audit/license checks, fuzzing, reproducible builds, CI coverage,
      Miri, independent vector verification, and a vulnerability-response
      process (SECURITY.md SLA) active.
- [x] Documented compatibility, deprecation, key-management, incident-response,
      and supported-version policies (`docs/POLICIES.md`, SECURITY.md).

---

## Suggested next step

The implementable engineering surface is now essentially complete: limits,
rate limiting, observability, WASM rekey, the browser-WT datagram adapter,
Miri, and independent vector verification all landed, and the spec is
normative and versioned. What remains is **release/process work**, in order:

1. **API-freeze decision** (§1.2 hard enforcement of context-bound HTTP APIs;
   §2.1 removing/renaming the `unauthenticated_for_testing` convenience
   constructors) — a deliberate breaking pass, best done as its own release.
2. **npm publish** of `foctet-wasm` (§5) and the **Workers `wrangler` E2E**
   (§4) — both are packaging/environment work, not code gaps.
3. **Independent cryptographic review** (§2.3/§6) — the final, mandatory gate;
   everything above is review-ready input for it.

Do not use "production-ready" / "v1 stable" wording until §8 is all green —
the review gate in particular.
