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
- [~] Optional selected-header binding + authority normalization guidance.
      Header binding done for requests (see §1.2 above); authority
      normalization guidance still open.
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
      ratchet **test vectors** not yet added.
- [ ] **Independent cryptographic review** of this ratchet **before** the PCS
      guarantee is claimed for high assurance (the one remaining gate; the
      construction is the alternating DH-ratchet, not improvised per-message).

### 2.4 Centralized protocol limits (P2 in review, do early)
- [~] One public `ProtocolLimits`. Done for the **stream** shape:
      `foctet_core::limits::ProtocolLimits` (`foctet-core/src/limits.rs`) covers
      max inbound ciphertext length, retained previous keys, replay-window size,
      and the distinct-replay-window cap, with documented defaults
      (`DEFAULT_MAX_CIPHERTEXT_LEN`, `DEFAULT_MAX_RETAINED_KEYS`) and a
      `replay_protector()` constructor. **Still open:** max plaintext, buffered
      (outbound `tx`) bytes, distinct stream IDs, control-message size, handshake
      duration, and outstanding-work bounds are not yet part of the struct.
- [~] Apply consistently. `FoctetFramed` + `SyncIo` now take `with_limits(...)` /
      expose `limits()`, routing their old `with_max_ciphertext_len` /
      `with_max_retained_keys` setters through `ProtocolLimits`; the replay
      window/cap are now configurable on these paths. **Still open:** datagram
      (`DatagramConfig`) and HTTP/body (`BodyEnvelopeLimits`) keep their own
      shape-specific limit types (different in kind — MTU-bounded / whole-buffer);
      archive APIs not yet wired. A future step may unify them under one umbrella
      type or have them share more constants.
- [x] Replay-window count cap (`DEFAULT_MAX_REPLAY_WINDOWS`) — first piece, now
      configurable on the stream paths via `ProtocolLimits::max_replay_windows`.
- [x] Bound outbound plaintext/frame length before `u32` ct_len conversion
      (`crypto::checked_ciphertext_len` in `foctet-core/src/crypto.rs`,
      shared by `encrypt_frame`, used by every sync/async send path).
      Still pending: the broader `ProtocolLimits` unification above.
- [~] Handshake read **timeout** + connection-level rate limit + cancellation.
      Timeout done for the Tokio path: `TokioTransportBuilder::establish_*_with_timeout`
      / `establish_*_with_auth_and_timeout` / `establish_*_with_default_timeout`
      (`DEFAULT_HANDSHAKE_TIMEOUT` = 10s) in `foctet-transport/src/tokio.rs`,
      using `tokio::time::timeout` and a new `CoreError::HandshakeTimeout`;
      `quinn`/`websock`/`webtrans`/`muxtls` all build on this builder so they
      gain it once their call sites switch to the timeout variants. The
      runtime-agnostic `FuturesTransportBuilder` now has parity via
      `establish_initiator_with_auth_and_timeout` /
      `establish_responder_with_auth_and_timeout`, which take a caller-supplied
      timer *future* (e.g. `tokio::time::sleep`, an async-io timer, a browser
      timer) and race it against the handshake with a `std`-only `poll_fn`
      (`CoreError::HandshakeTimeout` on expiry; verified by stalled-handshake
      tests). Still missing: a connection-level rate limit and cancellation.

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
- [ ] Out-of-order rekey delivery (a `Rekey` for the *next* expected
      `old_key_id`, not just a stale one), and rollback at the ratchet-design
      level — these depend on §2.3's ratchet decision, not just test coverage
      of the current symmetric-rekey state machine.

---

## 3. P1 — Transports (finish each; don't broaden claims)

### 3.1 Byte-stream conformance suite
- [ ] One shared conformance test suite run against **every** byte-stream adapter:
      TCP, quinn bi-streams, WebTransport bi-streams, multiplexed WebSocket.
- [ ] Currently only in-memory split I/O + a couple of adapters are tested; add
      runnable integration tests per advertised adapter.
- [ ] Publish an explicit **transport support matrix** (see `README`/`SPEC §5`).

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
      and CI gates that wasm build. **Still open:** the `ByteStream` marker shape
      below.
- [~] `ByteStream` shape trait. The byte-stream secure path already exists
      (`FoctetFramed`/`FoctetStream` over `PollIo`, plus the Tokio/Futures
      builders); a thin `ByteStream` marker trait unifying it with the other two
      shapes under a shared conformance suite is still open (ties into §3.1).

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
- [ ] Browser WebTransport datagram adapter (implement `DatagramTransport`
      for it).
- [ ] MTU/path-change handling and fragmentation policy for payloads above the
      datagram limit (currently fail-closed `FrameTooLarge`).
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
      build). **Still open:** a headless browser-runner *runtime* test and a
      documented mux/backpressure definition.
- [~] Browser WebTransport: the wasm `FoctetSession` (§5) protects data over
      both WebTransport **streams** (message mode: `newInitiator`/`sealMessage`)
      and WebTransport **datagrams** (datagram mode:
      `newDatagramInitiator`/`sealDatagram`, MTU-bounded via
      `DatagramEndpoint`, configurable `maxDatagramSize`). JS owns the transport;
      a session is locked to one framing mode so message/datagram traffic can
      never share a `(key_id, stream_id)` nonce space. **Still open:** a native
      WebTransport integration test and a headless browser-runner test.

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
- [~] Safe default body limits: Axum opener bounds via `max_body_bytes`; document
      recommended values and add backpressure guidance.
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
      **Still open:** turn-key axum/Workers body-stream wiring + backpressure
      guidance (the primitive is framework-agnostic by design).
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
- [ ] Browser-runner integration test in CI (wasm-bindgen-test / headless).
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
      **Still open:** in-session rekey is not carried over this message API yet
      (matches the datagram/message-shape rekey gap).
- [~] Host-backed / non-extractable key handling where the platform allows it;
      document zeroization limits across the boundary. **Documented** as
      unavailable: WebCrypto has no portable non-extractable X25519/Ed25519 key
      type, so `KeyPair`/`IdentityKeyPair` expose raw bytes (README "Scope and
      security"). Revisit if/when a platform offers a usable non-extractable path.
- [ ] Replace `interop/minimal_decoder.ts` (header-only) references with the SDK.

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
- [ ] Miri / sanitizers where applicable.
- [ ] Fuzzing in CI with a corpus + time budget. Add fuzz targets beyond
      frame/archive: **body envelope, control messages, handshake state machine,
      replay behavior, HTTP adapter parsing, transport framing**.
- [ ] Coverage of all transport integrations; mutation/negative protocol tests.
- [ ] Cross-implementation (independent decoder) interop tests.
- [ ] Vulnerability disclosure policy + security contact (started in
      `SECURITY.md`) — finalize contact + response SLA.
- [ ] **Independent cryptographic design & implementation review** (mandatory
      before v1; covers protocol, Rust impl, WASM/JS boundary, HTTP mode).

---

## 7. P2 — Stability, spec, scope

- [ ] Complete **normative** spec matching code + vectors; version it.
- [ ] Version-negotiation / compatibility / deprecation policy.
- [ ] Canonical vector suite verified by an **independent** implementation (not
      generated and checked within the same Rust workspace).
- [ ] Full threat model doc: active MITM, endpoint compromise, relay compromise,
      replay, rollback, metadata leakage, DoS, key loss.
- [ ] Key lifecycle / rotation / incident-response / supported-version policy.
- [ ] Observability hooks (without exposing secrets).

---

## 8. Release gates for "production-ready" / v1

All must be true before using either phrase:

- [ ] Every P0 and P1 finding fixed and regression-tested.
- [ ] Spec complete, normative, versioned, and matches code + vectors.
- [ ] Authenticated peer identity or explicit authenticated-channel binding is
      mandatory for production constructors.
- [ ] HTTP has authenticated protected context + replay defense, or is explicitly
      excluded from the production promise.
- [ ] Advertised transport matrix has real implementations + integration/
      conformance tests.
- [ ] WASM/TypeScript truly shipped + tested, or excluded from the claim.
- [ ] Independent security review complete; findings resolved or publicly tracked.
- [ ] cargo-audit/license checks, fuzzing, reproducible builds, CI coverage, and
      a vulnerability-response process active.
- [ ] Documented compatibility, deprecation, key-management, incident-response,
      and supported-version policies.

---

## Suggested next step

The most immediate, low-risk release hygiene work is **§6**: restore formatting
and require format, locked builds, and all-feature tests in CI. Then complete
**§1.2/§1.3** by making durable, context-bound HTTP replay protection the
production-default story and correcting the public documentation. The remaining
production sequence is: normative spec/interop → transport conformance and
operational scope → supply-chain/fuzz/browser/Workers validation → independent
security review.
