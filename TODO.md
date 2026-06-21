# Foctet — Road to Production-Ready

Tracking document for taking Foctet from **Draft v0 / experimental** to a
**stable, independently reviewed, general-purpose production E2EE SDK** that can
protect arbitrary TCP/UDP/QUIC/WebSocket/WebTransport payloads, HTTP bodies
(axum, Cloudflare Workers), and files.

- Source of requirements: `foctet-review.md` (review, 2026-06-20) + `SPEC.md`.
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
- Vectors, property tests, 2 fuzz targets, CI (lint/test/wasm-check).

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
- [ ] Follow-up: unify sequence allocation into one shared internal type so sync
      and async cannot diverge again (currently duplicated logic, kept in sync
      by tests).

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
- [ ] Cloudflare KV / Durable Object adapter (implement `AsyncReplayStore` in the
      Worker; shipped trait makes this app-side today). **Not done deliberately:**
      raw KV `get`-then-`put` cannot satisfy the trait's atomic check-and-insert
      contract (no conditional/NX write), so a naive KV-only store would silently
      reintroduce a replay race; needs a Durable Object (or KV + DO lock) before
      shipping.
- [ ] Make context-bound APIs the **enforced default**; consider deprecating the
      stateless `seal_request`/`open_request` for production use.
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

---

## 2. P1 — Required for v1 (protocol & core)

### 2.1 Native handshake authentication — **DONE (revisit at API-freeze)**
- [x] Fail-closed default; explicit `unauthenticated_for_testing()` /
      `allow_unauthenticated()`.
- [x] Downgrade/MITM negative tests (`session.rs`).
- [x] All transport convenience helpers route through explicit opt-in.
- [ ] Introduce a typed `AuthenticatedPeer` / `ChannelBinding` abstraction so an
      outer-channel binding (e.g. TLS exporter / channel id) can substitute for
      Foctet identity auth, instead of the current boolean opt-in.
- [ ] Consider removing/renaming the no-auth transport convenience constructors
      at API-freeze (currently they call `unauthenticated_for_testing()`).

### 2.2 Replay state after authentication — **DONE**
- [x] Reordered in `io.rs` (`recv`, `recv_application_with_session`) and
      `frame.rs::try_decode`.
- [x] Forged-high-sequence-then-valid regression tests (sync + async).

### 2.3 Rekey vs post-compromise security
- [x] SPEC/README/SECURITY now state rekey = symmetric rotation, **no PCS**.
- [ ] **Decide and document the target**: keep symmetric rekey (accurately
      specified) *or* design an authenticated **ephemeral-DH ratchet** with:
  - [ ] fresh forward-secret DH step per rekey
  - [ ] transcript binding, concurrency/collision rules, rollback behavior
  - [ ] out-of-order rekey delivery handling + vectors
  - [ ] independent cryptographic review **before** shipping (do not improvise)

### 2.4 Centralized protocol limits (P2 in review, do early)
- [ ] One public `ProtocolLimits` covering: max ciphertext, max plaintext,
      buffered bytes, distinct stream IDs, replay windows, retained keys, control
      message size, handshake duration, outstanding work.
- [ ] Apply consistently to sync, async, datagram, HTTP, archive APIs.
- [x] Replay-window count cap (`DEFAULT_MAX_REPLAY_WINDOWS`) — first piece.
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
      gain it once their call sites switch to the timeout variants. Still
      missing: the same for the runtime-agnostic `FuturesTransportBuilder`
      (needs a caller-supplied timer since that path has no runtime), a
      connection-level rate limit, and cancellation.

### 2.5 Key-material ergonomics
- [ ] Make secret-bearing types non-`Clone` where practical; zeroizing wrappers.
- [ ] Stop returning raw secret-key byte copies (`IdentityKeyPair::secret_key_bytes`,
      HTTP `[u8;32]` recipient secrets in `foctet-http/src/config.rs`).
- [ ] Key-provider / keystore abstraction: separate key *handles* from bytes;
      key IDs with rotation policy; optional hardware-backed path.
- [ ] Document that session state MUST NOT be restored with reset counters under
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
- [ ] `ByteStream` / `MessageTransport` (raw WebSocket messages) shape traits
      with per-shape guarantees and a shared conformance suite.

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
- [ ] Browser WebTransport datagram adapter; raw-UDP adapter + session/discovery
      guidance (implement `DatagramTransport` for each).
- [ ] MTU/path-change handling and fragmentation policy for payloads above the
      datagram limit (currently fail-closed `FrameTooLarge`).
- [ ] Rekey-over-datagram story (control frames are stream-oriented today).
- [ ] Anti-amplification guidance/limits documented for datagram adapters.

### 3.4 WebSocket / WebTransport specifics
- [ ] Test real WebSocket message framing + a browser client; define
      mux/backpressure behavior.
- [ ] Test native **and** browser WebTransport; document stream-only scope until
      datagrams land.

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
- [ ] Streaming HTTP mode (only after design + review): per-chunk AEAD, unique
      nonces, final authenticated manifest/length, cancellation, context/replay
      binding. Do not market whole-buffer envelope as streaming.
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
- [ ] Framed-session / handshake APIs over WASM (today: body envelope only).
- [ ] Host-backed / non-extractable key handling where the platform allows it;
      document zeroization limits across the boundary.
- [ ] Replace `interop/minimal_decoder.ts` (header-only) references with the SDK.

---

## 6. P1 — Security assurance & supply chain (CI)

- [x] `cargo-audit` (advisory scan) in CI; fail on vulnerable deps
      (`security-audit` job in `.github/workflows/rust.yml`). Fixed the
      vulnerabilities it found in `Cargo.lock` at the time
      (`quinn-proto`, `rustls-webpki`, `rand`, `rkyv` bumped to patched
      versions); one `unmaintained`-only warning remains on a dev-dependency
      (`rustls-pemfile`, used by transport examples/tests), which `cargo
      audit` does not fail the build on by default.
- [ ] License/source policy (`cargo-deny`).
- [ ] Reproducible locked builds; committed `Cargo.lock` checks.
- [ ] MSRV policy + CI job.
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

The highest-leverage P0 remaining is **§1.2 (HTTP protected-context schema +
`ReplayStore` + axum/Workers integration)** — it turns the existing body-envelope
primitive into safe, replay-resistant HTTP E2EE, which is the most-requested
surface (axum, Cloudflare Workers). Recommended order:
`§1.2 → §4 → §5 (WASM/TS) → §3.3 (datagrams) → §2.3 (ratchet decision) → §6 review`.
