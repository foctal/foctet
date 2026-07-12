# Security Policy

## Status: experimental — not production-ready

Foctet is an **experimental Draft v0** implementation of authenticated encrypted
framing, a one-shot `application/foctet` body envelope, and encrypted archive
formats. The project is under active security and interoperability development.

It is **not yet a stable, general-purpose production E2EE SDK**. Several
surfaces (datagram/UDP, WASM body envelope, HTTP protected context) are
implemented but remain partial or evolving — see "Known
limitations" below. Do not describe it as a complete E2EE library for arbitrary
TCP/UDP/QUIC/WebSocket/WebTransport payloads until the gates in
"Roadmap to a production claim" below are met.

The full threat model (per-threat defenses, residual risks, metadata leakage,
key-loss policy) is documented in `docs/THREAT_MODEL.md`; versioning,
key-lifecycle, and incident-response policies are in `docs/POLICIES.md`.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public issue
or pull request for security problems.

**Contact (in order of preference):**

1. GitHub's **private vulnerability reporting** ("Security" → "Report a
   vulnerability") on this repository — the canonical channel; it keeps the
   report, discussion, and advisory in one place.
2. If you cannot use GitHub, email the maintainer at the address listed on the
   repository/crates.io profile, with `[foctet security]` in the subject.

Include a description, the affected crate(s) and version(s), impact as you
understand it, and a reproduction if possible.

**Response targets (best-effort; this is a volunteer-maintained project):**

- **Acknowledgement** within **7 days** of the report.
- **Triage and severity assessment** (confirmed / not a vulnerability /
  needs more info) within **14 days**.
- **Fix or public advisory** within **90 days** for confirmed issues, sooner
  for critical ones; if a fix needs longer we will say so and agree on a
  disclosure date with you.

Coordinated disclosure is preferred: please allow the fix to ship before public
discussion. Credit is given in the advisory unless you ask otherwise. There is
currently no bug bounty.

**In scope:** the `foctet-*` crates in this repository, the wire format and key
schedule as specified in `SPEC.md`, the WASM/JS boundary, and the committed CI
supply-chain configuration. **Out of scope:** vulnerabilities in third-party
dependencies (report upstream; we will pick up the fix), and issues requiring a
compromised endpoint (see `docs/THREAT_MODEL.md` for the trust boundary).

## Supported versions

While the project is in the `0.x` Draft v0 line, only the latest published `0.x`
release receives security fixes. There is no long-term-support branch yet. A
supported-version policy will accompany the first `v1` release.

## What is protected today

- **Confidentiality / integrity / authenticity** of framed payloads and body
  envelopes via X25519 + HKDF-SHA-256 + XChaCha20-Poly1305, with the wire header
  authenticated as AEAD associated data.
- **All-zero X25519 shared secrets are rejected** in native handshakes, body
  envelopes (including streaming bodies), and archive recipient wrapping.
  Low-order recipient keys are rejected before sealing; malicious ephemeral
  keys while opening are reported as generic unwrap/authentication failures.
- **Fail-closed sequence and key-id exhaustion** on both the async (`FoctetFramed`)
  and synchronous (`SyncIo`) paths — a frame is never emitted with a reused
  `(key_id, stream_id, seq)` nonce. `SyncIo` and `FoctetFramed` reserve a
  sequence before the first write and become terminal after a write or flush
  error, because local code cannot know whether the peer received the frame.
  Applications that need delivery semantics must use authenticated message IDs
  and idempotency.
- **No session-state restoration.** Foctet does not provide a session-persistence
  format. After a crash or restart, applications must establish a fresh session;
  restoring traffic keys with reset or uncertain outbound sequence state can reuse
  a nonce and is unsafe.
- **Terminal protocol failures.** Message/datagram endpoints, `SyncIo`, and
  `FoctetFramed` reject all subsequent use after an inbound authentication,
  parser, replay, key, sequence, or session-control failure. Establish a fresh
  authenticated session; do not continue after a potentially diverged channel.
- **Replay protection** via per-`(key_id, stream_id)` sliding windows, committed
  **only after AEAD authentication** so a forged frame cannot desynchronize or
  DoS the receiver. The number of tracked windows is bounded
  (`DEFAULT_MAX_REPLAY_WINDOWS`) to prevent unbounded memory growth.
- **Authenticated-by-default native handshake.** A default `SessionAuthConfig`
  fails closed: an unauthenticated handshake requires an explicit
  `SessionAuthConfig::unauthenticated_for_testing()` /
  `allow_unauthenticated(true)` opt-in, intended only for tests or for use inside
  an already-authenticated outer channel (e.g. mutually authenticated TLS).
  Identity authentication uses Ed25519 transcript signatures with pinned peer
  identities.
- **Optional context binding** for body envelopes (`seal_body_with_context` /
  `open_body_with_context`): an application-supplied context (for HTTP: method,
  authority, path, timestamp, message ID, …) is folded into the AEAD associated
  data so a captured envelope cannot be replayed onto a different request.

## Known limitations (do not rely on these yet)

These are tracked work items; treat each as **unsupported** until implemented,
documented, and thoroughly tested:

1. **HTTP anti-replay (near-complete, not yet hard-enforced).** `foctet-http`
   ships a versioned protected-context schema (`ProtectedContext`, `x-foctet-*`
   carrier headers), a bounded `ReplayStore` with atomic check-and-insert
   (`InMemoryReplayStore`), and context-bound APIs
   (`seal_request_with_context` / `open_request_with_context`, plus Axum and
   Workers adapters) that bind method/path/query/message-id/timestamp/expiry
   into the AEAD and enforce single use. Multi-instance / serverless
   deployments have an `AsyncReplayStore` trait (`!Send`-friendly for
   Cloudflare Workers) with a Redis backend (`RedisReplayStore`, atomic
   `SET NX PX`) **and** a Cloudflare **Durable Object** adapter
   (`DurableObjectReplayStore`). The stateless full-request family is
   `#[deprecated]` in favor of the context-bound path; hard removal/gating is
   deferred to the API freeze so downstream callers get a deprecation cycle.
   The low-level `seal_body` / `open_body` primitives remain stateless by
   design — production HTTP code must use the `*_with_context` APIs backed by
   a shared, durable store. Still open: authority-normalization guidance.
2. **Forward-secret DH ratchet rekey.** In-session
   rekey now performs a Diffie-Hellman ratchet step: each rekey mixes a fresh
   ephemeral X25519 output into a root-key chain, and rekeys **alternate**
   between the two peers (enforced by a turn flag, so the root chain cannot fork
   and both peers' ratchet keys rotate). This gives forward secrecy and, across
   an alternating rekey, post-compromise security in both directions.
   Operational note: under strictly one-directional traffic the alternation can
   stall after one step (the quiet side never takes its turn); rekey
   periodically from both ends for continued ratcheting.
   Byte-stream transports prepare the new ratchet generation, enqueue the
   old-key control frame, and only then commit. An ambiguous output failure is
   terminal because Foctet has no rekey-delivery acknowledgement.
3. **Datagram support (near-complete).** A dedicated datagram API
   (`foctet_core::datagram::DatagramEndpoint`: one bounded frame per datagram,
   size cap, authenticate-before-replay, loss/reorder tolerant) ships with a
   QUIC datagram adapter (`foctet_transport::quinn::QuinnDatagramChannel`) and
   a raw-UDP adapter over a connected socket
   (`foctet_transport::udp::UdpDatagramTransport`) with an **opt-in
   anti-amplification limiter** (`with_anti_amplification`; peer
   discovery/pinning and MTU discovery remain the caller's responsibility).
   **Rekey-over-datagram** is supported: the DH-ratchet rekey rides a reliable
   control channel and `SecureDatagramChannel::rekey_from_session` adopts the
   rotated keys, with retained previous keys so reordered old-key datagrams
   still decrypt. A browser-WebTransport datagram adapter now ships as
   `foctet_transport::webtrans_browser::BrowserWebTransportDatagrams`
   (`transport-webtrans-browser`, wasm32) and is exercised in headless Chrome
   against in-page WHATWG streams. Still pending: a live end-to-end browser
   test against a real HTTP/3 WebTransport server, plus more deployment
   guidance around path-MTU changes and conservative datagram sizing.
4. **WASM/TypeScript SDK (partial).** The `foctet-wasm` crate ships a
   `wasm-bindgen` API for the body envelope (seal/open, context-bound variants,
   `KeyPair`) **and** a framed `FoctetSession` (authenticated handshake,
   ordered `sealMessage`/`openMessage`, datagram `sealDatagram`/`openDatagram`,
   and in-session DH-ratchet rekey via `forceRekey` / `handleControlMessage`),
   with generated `.d.ts`, Node/browser/bundler builds, a Node interop test that
   opens Rust-produced envelopes, an in-browser runtime harness
   (`foctet-wasm/examples/browser/index.html`), and a **headless-Chrome test
   suite in CI** (`foctet-wasm/tests/browser.rs`). **WASM clock limitation:**
   `wasm32-unknown-unknown` has no monotonic clock, so the *age-based* rekey
   threshold is disabled there; the frame-count and byte-count thresholds still
   apply, and a long-lived WASM session should still drive rekey explicitly when
   needed. Still pending: a published npm package and host-backed
   (non-extractable) key handling (documented as unavailable on current
   platforms).
5. **Streaming HTTP bodies (near-complete).** A chunked streaming mode exists
   (`foctet_core::body_stream`, plus `foctet_http`'s `HttpStreamSealer` /
   `HttpStreamOpener`): per-chunk AEAD with unique nonces, an authenticated
   final-chunk marker (truncation/extension resistance), ordering checks, and
   the same protected-context + replay binding as the one-shot path. Turn-key
   request wiring exists (`StreamFrameDecoder`, the framework-agnostic
   `HttpRequestStreamReader`, and the axum helper `open_request_stream`, no
   whole-body buffering). Still open: a response-body streaming helper and
   backpressure *tuning* guidance.
6. **Wire format is unstable** (`0.x`, Draft v0). Even though vectors and
   interoperability fixtures are checked in CI, breaking wire changes may still
   occur until the v1 compatibility commitment begins.

## Roadmap to a production / `v1` claim

Before using "production-ready" or "v1 stable" wording, all of the following must
hold:

- All P0/P1 findings fixed and regression-tested (see the project review).
- Documentation, examples, and operational guidance aligned with the shipped
  surface.
- Authenticated peer identity or explicit authenticated-channel binding is
  mandatory for production constructors.
- HTTP has an authenticated protected context and replay defense, or is
  explicitly excluded from the production promise.
- The advertised transport matrix has real implementations and conformance tests.
- WASM/TypeScript are either truly shipped and tested or excluded from the claim.
- Dependency advisory/license checks, fuzzing, reproducible builds, CI coverage,
  and a vulnerability-response process are active.
