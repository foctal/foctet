# Security Policy

## Status: experimental — not production-ready

Foctet is an **experimental Draft v0** implementation of authenticated encrypted
framing, a one-shot `application/foctet` body envelope, and encrypted archive
formats. The project is under active security and interoperability development.

It is **not yet a stable, independently audited, general-purpose production E2EE
SDK**. Several surfaces (datagram/UDP, WASM body envelope, HTTP protected
context) are implemented but remain partial or unreviewed — see "Known
limitations" below. Do not describe it as a complete E2EE library for arbitrary
TCP/UDP/QUIC/WebSocket/WebTransport payloads until the gates in
"Roadmap to a production claim" below are met.

The full threat model (per-threat defenses, residual risks, metadata leakage,
key-loss policy) is documented in `docs/THREAT_MODEL.md`; versioning,
key-lifecycle, and incident-response policies are in `docs/POLICIES.md`.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public issue
for security problems.

- Use GitHub's **private vulnerability reporting** ("Report a vulnerability") on
  this repository, or
- email the maintainer at the address listed on the crate/repository profile.

Include a description, affected crate/version, and a reproduction if possible.
We aim to acknowledge reports within 7 days. Coordinated disclosure is preferred;
please allow time for a fix before any public discussion.

## Supported versions

While the project is in the `0.x` Draft v0 line, only the latest published `0.x`
release receives security fixes. There is no long-term-support branch yet. A
supported-version policy will accompany the first `v1` release.

## What is protected today

- **Confidentiality / integrity / authenticity** of framed payloads and body
  envelopes via X25519 + HKDF-SHA-256 + XChaCha20-Poly1305, with the wire header
  authenticated as AEAD associated data.
- **All-zero X25519 shared secrets are rejected.**
- **Fail-closed sequence and key-id exhaustion** on both the async (`FoctetFramed`)
  and synchronous (`SyncIo`) paths — a frame is never emitted with a reused
  `(key_id, stream_id, seq)` nonce.
- **No session-state restoration.** Foctet does not provide a session-persistence
  format. After a crash or restart, applications must establish a fresh session;
  restoring traffic keys with reset or uncertain outbound sequence state can reuse
  a nonce and is unsafe.
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
tested, and independently reviewed:

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
2. **Forward-secret DH ratchet rekey (pending independent review).** In-session
   rekey now performs a Diffie-Hellman ratchet step: each rekey mixes a fresh
   ephemeral X25519 output into a root-key chain, and rekeys **alternate**
   between the two peers (enforced by a turn flag, so the root chain cannot fork
   and both peers' ratchet keys rotate). This gives forward secrecy and, across
   an alternating rekey, post-compromise security in both directions. **Caveat:**
   this construction has **not yet had the independent cryptographic review** this
   project requires, so do not yet rely on its post-compromise guarantee for
   high-assurance use. Operational note: under strictly one-directional traffic
   the alternation can stall after one step (the quiet side never takes its turn);
   rekey periodically from both ends for continued ratcheting.
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
   still decrypt. Still pending: a browser-WebTransport datagram *adapter*
   (the WASM `FoctetSession` datagram mode covers the crypto layer) and an
   MTU-change/fragmentation policy (oversize payloads fail closed).
4. **WASM/TypeScript SDK (partial).** The `foctet-wasm` crate ships a
   `wasm-bindgen` API for the body envelope (seal/open, context-bound variants,
   `KeyPair`) **and** a framed `FoctetSession` (authenticated handshake plus
   ordered, replay-protected `sealMessage`/`openMessage` and a datagram mode),
   with generated `.d.ts`, Node/browser/bundler builds, a Node interop test that
   opens Rust-produced envelopes, an in-browser runtime harness
   (`foctet-wasm/examples/browser/index.html`), and a **headless-Chrome test
   suite in CI** (`foctet-wasm/tests/browser.rs`). **WASM clock limitation:**
   `wasm32-unknown-unknown` has no monotonic clock, so the *age-based* rekey
   threshold is disabled there; the frame-count and byte-count thresholds still
   apply, and a long-lived WASM session should drive rekey explicitly (in-session
   rekey is not yet carried over the WASM message API). Still pending: a published
   npm package and host-backed (non-extractable) key handling (documented as
   unavailable on current platforms).
5. **Streaming HTTP bodies (near-complete).** A chunked streaming mode exists
   (`foctet_core::body_stream`, plus `foctet_http`'s `HttpStreamSealer` /
   `HttpStreamOpener`): per-chunk AEAD with unique nonces, an authenticated
   final-chunk marker (truncation/extension resistance), ordering checks, and
   the same protected-context + replay binding as the one-shot path. Turn-key
   request wiring exists (`StreamFrameDecoder`, the framework-agnostic
   `HttpRequestStreamReader`, and the axum helper `open_request_stream`, no
   whole-body buffering). Still open: a response-body streaming helper and
   backpressure *tuning* guidance.
6. **Wire format is unstable** (`0.x`, Draft v0) and has not been validated by an
   independent implementation.

## Roadmap to a production / `v1` claim

Before using "production-ready" or "v1 stable" wording, all of the following must
hold:

- All P0/P1 findings fixed and regression-tested (see the project review).
- Authenticated peer identity or explicit authenticated-channel binding is
  mandatory for production constructors.
- HTTP has an authenticated protected context and replay defense, or is
  explicitly excluded from the production promise.
- The advertised transport matrix has real implementations and conformance tests.
- WASM/TypeScript are either truly shipped and tested or excluded from the claim.
- An independent security review covers protocol design, the Rust
  implementation, the WASM/JS boundary, and HTTP mode.
- Dependency advisory/license checks, fuzzing, reproducible builds, CI coverage,
  and a vulnerability-response process are active.
