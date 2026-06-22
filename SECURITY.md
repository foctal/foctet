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

1. **HTTP anti-replay (partial).** `foctet-http` now ships a versioned protected-
   context schema (`ProtectedContext`, `x-foctet-*` carrier headers), a bounded
   `ReplayStore` with atomic check-and-insert (`InMemoryReplayStore`), and
   context-bound APIs (`seal_request_with_context` / `open_request_with_context`,
   plus an Axum adapter) that bind method/path/query/message-id/timestamp/expiry
   into the AEAD and enforce single use. For multi-instance / serverless
   deployments there is an `AsyncReplayStore` trait (`!Send`-friendly for
   Cloudflare Workers) with a Redis backend (`RedisReplayStore`, `redis` feature)
   using atomic `SET NX PX`. Still required before this is considered
   production-complete: a Cloudflare KV / Durable Object adapter, making the
   context-bound path the enforced default, and authority/idempotency-key
   guidance. The low-level `seal_body` /
   `open_body` and `seal_request` / `open_request` paths remain stateless and
   replayable by design — use the `*_with_context` APIs in production.
2. **No post-compromise security.** In-session rekey is symmetric traffic-key
   rotation, not a DH ratchet. See `SPEC.md` §3.2.
3. **Datagram support (partial).** A dedicated datagram API
   (`foctet_core::datagram::DatagramEndpoint`: one bounded frame per datagram,
   size cap, authenticate-before-replay, loss/reorder tolerant) ships with a QUIC
   datagram adapter (`foctet_transport::quinn::QuinnDatagramChannel`) and a
   raw-UDP adapter over a connected socket
   (`foctet_transport::udp::UdpDatagramTransport`; peer discovery/pinning, MTU,
   anti-amplification are the caller's responsibility). A browser-WebTransport
   datagram adapter, a rekey-over-datagram story, and an MTU/fragmentation policy
   are still pending.
4. **WASM/TypeScript SDK (partial).** The `foctet-wasm` crate ships a
   `wasm-bindgen` API for the body envelope (seal/open, context-bound variants,
   `KeyPair`) with generated `.d.ts`, Node/browser/bundler builds, and a Node
   interop test that opens Rust-produced envelopes. Still pending: a published
   npm package, browser-runner CI, framed-session/handshake APIs over WASM, and
   host-backed (non-extractable) key handling.
5. **HTTP adapters are whole-buffer**, not streaming; large uploads/downloads are
   not yet handled as bounded streams.
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
