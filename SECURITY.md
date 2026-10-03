# Security Policy

## Status: experimental — not production-ready

Foctet is an **experimental Draft v0** implementation of authenticated encrypted
framing, a one-shot `application/foctet` body envelope, and encrypted archive
formats. The project is under active security and interoperability development.

The wire format and APIs may change during the `0.x` release line. See the
[threat model](docs/THREAT_MODEL.md) for trust boundaries and metadata leakage,
and [policies](docs/POLICIES.md) for key management and incident response.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public issue
or pull request for security problems.

**Contact (in order of preference):**

1. GitHub's **private vulnerability reporting** ("Security" → "Report a
   vulnerability") on this repository.
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
release receives security fixes. Starting with v1, the current minor release
and the immediately preceding minor release receive security fixes for at
least 12 months after the newer minor is published. A major release receives
critical security fixes for at least 24 months after its successor is
published. The supported-version table in each advisory is authoritative when
a protocol/profile must be disabled sooner for safety.

## Security model

- Frames and body envelopes use X25519, HKDF-SHA-256, and
  XChaCha20-Poly1305. All-zero X25519 shared secrets are rejected.
- Session handshakes authenticate pinned Ed25519 identities or an explicit
  binding to an authenticated outer channel. Unauthenticated handshakes require
  an explicit testing opt-in. See [authentication APIs](docs/secure-api.md).
- Sequence and key-ID exhaustion are terminal. Replay windows are bounded and
  updated only after authentication, so forged frames cannot advance them.
- Session rekeys mix fresh X25519 output into a root-key chain and alternate
  between peers. Under one-way traffic, the quiet peer must also initiate rekeys
  to keep the ratchet advancing.
- HTTP protected-context APIs authenticate request metadata and enforce single
  use through a replay store. Multi-instance deployments require a shared,
  atomic store such as Redis or a Durable Object. Cloudflare KV is unsuitable
  for replay decisions. See [HTTP context rules](docs/http-canonicalization.md).
- Archives encrypt file contents and metadata and wrap the content key for
  each recipient. Use randomized builders for application data; deterministic
  secrets are intended for test vectors.

## Limitations and application responsibilities

- **No session persistence or resumption.** After a restart or reconnect,
  establish a fresh authenticated session. Restoring traffic keys with reset
  sequence counters can reuse nonces.
- **No delivery guarantee.** After an ambiguous write or transport failure,
  discard the affected channel. Application-level message IDs and idempotency
  are needed to handle retries. See [error handling](docs/error-handling.md).
- **Datagrams are unreliable and unordered.** Handshakes and rekey controls
  require a separate reliable channel. Configure payload limits for the path
  MTU; see the [transport guide](docs/transport-matrix.md).
- **HTTP body encryption does not hide routing metadata.** Use HTTPS or another
  authenticated outer channel. Low-level body-envelope helpers do not prevent
  replay; use protected-context APIs and a replay store for HTTP requests.
- **Streaming bodies require finalization.** Reject truncated or extended
  bodies. A decrypted chunk alone does not establish that the body is complete.
- **Browser keys are extractable.** Host-backed, non-extractable key handling is
  not implemented by the WASM SDK. Keep untrusted scripts out of the client.
  On `wasm32-unknown-unknown`, age-based rekey thresholds are disabled; use
  count thresholds or explicit rekeys. The SDK is not yet published to npm.
- **Endpoint security and key distribution belong to the application.** Foctet
  does not protect a compromised endpoint, distribute trusted identities,
  enforce application authorization, or provide key recovery.

See [resource limits](docs/resource-limits.md) and
[operations](docs/operations.md) for sizing, monitoring, and shutdown guidance.
