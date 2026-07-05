# Recommended Deployment Patterns

This guide summarizes the recommended production composition patterns for Foctet Draft v0.

## Choosing the Right Foctet Layer

| Use case | Recommended Foctet layer | What Foctet protects | What must be protected elsewhere |
| --- | --- | --- | --- |
| Interactive end-to-end transport between peers | `foctet-transport` with authenticated native handshake | Stream payloads, frame integrity, replay window, rekey lifecycle | Peer discovery, transport availability, routing metadata |
| HTTP request/response body encryption | `foctet-http` or `foctet_core::body` | HTTP body bytes only | Method, URL, query, status code, outer headers, server authentication |
| File transfer, offline export, or storage handoff | `foctet-archive` | File contents, encrypted metadata, recipient-scoped DEK wrapping | File naming outside the archive, storage ACLs, distribution channel authenticity |

## Pattern 1: Authenticated Transport E2EE

Use this when both endpoints actively exchange encrypted data over a live connection.

- Recommended crates: `foctet-transport` plus `foctet-core` identity types.
- Recommended transports: QUIC streams, WebTransport streams, multiplexed WebSocket streams, `muxtls`, or any split send/recv byte stream.
- Recommended setup:
  - create a `SessionAuthConfig`
  - attach a local Ed25519 identity
  - pin the expected remote `PeerIdentity`
  - call `require_peer_authentication(true)`
  - use `establish_initiator_with_auth` / `establish_responder_with_auth`

This is the primary production path when Foctet is the main secure channel.

### When to choose it

- You need bidirectional E2EE streams.
- You need replay protection and rekey over a long-lived session.
- You want one transport-agnostic secure channel abstraction across `quinn`, `webtrans`, `websock`, or custom split I/O.

### What still remains outside Foctet

- Connection establishment and retry policy.
- Transport-level routing information such as IP addresses, QUIC connection IDs, or relay metadata.
- Authorization rules above peer identity, if your application needs roles or permissions.

## Pattern 2: HTTP Body Encryption

Use this when you need encrypted payload bodies over HTTP APIs but do not need full HTTP-message confidentiality.

- Recommended crates: `foctet-http` or `foctet_core::body`.
- Recommended outer channel: HTTPS or another authenticated session that already authenticates the peer.
- Recommended setup:
  - seal request or response bodies with `application/foctet`
  - keep `x-foctet-scope: body-only`
  - authenticate the outer HTTP channel separately
  - rotate recipient keys with an `HttpOpener` keyring and an overlap window
    (see [Key rotation](key-rotation.md))

### When to choose it

- You are integrating with `axum`, Cloudflare Workers, or another HTTP stack.
- You need encrypted request or response bodies without replacing your existing routing or middleware model.
- You want a compact one-shot envelope instead of a long-lived Foctet session.

### Important boundary

Foctet HTTP does not hide or authenticate:

- request method
- URL path or query
- response status code
- outer HTTP headers unless your application copies them into the encrypted body

If you need full-message confidentiality, use transport E2EE instead of relying on HTTP body envelopes alone.

## Pattern 3: Archive and File Distribution

Use this when the data must survive outside a live session.

- Recommended crate: `foctet-archive`
- Recommended setup:
  - use `create_archive_from_bytes` or `create_split_archive_from_bytes`
  - distribute the resulting archive bytes or manifest/parts through any storage or transport layer
  - decrypt with the intended recipient private key

### When to choose it

- You need encrypted files for offline transfer.
- You need split archives for large payload delivery or resumable distribution.
- You need recipient-wrapped content keys and encrypted metadata.

### Deterministic builds

`ArchiveBuildSecrets` is for reproducible vectors and deterministic tests only.

Do not use deterministic archive secrets for real user data because fixed archive identifiers, DEKs, or wrapping ephemeral secrets leak equality and key-reuse signals across builds.

## Deployment Checklist

- Use authenticated native handshakes with pinned peer identities whenever Foctet is the main secure channel.
- Treat sequence-space exhaustion and key-id exhaustion as terminal; start a fresh session instead of trying to recover in place.
- Keep parser limits enabled for untrusted input.
- Keep `x-foctet-scope: body-only` on HTTP body-envelope deployments unless you have a strong compatibility reason not to.
- Use randomized archive builders in production.
- Update `SPEC.md` and `test-vectors/` together for every wire-format change.
