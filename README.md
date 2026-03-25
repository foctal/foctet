[crates-badge]: https://img.shields.io/crates/v/foctet.svg
[crates-url]: https://crates.io/crates/foctet
[doc-url]: https://docs.rs/foctet/latest/foctet
[license-badge]: https://img.shields.io/crates/l/foctet.svg
[examples-url]: https://github.com/foctal/foctet/tree/main/foctet/examples

# foctet [![Crates.io][crates-badge]][crates-url] ![License][license-badge]

Transport-agnostic end-to-end encryption layer for secure data transfer.

## Crates

- `foctet-core`: Framing, crypto, handshake/rekey state, replay protection.
- `foctet-http`: Thin HTTP adapter for `application/foctet` body envelopes.
- `foctet-archive`: Encrypted single-file and split archives with recipient key wrapping.
- `foctet-transport`: Layered transport integration helpers.
- `foctet`: Top-level re-export crate.

## Stability

- Current releases are `0.x`; breaking changes may occur while Draft v0 is finalized.
- Wire-level changes must update both `SPEC.md` and `test-vectors/`.
- Stable wire/API compatibility is planned for `v1`.

## Deployment Guide

See [`docs/recommended-deployments.md`](docs/recommended-deployments.md) for the recommended production composition patterns across transport E2EE, HTTP body envelopes, and archive/file delivery.

## Examples

- Repository examples: [examples][examples-url]
- Guided overview: [`docs/examples.md`](docs/examples.md)

## What Foctet Covers

- Transport-agnostic encrypted framing for byte streams and split send/recv transports.
- Encrypted body envelopes for HTTP integrations such as `axum` and Cloudflare Workers.
- Encrypted archive formats for files and split-file delivery.
- Transport helpers for `quinn`, `webtrans`, `websock`, and `muxtls`.

## Quick Start

For async stream transports, the recommended path is `foctet-transport`:

```rust,ignore
use foctet_core::{IdentityKeyPair, PeerIdentity, RekeyThresholds, SessionAuthConfig};
use foctet_transport::TokioTransportBuilder;

let builder = TokioTransportBuilder::new();
let channel = builder
    .establish_initiator_with_auth(
        stream,
        RekeyThresholds::default(),
        SessionAuthConfig::new()
            .with_local_identity(IdentityKeyPair::generate())
            .with_peer_identity(PeerIdentity::new(peer_public_key))
            .require_peer_authentication(true),
    )
    .await?;
```

If you already derived or exchanged Foctet session state out of band, you can still inject an active `Session` directly.

For encrypted files and reproducible test fixtures, `foctet-archive` exposes archive builders for both normal and deterministic generation:

```rust,ignore
use foctet_archive::{
    ArchiveBuildSecrets, ArchiveOptions, create_archive_from_bytes_with_secrets,
};

let secrets = ArchiveBuildSecrets {
    archive_id: [0x91; 16],
    file_id: [0x92; 16],
    dek: [0x93; 32],
    wrap_ephemeral_secret_keys: vec![[0x94; 32]],
};

let (archive_bytes, meta) = create_archive_from_bytes_with_secrets(
    payload,
    &[recipient_public_key],
    ArchiveOptions::default(),
    &secrets,
)?;
```

Use the `*_with_secrets` archive APIs only for reproducible vectors and deterministic tests. Production archive creation should use the default random builders.

## Security Notes

- Foctet fails closed on sequence/key identifier exhaustion and rejects invalid all-zero X25519 shared secrets.
- Native handshake authentication supports optional Ed25519 transcript signatures with pinned peer identity verification.
- For production deployments, prefer authenticated handshakes with pinned peer keys, or bind Foctet to an already-authenticated outer channel.
- Deterministic archive secrets intentionally disable build-time randomness. Reusing them across real payloads leaks equality and key-reuse signals, so reserve them for fixtures and interoperability tests.
