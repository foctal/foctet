[crates-badge]: https://img.shields.io/crates/v/foctet.svg
[crates-url]: https://crates.io/crates/foctet
[license-badge]: https://img.shields.io/crates/l/foctet.svg

# foctet [![Crates.io][crates-badge]][crates-url] ![License][license-badge]

Transport-agnostic end-to-end encryption for live connections, HTTP bodies,
stored records, and files. Foctet provides authenticated sessions with rekeying,
public-key envelopes, signed records, and encrypted archives.

Encrypt and decrypt at trusted endpoints to keep plaintext out of relays and
storage services. Applications supply trusted identities, key custody, and
authorization. See the [security model](SECURITY.md) and
[compromise boundaries](docs/security-boundaries.md).

The wire format and APIs may change during `0.x`. See
[compatibility policy](docs/api-stability.md) and [release notes](CHANGELOG.md).

## Crates

| Crate | Purpose |
| --- | --- |
| `foctet-core` | Framing, cryptography, handshake, rekeying, and replay protection |
| `foctet-http` | HTTP body envelopes and protected request context |
| `foctet-archive` | Single-file, split, and streaming encrypted archives |
| `foctet-transport` | Byte-stream, message, and datagram adapters |
| `foctet-wasm` | WebAssembly / TypeScript body and session APIs |
| `foctet-storage` | Native SQL and remote Turso adapters (Rust 1.94) |
| `foctet-storage-wire` | Driver-free signed TEXT records and SQL plans (Rust 1.88) |
| `foctet` | Facade re-exporting the component crates |

## Quick Start

For async stream transports, enable the `runtime-tokio` feature on
`foctet-transport`:

```rust,no_run
use foctet_core::{
    IdentityKeyPair, PeerIdentity, ProductionSessionAuth, RekeyThresholds,
};
use foctet_transport::TokioTransportBuilder;

async fn connect<T>(
    stream: T,
    local_identity: IdentityKeyPair,
    peer_public_key: [u8; 32],
) -> Result<(), foctet_core::CoreError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let builder = TokioTransportBuilder::new();
    let channel = builder
        .establish_production_initiator(
            stream,
            RekeyThresholds::default(),
            ProductionSessionAuth::pinned_identity(
                local_identity,
                PeerIdentity::new(peer_public_key),
            ),
        )
        .await?;
    let _ = channel;
    Ok(())
}
```

The peer public key must come from a trusted source. The responder uses
`establish_production_responder` with its own identity and the initiator's pin.
After a restart or failed connection, establish a fresh session; live session
state must not be restored.

## Guides

- [Choosing an integration](docs/recommended-deployments.md)
- [Runnable examples](docs/examples.md) and [transport features](docs/transport-matrix.md)
- [HTTP context rules](docs/http-canonicalization.md) and [recipient-key rotation](docs/key-rotation.md)
- [Storage integration](docs/storage-integration.md), [portable TEXT records](docs/worker-databases.md), and [Rust Workers](docs/workers-rs.md)
- [Threat model](docs/THREAT_MODEL.md), [key management](docs/POLICIES.md), and [error handling](docs/error-handling.md)
- [Protocol specification](SPEC.md), [test vectors](test-vectors/README.md), and [running tests](docs/testing.md)

Report suspected vulnerabilities privately using the [security policy](SECURITY.md#reporting-a-vulnerability).
