# Example Guide

This guide collects the recommended Foctet examples by deployment style.

## Start Here

| Goal | Recommended example | Why start here |
| --- | --- | --- |
| Authenticated end-to-end stream over a single connection | `foctet/examples/secure_channel_tokio.rs` | Smallest authenticated native-handshake example with pinned identities |
| Runtime-agnostic transport integration over a real stream transport | `foctet-transport/examples/quinn_split.rs` | Shows the recommended `foctet-transport` builder flow with authenticated per-stream sessions |
| HTTP body encryption with a Rust server | `foctet-http/examples/axum_body_echo_server.rs` and `foctet-http/examples/axum_body_echo_client.rs` | Demonstrates the high-level `HttpSealer` / `HttpOpener` path |
| HTTP body encryption with Cloudflare Workers | `foctet-http/examples/workers-echo` plus `foctet-http/examples/workers_echo_client.rs` | Shows Workers integration while preserving body-only scope |
| Archive/file encryption and split archive roundtrip | `foctet/examples/file_archive_roundtrip.rs` | Shows single-file and split archive creation plus restore |
| Deterministic interoperability fixtures | `foctet/examples/gen_vectors.rs` | Regenerates the repository test vectors |

## Transport E2EE Examples

### Lowest-friction authenticated native handshake

```bash
cargo run -p foctet --example secure_channel_tokio
```

- Uses pinned Ed25519 peer identities.
- Completes the native Foctet handshake before application data is exchanged.
- Best first read if you want to understand the core secure-channel flow.

### Sync variant

```bash
cargo run -p foctet --example secure_channel_sync
```

### Transport-builder integrations

- `foctet-transport/examples/quinn_split.rs`
- `foctet-transport/examples/webtrans_split.rs`
- `foctet-transport/examples/websock_split.rs`
- `foctet-transport/examples/muxtls_split.rs`

These examples all use authenticated Foctet handshakes and `SessionAuthConfig`. They are the best reference when integrating Foctet with existing stream transports.

## HTTP Body Envelope Examples

### Axum

Run the server:

```bash
cargo run -p foctet-http --example axum_body_echo_server --features axum
```

Run the client in another terminal:

```bash
cargo run -p foctet-http --example axum_body_echo_client --features axum
```

### Cloudflare Workers

Run local Worker development:

```bash
cd foctet-http/examples/workers-echo
npm i -D wrangler@latest
npx wrangler dev
```

Run the Rust client in another terminal:

```bash
cargo run -p foctet-http --example workers_echo_client
```

These examples protect HTTP body bytes only. Keep the outer channel authenticated and keep the advisory `x-foctet-scope: body-only` header unless you have a compatibility reason not to.

## Archive and File Examples

### File roundtrip

```bash
cargo run -p foctet --example file_archive_roundtrip -- <input_file> <output_dir>
```

- Writes both a single-file archive and a split archive.
- Restores both forms and verifies roundtrip correctness.

### Tokio file roundtrip

```bash
cargo run -p foctet --example file_archive_roundtrip_tokio -- <input_file> <output_dir>
```

## Advanced and Legacy-style Core Examples

- `foctet/examples/e2ee_tokio_stream.rs`
- `foctet/examples/e2ee_tcp_sync.rs`
- `foctet/examples/e2ee_tcp_relay_sync.rs`
- `foctet/examples/e2ee_tcp_relay_tokio.rs`

These remain useful for lower-level experimentation, but new production integrations should generally start with `secure_channel_*` or `foctet-transport`.

## Regenerating Test Vectors

```bash
cargo run -p foctet --example gen_vectors
```

This rewrites the deterministic vectors under `test-vectors/`.
