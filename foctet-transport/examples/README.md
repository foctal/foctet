# Transport examples

Run commands from the workspace root. Each example requires the feature listed
below. For examples with command-line options, use `-- --help` to list them.

| Example | Feature | Description |
| --- | --- | --- |
| [`quinn_split`](quinn_split.rs) | `transport-quinn` | Authenticated multiplexed QUIC streams; loopback, server, and client roles |
| [`quion_split`](quion_split.rs) | `transport-quion` | Authenticated QUIC stream and datagram round trips over loopback |
| [`webtrans_split`](webtrans_split.rs) | `transport-webtrans` | Authenticated WebTransport streams over loopback |
| [`websock_split`](websock_split.rs) | `transport-websock-mux` | Authenticated multiplexed WebSocket streams; loopback, server, and client roles |
| [`muxtls_split`](muxtls_split.rs) | `transport-muxtls` | Loopback streams using Foctet sessions established in process |
| [`udp_datagram_split`](udp_datagram_split.rs) | `runtime-tokio` | UDP datagrams with a TCP handshake/control channel |
| [`websock_message_server`](websock_message_server.rs) | `runtime-tokio,transport-websock` | Raw WebSocket messages, including browser interoperability |
| [`webtrans_datagram_split`](webtrans_datagram_split.rs) | `transport-webtrans` | WebTransport datagrams, including browser interoperability |

Start with an authenticated loopback connection:

```bash
cargo run -p foctet-transport --example quion_split --features transport-quion
```

`muxtls_split` is a lower-level I/O example: it exchanges Foctet handshake
messages in process using the testing authentication configuration, then passes
the active sessions to the transport builder. Its TLS client trusts the demo
server certificate; it does not configure mutual TLS. For an authenticated
Foctet handshake over muxtls, use the adapter's
`open_secure_channel_with_handshake_and_auth_config` and
`accept_secure_channel_with_handshake_and_auth_config` helpers with pinned
identities or an authenticated outer-channel binding.

## Separate server and client processes

`quinn_split` and `websock_split` accept `--role server` and `--role client`.
Generate a development certificate first:

```bash
./devcert/generate.sh
```

On Windows, use `devcert/generate.ps1`. For Quinn, start the server:

```bash
cargo run -p foctet-transport --example quinn_split --features transport-quinn -- \
  --role server --addr 127.0.0.1:4433 \
  --tls-cert devcert/localhost.crt --tls-key devcert/localhost.key
```

Then run the client in another terminal:

```bash
cargo run -p foctet-transport --example quinn_split --features transport-quinn -- \
  --role client --addr 127.0.0.1:4433 --tls-cert devcert/localhost.crt
```

Add `--wrong-identity` to check rejection of an unexpected peer identity.
`quinn_split` also accepts `--messages` and `--rekey-frames`; for example,
`--messages 20 --rekey-frames 4` exercises repeated rekeys and logs the key changes.

For two hosts, copy the certificate to the client and use the server's address.
The default TLS server name is `localhost`, matching the development certificate.
Use your own identities and certificates for application deployments.

## Browser interoperability

Build and serve the [WASM browser harness](../../foctet-wasm/README.md#browser-harness),
then start the corresponding native server from the workspace root.

For raw WebSocket messages:

```bash
cargo run -p foctet-transport --example websock_message_server \
  --features runtime-tokio,transport-websock -- --role server
```

Open `http://localhost:8011/examples/browser/websocket.html`.

For WebTransport, generate the development certificate as above, then run:

```bash
cargo run -p foctet-transport --example webtrans_datagram_split \
  --features transport-webtrans -- --role server \
  --tls-cert devcert/localhost.crt --tls-key devcert/localhost.key
```

Open `http://localhost:8011/examples/browser/webtransport.html` and paste the
SHA-256 certificate hash from `devcert/localhost.hex`. The browser pins this
hash through `serverCertificateHashes`. The Foctet handshake uses a reliable
stream; application payloads use datagrams.

## UDP datagrams

`udp_datagram_split` supports loopback, server, and client roles. Its options
include `--control-addr`, `--udp-addr`, `--datagrams`, and `--anti-amplification`.
It demonstrates a pre-validation response budget and lifts that budget after
receiving the first authenticated client datagram. Address validation for a
shared UDP listener needs an application-specific protocol; see the
[transport requirements](../../docs/transport-matrix.md#server-admission).

Demo keys and certificates are for local testing. See the
[example guide](../../docs/examples.md) for HTTP and archive examples.
