# Transport examples

These examples show the recommended Foctet transport-builder flow over real stream transports.

Start with:

- `quinn_split.rs`
- `webtrans_split.rs`
- `websock_split.rs`
- `muxtls_split.rs`

Common properties:

- They use `TokioTransportBuilder`.
- They run the native Foctet handshake per stream.
- They pin peer identities with `SessionAuthConfig`.
- They assert `peer_authenticated()` before exchanging application data.

## Running across two processes / two hosts

`quinn_split` and `websock_split` take a `--role`:

- `--role loopback` (default): both peers in one process, ephemeral port — a
  quick smoke test (`cargo run --example quinn_split ...` with no args).
- `--role server --addr <ip:port> --tls-cert devcert/localhost.crt --tls-key devcert/localhost.key`
- `--role client --addr <ip:port> --tls-cert devcert/localhost.crt`

Generate the dev cert first with `devcert/generate.sh`. Add `--wrong-identity`
to the client to see the server reject a mismatched pinned identity
(`peer identity mismatch`). For two real hosts, copy `devcert/localhost.crt` to
the client and dial the server's address; the client validates SNI `localhost`,
which the cert's SAN covers. See `tests.md` (§3) for the full runbook.

`quinn_split` also takes `--messages <M>` (request/reply round-trips per stream)
and `--rekey-frames <N>` (lower `RekeyThresholds::max_frames` to force frequent
DH-ratchet rekeys); it prints each rekey so the alternating ratchet is
observable. See `tests.md` (§7) for the rekey runbook.

`udp_datagram_split` is the raw-UDP two-process driver: it runs the Foctet
handshake over a reliable TCP control channel, then exchanges sealed datagrams
over a connected `UdpDatagramTransport`. The server enables
`with_anti_amplification(3)` and refuses to send until the first client datagram
validates the address. It takes `--role`, `--control-addr`, `--udp-addr`,
`--datagrams`, and `--anti-amplification`. See `tests.md` (§3.6).

`websock_message_server` is the native raw-WebSocket **message** endpoint
(`WebsockMessageTransport` + `SecureMessageChannel`, one Foctet frame per binary
WebSocket message) — the counterpart the browser WASM SDK speaks with
`sealMessage`/`openMessage`. `--role server` is the responder for the browser
interop page (`foctet-wasm/examples/browser/websocket.html`); `--role client` /
`--role loopback` drive the same wire format natively. Needs
`--features "runtime-tokio transport-websock"`. See `tests.md` (§3.3).

`webtrans_datagram_split` is the native WebTransport **datagram** endpoint: the
authenticated Foctet handshake runs over a reliable bidi stream, then sealed data
flows as WebTransport datagrams (one Foctet datagram frame each — what the browser
SDK's `sealDatagram`/`openDatagram` produce). `--role server` (with
`--tls-cert`/`--tls-key`) is the responder for the browser page
(`foctet-wasm/examples/browser/webtransport.html`, which pins the cert via
`serverCertificateHashes`); `--role client` / `--role loopback` drive the same
wire format natively. Needs `--features "runtime-tokio transport-webtrans"`. See
`tests.md` (§3.5). (`webtrans_split` remains the streams-only loopback smoke
test.)

`muxtls_split` and `webtrans_split` are currently **loopback-only** smoke tests:
muxtls pre-establishes its Foctet sessions in-process (mutual TLS is the peer
authenticator), and WebTransport's meaningful real test is a browser client
against a native server (see `tests.md` §3.5). A two-process muxtls variant
(running the Foctet handshake over the muxtls stream) is future work.

Notes:

- Demo certificates and keys are for local development only.
- Transport metadata remains visible to the underlying transport.
- For a full cross-crate map of examples, see `docs/examples.md`.
