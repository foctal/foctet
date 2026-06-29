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

`muxtls_split` and `webtrans_split` are currently **loopback-only** smoke tests:
muxtls pre-establishes its Foctet sessions in-process (mutual TLS is the peer
authenticator), and WebTransport's meaningful real test is a browser client
against a native server (see `tests.md` §3.5). A two-process muxtls variant
(running the Foctet handshake over the muxtls stream) is future work.

Notes:

- Demo certificates and keys are for local development only.
- Transport metadata remains visible to the underlying transport.
- For a full cross-crate map of examples, see `docs/examples.md`.
