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

Notes:

- Demo certificates and keys are for local development only.
- Transport metadata remains visible to the underlying transport.
- For a full cross-crate map of examples, see `docs/examples.md`.
