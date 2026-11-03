# Choosing a Foctet integration

Choose by data lifetime and where plaintext may be accessed. A service that
opens ciphertext is a trusted endpoint, including a Worker or database API server.

| Use case | Layer | Application responsibilities |
| --- | --- | --- |
| Live peer connections | `foctet-transport` | Peer trust, connection establishment, authorization, delivery policy |
| HTTP request/response bodies | `foctet-http` | HTTPS, authorization, shared replay storage, visible routing metadata |
| Persistent records | Signed storage APIs | Trusted writer pins and revisions, backend access control |
| Offline files and exports | `foctet-archive` | Recipient keys, writer trust, distribution and retention |

## Authenticated connections

Use `ProductionSessionAuth::pinned_identity` with a local Ed25519 identity and
the expected remote `PeerIdentity`. Call the transport builder's
`establish_production_initiator` or `establish_production_responder`.
If an outer channel already authenticates the peer, bind the session to it with
`ProductionSessionAuth::authenticated_channel` and its `ChannelBinding`.

See [transport support](transport-matrix.md) for byte streams, messages,
datagrams, and backend features. Datagrams require a separate reliable control
channel for handshake and rekey. Reconnect with a fresh session after terminal
errors; see [error handling](error-handling.md).

## HTTP bodies

Use `HttpSealer::seal_request_with_context` and
`HttpOpener::open_request_with_context`, or their axum / Workers adapters.
Multi-instance services need a shared atomic replay store. Authenticate the
outer channel and authorize requests separately.

Protected context authenticates selected request metadata but does not hide
methods, URLs, status codes, or outer headers. The `x-foctet-scope: body-only`
header describes this boundary; it does not authenticate the sender.
See [context rules](http-canonicalization.md) and [key rotation](key-rotation.md).

## Persistent records

Encrypt and sign at the trusted data endpoint, then store the complete opaque
record. Use core signed storage APIs for binary records, `foctet-storage` for
native database adapters, or `foctet-storage-wire` for TEXT records and SQL plans.
JavaScript adapters support selected client interfaces.

Keep writer pins and expected revisions outside the untrusted store's rollback
domain. Conditional writes do not replace these trust checks. See
[storage integration](storage-integration.md), [portable TEXT storage](worker-databases.md),
and [blind storage](zero-knowledge-workers-storage.md).

## Files and archives

Use `SignedArchive` or `SignedSplitArchive` when readers must authenticate the
writer. For large single-recipient files, use the signed file-streaming API.
Distribute encrypted bytes through the application's storage or transport.
Readers need an independently trusted writer key and the recipient private key.

Use randomized builders. Deterministic `*_with_secrets` APIs are for fixtures
and interoperability tests: reusing secrets can reuse encryption keys and nonces.
Split archives segment data; threshold recovery is a separate, optional API that
requires recovery shares to be provisioned before key loss.

See [security boundaries](security-boundaries.md) for the consequences of key
compromise and the checks required before using decrypted data.
