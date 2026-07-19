# Resource Limits

Foctet applies hard resource ceilings before copying attacker-controlled fields,
allocating count-derived collections, or starting cryptographic work. Public
configuration may tighten these limits but cannot raise a hard ceiling.

| Surface | Default | Hard maximum | Enforcement point |
| --- | ---: | ---: | --- |
| Handshake/control message | 199 bytes | 199 bytes | Length prefix is checked before allocation and control decoding |
| Ed25519 identity/signature | 32 / 64 bytes | Fixed by the wire format | Fixed-size decoding precedes signature verification |
| Outer-channel binding | 1–1024 bytes | 1024 bytes | `ChannelBinding::new` checks before copying or transcript hashing |
| Frame ciphertext | 16 MiB | Configured receiver limit | Header length is checked before body allocation |
| Buffered framed output | 64 MiB | Configured sender limit | Checked before frame enqueue |
| Replay window | 4096 slots | 65,536 slots | Configuration is clamped before bitmap allocation |
| Replay windows / inbound stream IDs | 1024 | 4096 | New map entries are rejected at capacity |
| Outbound message/datagram stream IDs | 1024 | 4096 | New sequence-map entries are rejected before encryption |
| Retained previous traffic keys | 2 | 16 | Configuration is clamped before key retention |
| Message | 16 MiB | Configured endpoint limit | Checked before parsing or emitting |
| Datagram | 1200 bytes | Configured endpoint limit | Checked before parsing or emitting |
| Body recipients | 16 | Configured parser limit | Declared count is checked before recipient parsing or key unwrap |
| Body context | 64 KiB | Configured body limit | Checked before copying or AEAD |
| HTTP opener keyring | 16 keys | 16 keys | Construction stops before retaining key 17 |
| HTTP bound headers | 32 | 32 | Count is checked during policy iteration |
| HTTP bound header name/value | 256 bytes / 16 KiB | Fixed HTTP limit | Checked before copying into protected context |
| HTTP protected context | 64 KiB | 64 KiB | Aggregate variable data is checked before AAD construction |
| Archive recipients | 1024 | 1024 | Checked before wrapper allocation or X25519 |
| Archive chunks | 65,536 | 65,536 | Checked before hashing plaintext or allocating chunk records |
| Archive split parts | 65,536 | 65,536 | Checked before manifest maps and part iteration |
| Archive chunks per part | 65,536 | 65,536 | Checked before part record allocation |
| Concurrent handshakes/sessions | Caller-selected | 65,536 | `HandshakeConcurrencyLimiter` rejects before handshake work |

`HandshakeRateLimiter` independently bounds admission rate. A server should
share both limiters across its accept loop and retain a concurrency permit for
as long as it wants the admitted handshake or session to count against the
concurrent-work budget.

Exceeding a recoverable local configuration limit does not consume a sequence
number or make an endpoint terminal. Authenticated protocol failures and
receiver-side replay-capacity failures follow the terminal policy documented in
[Error Handling](error-handling.md).
