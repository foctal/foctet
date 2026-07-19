# Operations, observability, and sizing

This document defines the v1 operational contract. It complements the exact
hard ceilings in `resource-limits.md` and transport requirements in
`transport-matrix.md`.

## Safe defaults and sizing

Keep the library defaults unless a measured workload requires a lower value.
Public configuration is clamped to protocol hard ceilings and cannot disable
the bounds. In particular:

| Surface | Safe starting point | Sizing rule | Backpressure behavior |
| --- | --- | --- | --- |
| Ordered streams | Default frame and TX-buffer limits | Bound the application queue separately; budget one maximum frame plus the bounded TX buffer per active channel | A pre-delivery full buffer is recoverable; drain before retrying |
| Messages | `DEFAULT_MAX_MESSAGE_SIZE` | Clamp to the backend's lower message limit | Queue rejection before acceptance is recoverable; backend send failure is terminal |
| Datagrams | 1200-byte on-wire default | Lower it to the proven path MTU; never depend on fragmentation | Oversize output is rejected before delivery; loss is not backpressure |
| HTTP bodies | 64 MiB one-shot default | Prefer streaming for large bodies and cap aggregate request concurrency | Streaming holds at most one undecoded maximum frame; incomplete bodies are rejected |
| Archives | 512 MiB in-memory plaintext maximum | Budget plaintext plus encrypted chunks and metadata; use an application-level smaller cap under constrained runtimes | No streaming archive format exists; input above the cap is rejected |
| Workers replay | One Durable Object entry per message ID until expiry | TTL multiplied by peak accepted request rate determines retained state | Store failure rejects the request; never bypass replay protection |

Every release candidate must run:

```bash
cargo run --release -p foctet --example release_benchmark --locked
/usr/bin/time -l cargo run --release -p foctet --example release_benchmark --locked
```

Record CPU, OS, Rust version, build profile, throughput, mean latency, and peak
resident memory in the release evidence. Compare with the previous release; a
greater than 10% regression requires an explanation or fix. These numbers are
sizing evidence for that machine, not a universal performance promise.

## Structured metrics

`SessionEvent::metric`, `CoreError::security_metric`,
`BodyEnvelopeError::security_metric`, and `HttpError::security_metric` expose
stable, secret-free, low-cardinality categories. Export counters using the
returned labels. Never attach plaintext, ciphertext, key IDs, message IDs,
identity keys, route strings, header values, or raw errors as metric labels.

Required counters and alert signals:

| Label | Meaning | Suggested alert |
| --- | --- | --- |
| `foctet.handshake.completed` | Authenticated channel established | Capacity/baseline only |
| `foctet.handshake.failed` | Authentication, identity, or timeout failure | Sustained rate above baseline |
| `foctet.aead.failure` / `foctet.http.aead.failure` | Authentication or crypto failure | Any sustained burst |
| `foctet.replay.rejected` / `foctet.http.replay.rejected` | Duplicate or stale protected input | Rate above expected retry baseline |
| `foctet.limit.hit` / `foctet.http.limit.hit` | Resource/admission cap reached | Capacity review or abuse signal |
| `foctet.rekey.completed` | Ratchet generation applied | Missing events on long-lived busy channels |
| `foctet.send.ambiguous` | Delivery uncertain; channel discarded | Alert immediately and inspect transport health |
| `foctet.http.replay_store.failure` | Durable replay decision unavailable | Alert immediately; protected traffic must fail closed |

Rate-limit pre-authentication work before allocating a session: cap concurrent
handshakes, use per-source token buckets where the transport supplies a trusted
source, enforce a short handshake deadline, and avoid expensive identity or
signature lookup before size and syntax validation. Do not key a global metric
by untrusted source input.

## Shutdown, cancellation, and restart

Graceful shutdown stops admission first, lets already accepted writes flush up
to a bounded deadline, and then discards every session. A cancelled or aborted
write whose accepted-byte count is unknown is an ambiguous send and makes the
channel terminal. An incomplete streaming body exposes no successful final
plaintext. Partial reads, EOF, authentication failure, invalid control state,
and backend close are terminal for the affected channel.

Foctet has no persisted traffic-session or transport-resume format. After a
process restart or reconnect, establish a fresh authenticated session. Durable
HTTP replay state survives independently and must remain available across
Workers restarts. Exactly-once delivery, durable acknowledgements, retry after
an ambiguous send, offline queues, and process-crash recovery require
application-level message IDs, persistence, and idempotency; Foctet does not
claim those guarantees.
