# Changelog

## [Unreleased]

Target version: 0.6.0.

### Added

- WebSocket adapters use websock 0.6.1 components. The message adapter depends
  on the backend-neutral `websock-proto` interface, preserving connection trait
  identity. A workerd regression checks the published facade alongside workers-rs
  0.8.7, HTTP/storage features and authenticated encrypted WebSocket messages.
- Portable `AsyncTextStore` and a `TextDriver` bridge with non-`Send` futures for
  request-scoped database connections, including drivers on workers-rs sockets.
- Optional `foctet-storage-wire/workers` adapters for D1 and remote libSQL over
  Fetch, with bounded responses, cancellation, timeouts and redirect rejection.
  Runtime tests cover workers-rs 0.8.7, including its `http` feature.
- Streaming input limits in the workers-rs HTTP opener and Durable Object replay
  handler, enforced before accumulating oversized bodies.

- Detached ciphertext signatures and signed storage-record APIs with independently
  pinned writer verification.
- Signed HTTP bodies and a signed-chunk API, signed single/split archives,
  bounded-memory `FOCTETFS` file streams, and optional threshold archive recovery.
- `foctet-storage`: native SQLite, PostgreSQL, MySQL and MariaDB adapters, an
  optional remote Turso/libSQL Hrana adapter, conditional updates and atomic replay
  storage. This crate requires Rust 1.94; existing cryptographic and transport
  crates retain Rust 1.88.
- `foctet-storage-wire`: portable signed TEXT encoding and parameterized SQL plans
  for libSQL and MySQL-compatible drivers, also exposed through the optional
  `foctet::storage_wire` facade. This crate supports Rust 1.88 and WebAssembly.
- JavaScript storage adapters for libSQL-web and mysql2 connections, with
  TypeScript declarations, bounded text records and `bigint` revisions.
- WASM signing, signed-record verification, `SignedObject.toStorageText()` and
  `openSignedTextStorageRecord` APIs.
- Database/runtime conformance tests, signed-format vectors, parser fuzz coverage
  and checks that distributed crate fixtures match canonical vectors.

### Changed

- `HttpStreamOpener` borrows its replay store and has lifetime/store type
  parameters. Request construction validates the header; replay state is consumed
  after the first authenticated chunk. Replay errors can therefore arise when
  opening that chunk. Keep the store alive for the opener's lifetime. Response
  openers use the default store type without retaining a store. Stream-reader
  errors are terminal.
- `ArchiveBuildSecrets` implements `Drop` and redacts secrets in `Debug` output.
  Code that moved fields out of this struct must borrow them or explicitly clone
  a required value.
- HTTP body replacement removes obsolete framing headers. Additional bound
  headers cannot include rewritten content type/framing fields or the
  `x-foctet-*` namespace.
- Native-only archive property tests and filesystem APIs are excluded from
  WebAssembly targets. The archive crate's applicable targets compile for WASM;
  this does not imply filesystem support in browsers.

### Security

- Redact session ratchet roots in `Debug`, including nested transport diagnostics.
  Erase ephemeral secrets on terminal closure and guard temporary DH/root values
  across fallible rekey preparation.
- Close the paired session on terminal receive failures, including malformed
  control messages, TLV failures, and EOF in secure channels. A closed session
  cannot continue receiving through a transport that still holds shared keys.
- Reject authenticated non-increasing sequences in reliable stream/message
  adapters; datagram reordering remains supported. Replay bitmap shifts now
  reuse their allocation and are checked against a set model at word boundaries.
- Use constant-time all-zero X25519 shared-secret validation. Document
  ciphertext-only breach protection separately from recipient-key compromise,
  retained session keys, and deployment acceptance.

- Require a trusted peer pin or authenticated channel binding for default
  authenticated sessions; arbitrary self-signed peers are rejected.
- Use strict Ed25519 verification and verify pinned writers before opening signed
  records, bodies and archives.
- Harden replay expiry, streaming finalization, terminal failure handling,
  parser/response limits and cleanup of owned secret/plaintext buffers.
- Validate database dialects, transactional MySQL/MariaDB storage engines and
  remote response shapes. Update dependencies and remove the obsolete advisory
  exception.

### Upgrade notes

Existing body, archive and frame vectors remain byte-compatible. New signed APIs
and formats do not automatically authenticate existing unsigned data or provide
an unsigned fallback. Applications must provision trusted writers and expected
revision checkpoints, and establish the provenance of historical data before
re-encrypting or signing it. Do not treat arbitrary database responses as trusted
history. Keep tenant/object identity canonical and authenticated.

The portable TEXT adapter uses a separate table from the native binary adapter.
Apply schema migrations explicitly and preserve existing data. Use authoritative
reads for freshness-sensitive operations; cached or replicated reads require an
application policy that accounts for staleness. Neither dependency upgrades nor
SQL compare-and-swap establish trusted freshness on their own.

See [storage integration](docs/storage-integration.md),
[portable TEXT storage](docs/worker-databases.md) and
[API stability](docs/api-stability.md) for API selection and compatibility policy.
