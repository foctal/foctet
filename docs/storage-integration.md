# Signed storage and recovery integration

Encrypt and sign at the endpoint, before calling any database or cloud API.
Provision the recipient key, trusted writer pin, canonical tenant/object identifier,
and expected revision independently of the untrusted store. Database credentials
only authorize storage access; they are not encryption keys.

Choose a storage API based on the runtime and driver interface. The native
adapter manages supported SQL connections. For an existing driver or a runtime
that cannot use the native adapter, see [portable TEXT storage](worker-databases.md)
for signed text records, parameterized SQL plans and JavaScript adapters.

## Database adapters

`foctet-storage` is a separate optional driver crate requiring Rust 1.94 because
SQLx 0.9 requires it. Existing cryptographic/transport crates retain Rust 1.88.
It is not supported inside a Cloudflare Worker or a browser; those endpoints use
WASM/core record bytes and platform bindings instead. Enable `turso` for the remote
libSQL Hrana HTTP v2 adapter. There is no implicit replica or offline sync policy.

1. Create `SqlStore::connect(url, Dialect, max_bytes)` (or `TursoStore::connect`).
2. Call `initialize()` explicitly when applying the idempotent v1 schema. Existing
   incompatible schemas fail when used rather than being destructively migrated.
   MySQL/MariaDB tables are explicitly InnoDB, and initialization rejects existing
   non-InnoDB tables; the server's default engine is not trusted.
3. Use `StoredRecord::seal` with a canonical `StorageRecord` and writer identity.
4. `compare_and_swap(key, None, record)` inserts revision 1. An update requires the
   exact previous revision and advances by one. A false result means conflict.
5. Read opaque bytes with `get`, then call `open` with an independently trusted
   expected descriptor/version and writer. Never accept the store's revision as
   your only freshness authority.

Identifiers passed to the adapter are fixed 32-byte opaque keys. Derive/store
these without leaking plaintext filenames or tenant information. Ciphertext and
signature are committed together. SQL parameters bind every user value. Use the
primary database for atomic replay; replicas, KV, and caches are unsuitable.
Run `prune_replay` periodically and pass retention deadlines including clock skew.
Database protocol buffers and backend resource consumption are outside the
cryptographic library's allocation guarantee; use trusted TLS peers and quotas.

Require certificate and hostname validation (`verify-full` or driver-equivalent)
for network databases. MySQL RSA password exchange is intentionally disabled;
use TLS. The Turso adapter requires HTTPS except on loopback, rejects redirects,
limits response bytes and time, and keeps bearer tokens out of Debug/error output.
Local tests use disposable credentials and may use loopback plaintext/self-signed
TLS; these test settings are not production configurations.

Test the server databases with disposable Docker containers and SQLite locally:

```sh
python3 scripts/test-storage-databases.py
cargo test -p foctet-storage --all-features --locked
```

The script creates uniquely named containers, binds random loopback ports, and
removes only its own containers on success or failure. It tests binary roundtrip,
16 concurrent CAS writers, durable replay uniqueness, stale version rejection,
and reconnection. SQLite additionally closes/reopens an on-disk database. Real
backup restoration, cross-region replica routing, credentials, and infrastructure
failover must be validated against the application's deployed configuration.

## Signed HTTP, files and browser data

Configure `HttpSealer::with_writer` and `HttpOpener::require_writer` together.
Axum/Workers adapters constructed from these objects retain the policy. Direct
stream callers use `seal_signed_chunk` / `open_signed_chunk` with detached
signature sidecars; unsigned byte readers are not a signed-sidecar wire protocol.
See `foctet-http/tests/signed.rs` for executable request/response examples.

Use `SignedArchive` or `SignedSplitArchive` for in-memory files. For large files,
use `streaming::encrypt_stream` and `decrypt_stream_to_file`; keep object/version
in the application context. For arbitrary output writers, discard all provisional
output on error. Memory use depends on configured chunk limits, concurrent streams
and the underlying reader/writer buffers; measure it for the deployment workload.

Enable archive `threshold` for `create_threshold_archive` and
`recover_threshold_archive`. Keep the returned `RecoverySet` in trusted metadata,
protect each `RecoveryShare::expose_bytes()` under a different custodian's key,
and require the writer pin on recovery. Rotate by creating a fresh set/archive.
The threshold convenience API currently uses the bounded in-memory archive format;
it is not a threshold large-file stream API. Frozen vectors and independent JS
reconstruction cover all 2-of-3 subsets.

The WASM SDK exposes identity signing, `verifyCiphertext`,
`openSignedBodyWithContext`, `sealSignedStorageRecord`, and
`openSignedStorageRecord`. Keys are still extractable endpoint memory. External
hardware keys can implement the Rust `HandshakeSigner`; browser/WebAuthn identity
provisioning and recovery UX remain application decisions.

## Runtime and backend requirements

A storage service must preserve the complete ciphertext and signature. Configure
its object/row size limits, consistency, retries, expiration and cache behavior
for the application. Database proxies and serverless bindings do not change the
cryptographic trust boundary. Server-side content processing requires access to
plaintext and therefore makes that service a trusted endpoint.

Backend-specific integration suites are described in [testing](testing.md).
Local fixtures exercise supported interfaces; production credentials, routing,
quotas, failover and recovery remain deployment responsibilities.

## Validation and failure handling

Remote Hrana results are validated locally for response kind, completion, row and
column count, value types, version range, signature size and decoded ciphertext
budget. SQL predicates alone are not a defensive parser boundary. SQL connection
URLs must match the selected dialect. Invalid remote results fail closed.

HTTP body replacement removes stale Content-Length and Transfer-Encoding so the
transport computes framing for the new body. Rewritten content type, framing and
Foctet carrier/signature fields cannot be configured as additional bound headers;
this avoids circular signatures and contexts changed by the sealing operation.
A signed-stream API error is terminal even when caused by a missing writer pin.
Rejected/cancelled request plaintext and buffered chunks are held in zeroizing
owners until successfully returned to the application. Zeroization reduces owned
buffer retention; it does not promise erasure of compiler, allocator, third-party
cryptographic implementation, OS, or caller-created copies.
