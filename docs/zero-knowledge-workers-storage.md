# Blind storage backends

A blind storage backend persists and forwards data that it cannot decrypt. The
cryptographic model is independent of the database, hosting provider and server
framework: encryption and decryption happen at trusted endpoints, while the
backend receives opaque ciphertext and the metadata required to route it.

Here, "zero-knowledge storage" means that the backend has no decryption keys. It
does not imply zero-knowledge proofs or concealment of access patterns, record
sizes or routing metadata.

## Choose the decryption boundary

| Pattern | Who decrypts | Foctet API |
| --- | --- | --- |
| Blind storage | Trusted data endpoints; the storage service cannot decrypt | Signed APIs in `foctet_core::storage` |
| Encrypted request/response | The application endpoint processing the request | Protected-context APIs in `foctet-http` |
| Encrypted file storage | Authorized archive recipients | Signed archives and file streaming in `foctet-archive` |

A service that processes plaintext is a trusted endpoint for that data. Transport
encryption, database authentication and encryption at rest do not make that
service blind. Choose the boundary separately for each operation.

## Seal and authenticate records

The endpoint binds the expected namespace, record ID and version into the record.
A pinned writer signature prevents an untrusted store from replacing the record
with a new envelope encrypted using the public recipient key. Store ciphertext
and signature atomically; obtain the writer pin independently of the store.

```rust
use foctet_core::{StorageRecord, seal_signed_storage_record, open_signed_storage_record};

let record = StorageRecord::new(namespace, record_id, expected_version);
let (ciphertext, signature) = seal_signed_storage_record(
    plaintext, recipient_public_key, recipient_key_id, record, &writer, &limits,
)?;
// Persist ciphertext and signature together using the selected backend.
let plaintext = open_signed_storage_record(
    &ciphertext, signature, recipient_secret_key, record, trusted_writer, &limits,
)?;
```

The reader must supply its independently expected descriptor and writer identity:

- The recipient key provides confidentiality.
- The signature authenticates the writer against the trusted pin.
- Namespace and record identity binding prevent cross-record substitution.
- Expected version binding rejects stale records only when the reader has a
  trustworthy freshness checkpoint. A database-reported revision is insufficient.

These properties do not prevent deletion, withholding or denial of service.

## Choose the stored representation

| Representation | Use when | API |
| --- | --- | --- |
| Ciphertext bytes and detached signature | The driver supports binary values | Core signed storage APIs or `StoredRecord` in `foctet-storage` |
| Canonical signed TEXT value | An ASCII value is convenient for the driver or transport | `TextRecord` in `foctet-storage-wire` or the WASM signed TEXT API |
| Signed archive or file stream | Data is stored or delivered as files/objects | `SignedArchive`, `SignedSplitArchive` or `foctet_archive::streaming` |

Encoding ciphertext as text does not add encryption. Preserve the exact signed
bytes and enforce size limits before buffering untrusted input. For SQL storage,
use bound parameters and select column capacities for the complete encrypted
representation, including signatures and encoding overhead.

| Database family | Binary column |
| --- | --- |
| PostgreSQL | `BYTEA` |
| MySQL / MariaDB | An appropriately sized `BLOB` family column or `VARBINARY` |
| SQLite / libSQL-compatible services | `BLOB` |

Signed TEXT records can be stored in a sufficiently sized text column. The native
and portable adapters have separate schemas; apply their migrations explicitly.
See [storage integration](storage-integration.md) and
[portable TEXT storage](worker-databases.md) for supported interfaces and limits.

## Routing metadata and concurrency

Keep intentionally visible metadata separate from the encrypted payload. A row
may contain an opaque storage key, revision, ciphertext and signature; a TEXT
record already carries ciphertext and signature together. The backend may use
routing metadata for authorization, quotas and conflict detection, but must not
derive searchable columns from decrypted fields while claiming to remain blind.

Ensure the authenticated record identity also distinguishes tenants. A tenant
column used only for routing is not itself cryptographic tenant binding.

Conditional updates can prevent concurrent writers from overwriting one another.
They do not establish the reader's trusted latest version. Define checkpoint
storage, conflict resolution and recovery independently. Do not reset revisions
or reuse identifiers in a way that makes an old signed record current again.

## Backend-specific concerns

The same record representation can be carried by SQL databases, object stores,
key/value services and queues. Applications must account for their differing
atomicity, consistency, size limits, expiration and retry behavior. A cache may
return a valid but old signed record. Queue consumers must handle redelivery.

Connection proxies and platform bindings change how the backend is accessed,
not who can decrypt the payload. Use the native adapter where supported, or pass
opaque records through an existing driver. Drivers, credentials, connection
lifetime and authoritative-read routing must match the deployment.

The [`workers-kv-vault` example](../foctet-http/examples/workers-kv-vault/README.md)
illustrates one implementation using a key/value service. It is an example of the
storage boundary, not a required deployment architecture.

## Application responsibilities

Applications manage key distribution, endpoint security, authorization, and
recovery. See [key policies](POLICIES.md) and
[security boundaries](security-boundaries.md) for these requirements.

Foctet does not require a password-derived account key or a particular multi-device
identity design. If an application derives or wraps keys, it owns that protocol
and its recovery policy. Multi-recipient archives can protect a payload for
several recipients; the application authenticates those recipients and the writer.
See [key rotation](key-rotation.md) and [security boundaries](security-boundaries.md).
