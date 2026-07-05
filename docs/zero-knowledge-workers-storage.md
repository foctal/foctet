# Zero-Knowledge Storage Backends

How to use foctet so a backend stores and moves user data it **cannot read** —
the model for a password manager or any end-to-end-encrypted app. The examples
focus on Cloudflare Workers, but the same storage model applies to D1, Turso /
libSQL, PostgreSQL, MySQL / MariaDB, R2, KV, object stores, and ordinary Rust
servers such as axum or Actix Web.

The core rule is independent of the database: the backend stores opaque
ciphertext bytes and never receives the user's plaintext or decryption key.

## Two encryption patterns

| Pattern | Who decrypts | foctet API | Use for |
| --- | --- | --- | --- |
| **Blind storage** (zero-knowledge) | client only | `foctet_core::storage` (`seal_storage_record` / `open_storage_record`) | vault items, notes, attachments — anything the server just stores |
| **Encrypted transport** | the Worker | `foctet_http::workers` (`WorkersOpener` / `WorkersSealer`) | requests the server must act on (sync metadata, sharing control) |

A zero-knowledge app is mostly blind storage, with encrypted transport only for
the few operations the server legitimately processes.

## Blind storage

The client seals a value to its own key and hands the opaque bytes to the
Worker, which stores them verbatim. Each value binds a record descriptor —
namespace, id, version — into the AEAD:

```rust
use foctet_core::{StorageRecord, seal_storage_record, open_storage_record};

let record = StorageRecord::new(b"vault-items", b"login-github", version);
let blob = seal_storage_record(plaintext, account_public_key, b"account-v1", record)?;
// ... store `blob` in KV / D1 / Turso / PostgreSQL / MySQL / R2 / any backend,
// keyed by plaintext-free metadata such as owner id, record id, and version ...
let plaintext = open_storage_record(&blob, account_secret_key, record)?;
```

The descriptor is authenticated but not stored in the envelope, so the reader
must supply the same `StorageRecord` to open it. This gives:

- **Confidentiality:** the server holds only ciphertext; it has no key.
- **Substitution resistance:** a backend cannot answer a read for record A with
  record B's ciphertext — the namespace/id in the reader's descriptor would not
  match, and the open fails.
- **Rollback resistance:** bind the version the client *expects* (tracked
  client-side or via an authenticated version pointer); serving a stale
  ciphertext then fails to open.

See the runnable [`workers-kv-vault`](../foctet-http/examples/workers-kv-vault/README.md)
example — a Worker with **no crypto dependency** that stores blobs in KV.

## Mapping to Cloudflare primitives

Blind storage produces `Vec<u8>`, so it drops into any Cloudflare store:

- **KV** — `put_bytes(id, blob)` / `get(id).bytes()`. Best for per-record vault
  items and small config. (See the example.)
- **D1** — store the blob in a `BLOB` column; index on plaintext-free columns
  only (record id, owner id, version), never on decrypted fields.
- **Turso / libSQL** — store the blob in a `BLOB` column, or encode it as
  base64/hex `TEXT` only if the client library or migration path makes binary
  values awkward. Cloudflare's TypeScript Worker integration uses
  `@libsql/client/web`; worker-rs applications commonly use `libsql-client`.
  Both are application-level database choices: foctet only requires that the
  stored value remain the exact sealed bytes.
- **R2** — for large attachments, seal with `foctet-archive`
  (`create_split_archive_from_bytes`) and store the parts as R2 objects.
- **Durable Objects** — hold per-user coordination state and opaque blobs; a DO
  also backs strongly-consistent anti-replay (see
  [`DurableObjectReplayStore`](../foctet-http/src/workers.rs)).
- **Hyperdrive to PostgreSQL / MySQL** — Hyperdrive is a connectivity layer, not
  an encryption boundary. Store foctet ciphertext in `BYTEA` (PostgreSQL) or
  `BLOB` / `VARBINARY` (MySQL / MariaDB), and keep indexes limited to
  plaintext-free metadata.
- **Queues** — enqueue sealed bytes for async fan-out. Queues redeliver, so make
  consumers idempotent; dedupe by the record/message id with an
  `AsyncReplayStore` (e.g. a Durable Object) if a duplicate would cause harm.

## SQL schema pattern

For relational databases, the safe shape is boring on purpose: split the
server-visible routing metadata from the sealed user payload.

```sql
CREATE TABLE vault_records (
    owner_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    record_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    key_id TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (owner_id, namespace, record_id)
);

CREATE INDEX vault_records_owner_version
    ON vault_records(owner_id, namespace, version);
```

The corresponding `StorageRecord` must be derived from the same logical
descriptor that the client expects:

```rust
let record = StorageRecord::new(
    namespace.as_bytes(),
    record_id.as_bytes(),
    version,
);
```

The server may use `owner_id`, `namespace`, `record_id`, and `version` for
routing, authorization checks, pagination, conflict detection, or quota
accounting. It must not derive columns from decrypted fields such as a note
title, URL, task name, email body, attachment filename, or password entry
username unless those fields are intentionally public metadata for that
application.

When binary columns are unavailable or inconvenient, store `ciphertext` as
base64 `TEXT` and decode it byte-for-byte before returning it to the client.
Do not JSON-serialize the plaintext and call that zero knowledge.

## Turso / libSQL deployment patterns

Turso works as a zero-knowledge backend when it is only the persistence layer for
sealed bytes.

- **Cloudflare Worker, TypeScript:** use Turso's Worker-compatible web client
  (`@libsql/client/web`) to insert and fetch the sealed blob. The Worker should
  receive ciphertext from the client, store it, and return ciphertext on reads.
  It does not need a foctet secret key for blind storage.
- **Cloudflare Worker, worker-rs:** use `libsql-client` or another
  wasm-compatible libSQL client. The database adapter should accept and return
  `Vec<u8>` (or encoded text) without trying to parse foctet envelopes.
- **Native Rust backend:** use the `turso` or `libsql` crate when that is the
  right operational fit for an axum / Actix Web / background worker process.
  The same zero-knowledge rule applies: store opaque bytes and keep keys on the
  end-user client.

Turso authentication tokens, database URLs, retry policy, migrations, and query
builders are application concerns. They do not belong in foctet unless foctet
itself starts owning a database service, which it intentionally does not.

## PostgreSQL, MySQL, and MariaDB

PostgreSQL, MySQL, and MariaDB are also valid blind-storage backends.

Recommended binary columns:

| Database | Ciphertext column | Notes |
| --- | --- | --- |
| PostgreSQL | `BYTEA` | Keep server-side indexes on owner/record/version metadata only. |
| MySQL / MariaDB | `BLOB`, `MEDIUMBLOB`, or `VARBINARY` | Choose the size class from the maximum sealed payload size. |
| SQLite / D1 / libSQL / Turso | `BLOB` | `TEXT` with base64 is acceptable only as an encoding workaround. |

With Cloudflare Workers, Hyperdrive can connect a Worker to PostgreSQL or MySQL,
but Hyperdrive does not change the cryptographic model. With axum, Actix Web, or
another native Rust backend, any DB library (`sqlx`, `diesel`, `tokio-postgres`,
`mysql_async`, `turso`, `libsql`, or a project-specific adapter) can be used as
long as it preserves the sealed bytes exactly.

## What belongs in foctet vs the application

foctet should provide the cryptographic storage envelope and the authenticated
descriptor binding. It should not grow database-specific adapters for every
storage engine.

foctet responsibilities:

- `StorageRecord` descriptor binding.
- `seal_storage_record` / `open_storage_record`.
- archive formats for large sealed objects.
- HTTP protected-context helpers for requests that the server must process.
- documentation and test vectors for the wire formats.

Application responsibilities:

- database schema, migrations, pooling, retries, and credentials;
- Cloudflare bindings, Turso tokens, Hyperdrive configuration, or native DB
  connection strings;
- authorization for who may create, read, update, or delete a record id;
- conflict resolution, version allocation, pagination, quotas, and retention;
- deciding which metadata is intentionally visible to the backend.

## Safe and unsafe patterns

Safe patterns:

- Store `ciphertext` plus `owner_id`, `namespace`, `record_id`, and `version`.
- Bind the same namespace/id/version into `StorageRecord`.
- Return ciphertext to the client and let the client decrypt.
- Use encrypted transport separately for server-processed control operations.
- Use `foctet-archive` or split archives for large attachments.

Unsafe patterns:

- Decrypt in the Worker or backend and store plaintext in SQL.
- Store searchable decrypted fields next to the ciphertext and still call the
  design zero knowledge.
- Let the server choose a different descriptor than the client expects.
- Treat database encryption-at-rest, Turso auth tokens, TLS, Hyperdrive, or
  private networking as a replacement for client-side foctet encryption.
- Reuse one ciphertext under a different namespace/id/version and expect it to
  open.

## Sharing and multiple devices

- **One account, many devices:** derive one account keypair from the master
  password; every device holds the same key, so single-recipient
  `seal_storage_record` reads everywhere.
- **Sharing with other users:** wrap one payload to several recipient public keys
  with `foctet-archive` (`create_archive_from_bytes(payload, &[pub_a, pub_b, …])`),
  and store the archive bytes like any other blob.

## Client key management (out of foctet's scope)

foctet encrypts to X25519 keys; it does not derive them from a password. The
client is responsible for:

- deriving the account key from the master password with a memory-hard KDF
  (Argon2id) and never uploading it;
- rotating the account key with an overlap window if it changes (see
  [Key rotation](key-rotation.md));
- authenticating the outer transport (TLS) and the user session separately —
  blind storage protects data at rest, not who is allowed to read or write a
  given record id.
