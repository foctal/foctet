# Zero-Knowledge Storage on Cloudflare Workers

How to use foctet so a Cloudflare Workers backend stores and moves user data it
**cannot read** — the model for a password manager or any end-to-end-encrypted
app whose clients are any Rust Apps and whose server is a Worker.

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
// ... store `blob` in KV / D1 / R2 / a Durable Object, keyed by the record id ...
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
- **R2** — for large attachments, seal with `foctet-archive`
  (`create_split_archive_from_bytes`) and store the parts as R2 objects.
- **Durable Objects** — hold per-user coordination state and opaque blobs; a DO
  also backs strongly-consistent anti-replay (see
  [`DurableObjectReplayStore`](../foctet-http/src/workers.rs)).
- **Queues** — enqueue sealed bytes for async fan-out. Queues redeliver, so make
  consumers idempotent; dedupe by the record/message id with an
  `AsyncReplayStore` (e.g. a Durable Object) if a duplicate would cause harm.

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
