# Portable signed TEXT storage

Use signed TEXT records when an application needs a transportable ASCII value
or its database driver handles strings more easily than binary values. The codec
is independent of a hosting provider; SQL plans and JavaScript adapters connect
it to supported driver interfaces.

The shared format is `FCT1.<standard padded Base64 ciphertext>.<standard padded
Base64 Ed25519 signature>`. The signature uses the existing signed storage-record
protocol; namespace, record ID and revision are authenticated. There is no writer
key or authoritative version inside the text value. Both must be independently
trusted at the decrypting endpoint. The SQL row's version is a concurrency guard.

## Responsibility boundary

| Foctet provides | The application provides |
| --- | --- |
| Encryption and mandatory signature verification in signed APIs | Authorized writer pins, recipient-key provenance, rotation and revocation |
| Canonical bounded ASCII encoding; ciphertext and signature stored together | Request/body limits before buffering, DB quotas and tenant authorization |
| Parameterized SQL plans and atomic compare-and-swap (CAS) | Existing driver/socket connection, credentials, TLS, timeout and connection lifetime |
| Verification against an expected namespace, object ID and version | Trusted latest-version checkpoints outside the untrusted database |
| Rejection of tampering, wrong writer and wrong expected context | Device enrollment, recovery approval, migration of historical unsigned data |
| Reproducible driver and runtime tests | Production routing, caching, TLS, quotas and failover validation |

A blind storage service never receives private decryption keys. If the application
decrypts inside that service, it is a trusted endpoint and can see the plaintext.
Foctet cannot authorize an HTTP caller, prevent deletion/denial of service, encrypt
metadata used for routing, or make server-side plaintext processing opaque.
A signed old record is still valid for its old revision: do not trust a database's
latest-version response as your sole freshness authority. This record adapter is
not a durable authentication replay store.

## JavaScript adapters

`packages/worker-storage` is a dependency-free runtime ESM adapter with TypeScript
declarations. It is currently a private workspace package, not an npm release.
Use its source module or a local workspace dependency. Test drivers are
devDependencies.

| Factory | Connection interface |
| --- | --- |
| `tursoStore(client)` | A libSQL client exposing `execute({ sql, args })` |
| `hyperdriveStore(connection)` | A mysql2 promise connection exposing `execute(sql, args)` |

The factories accept existing connections. They do not configure a particular
hosting topology or manage connection lifetime. Despite its name,
`hyperdriveStore` uses the mysql2 interface and does not itself require a
Hyperdrive binding. The application selects and configures its driver.

Seal at the endpoint using the WASM SDK:

```js
const signed = wasm.sealSignedStorageRecord(
  plaintext, recipientPublicKey, recipientKeyId,
  namespaceBytes, recordIdBytes, 1n, authorizedWriterIdentity,
);
const text = signed.toStorageText();
signed.free();
// Send text to the authorized blind service. Never send endpoint private keys.
```

### libSQL connection example

The following example uses the libSQL web client. Configure the connection URL
and authentication for the database service in use:

```js
import { createClient } from '@libsql/client/web';
import { tursoStore } from './worker-storage/index.mjs';

// Use a connection lifetime appropriate to the runtime and authoritative routing.
const client = createClient({ url: databaseUrl, authToken: databaseAuthToken });
try {
  const store = tursoStore(client, { maxBytes: 256 * 1024 });
  // Run initialize() only from an explicit, authorized migration procedure.
  const inserted = await store.compareAndSwap(authorizedOpaqueKeyHex, null, text);
  // false is a conflict. For revision 2, pass 1n as the previous revision.
} finally {
  client.close();
}
```

### MySQL-compatible connections

Pass an existing `mysql2/promise` connection to `hyperdriveStore(connection)`.
The adapter uses parameterized statements and requires an InnoDB table. Configure
connection options, TLS and timeouts for the database and runtime, and close the
connection when its application-defined lifetime ends.

When using Cloudflare Hyperdrive specifically, obtain the connection fields from
the binding, set `disableEval: true` on mysql2, and enable `nodejs_compat` in the
Worker. Use a cache-disabled Hyperdrive configuration for authoritative reads;
the adapter cannot inspect or override account-level caching. Do not rely on SQL
comments to bypass caches.

### Reads and write outcomes

Use authoritative reads for operations that require current database state. A
cached or replicated result may be stale even when its signature is valid. Use a
fresh read to reconcile an ambiguous write timeout; the adapters do not retry
writes automatically. A write acknowledgement or row existence does not
authenticate the stored contents.

Read the exact independently expected revision and verify on the endpoint:

```js
const text = await store.get(authorizedOpaqueKeyHex, expectedRevision); // bigint
if (text === null) throw new Error('Expected record is unavailable');
// Perform this on the decrypting endpoint, not a blind storage service:
const plaintext = wasm.openSignedTextStorageRecord(
  text, recipientSecretKey, namespaceBytes, recordIdBytes,
  expectedRevision, independentlyPinnedWriterKey,
);
```

`openRecord(wasm, ...)` is an equivalent JS helper for an SDK exposing the existing
`openSignedStorageRecord` binding. `encodeRecord`/`decodeRecord` are codecs only;
parsing successfully does not prove authenticity. No unsigned fallback exists.

## Rust codec and SQL plans

Use `foctet-storage-wire` directly (`default-features = false` on foctet-core), or
`foctet::storage_wire` with the `storage-wire` feature. It compiles for
`wasm32-unknown-unknown` with Rust 1.88, has no SQLx/Tokio/HTTP driver dependency,
and works with existing drivers that bind scalar SQL parameters. `Dialect::Libsql`
and `Dialect::Mysql` select the supported SQL dialects; other drivers can store
the text record using their own statements.
The separate `foctet-storage` crate remains a native SQLx/reqwest adapter.

```rust
use foctet_storage_wire::{Dialect, TextRecord, TextStore, MAX_TEXT_BYTES};

// At a blind storage service, parse only. Do not claim this validates a writer.
let value = TextRecord::parse(incoming_text, MAX_TEXT_BYTES)?;
let store = TextStore::new(Dialect::Mysql);
let plan = store.compare_and_swap([0x42; 32], Some(1), &value)?;
// Execute plan.sql with each plan.args value bound as a scalar SQL string.
// For a scalar-only driver: map args through serde_json::Value::String.
// Never interpolate strings into SQL or reinterpret them as binary JSON arrays.
```

`TextRecord::seal` and `TextRecord::open` wrap the core signed storage API on the
endpoint. `TextStore` produces statements, not network I/O. The application's
bridge must execute one statement atomically, preserve integer precision and
return affected rows. An INSERT duplicate primary key is conflict; other errors
must propagate. Use `TextStore::write_succeeded` to accept zero for conflict or
one for success and reject any other affected-row count. Do not treat permission
errors, disconnection or malformed responses as conflicts. JS adapters implement
these checks for their supported clients.

Migration uses `store.schema()` and must verify any existing MySQL/MariaDB table's
engine is InnoDB. The JS MySQL adapter performs this check in `initialize()`.
The text table is separate from the native binary adapter's table. Never silently
recreate, drop or convert an existing application's table.

## Bounds and semantics

- Maximum encoded text: 1 MiB; select a smaller application upload budget if needed.
  This bounds codec allocations, not driver buffering or network response parsing.
- Base64 adds approximately one third to ciphertext size plus 94 format/signature
  bytes. A custom SQL driver hex-encoding strings doubles this ASCII SQL payload.
  The default stays below a single MySQL packet; configured server limits can be
  smaller. Use encrypted object/file storage for larger payloads.
- All SQL arguments are scalar strings. Versions use explicit SQL casts and JS
  `bigint` (1 through 2^63−1); no floating-point version conversions are used.
- Storage keys are exactly 32 bytes / 64 lowercase hex characters. Apps assign
  opaque keys and enforce their tenant ownership; a public hash may leak names.
- Insert starts at revision 1. Update changes the payload and increments revision
  in one conditional SQL statement. Only one concurrent writer wins.
- No implicit delete or reset is provided. Tombstones should be signed revisions;
  resetting to revision 1 would undermine trusted freshness checkpoints.
- A blind store can accept an unauthorized or wrong-context signed value. The
  decrypting endpoint rejects it. Enforce service-side write authorization too.

Release-specific changes and historical-data migration notes are in
[CHANGELOG.md](../CHANGELOG.md). Application authorization, key lifecycle and
trusted revision checkpoints remain independent of the chosen storage adapter.

## Verification

```sh
cargo test -p foctet-storage-wire --locked
cargo check -p foctet-storage-wire --target wasm32-unknown-unknown --locked
cd packages/worker-storage
npm ci
npm test
npm run test:types
npm run test:databases
```

The database test requires Docker, Rust with the WASM target, and a wasm-bindgen
CLI matching Cargo.lock. It creates loopback-only disposable libSQL and MariaDB
containers, bundles an actual workerd fixture using `@libsql/client/web` and
`mysql2/promise`, and configures a local Hyperdrive binding. It checks signed
Rust↔WASM↔JS text, insert/update races, restart persistence, precision beyond 2^53,
and endpoint rejection of tampering and stale versions. The fixture has no HTTP
authorization and must not be deployed. Local Hyperdrive emulation is not the
managed service's cache, TLS termination, region routing or production failover.

References: [Cloudflare Turso guide](https://developers.cloudflare.com/workers/tutorials/connect-to-turso-using-workers/),
[Hyperdrive MySQL configuration](https://developers.cloudflare.com/hyperdrive/examples/connect-to-mysql/),
[Hyperdrive query caching](https://developers.cloudflare.com/hyperdrive/concepts/query-caching/).
