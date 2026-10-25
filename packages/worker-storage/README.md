# Worker storage adapter

Portable signed TEXT records for `@libsql/client/web` and `mysql2/promise` on
Cloudflare Workers. The module does not open connections, hold decryption keys,
provision trusted writers, or authorize requests. Applications pass an existing
request-scoped driver connection and verify records at a trusted endpoint.

Use `tursoStore(client)` or `hyperdriveStore(connection)` to access opaque records.
Call `initialize()` only in an explicit schema migration. `compareAndSwap(key,
null, text)` inserts revision 1; subsequent updates require the previous `bigint`
revision. `get(key, expectedVersion)` returns untrusted text or null. Use
`openRecord(wasm, ...)` or the SDK's `openSignedTextStorageRecord` with independent
writer pins and expected context to authenticate and decrypt it.

The codec uses canonical Base64 and limits encoded records to 1 MiB. Parsing alone
does not authenticate the writer. Hyperdrive freshness-sensitive reads require a
cache-disabled configuration. The driver must preserve integer precision and
implement suitable network/resource limits.

See the [integration guide](https://github.com/foctal/foctet/blob/main/docs/worker-databases.md)
for examples, migration, trust boundaries and local workerd/database testing.
This is currently a private workspace package; it is not an npm release.
