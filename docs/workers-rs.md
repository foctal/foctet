# Rust Workers integration

Foctet supports the [workers-rs SDK](https://github.com/cloudflare/workers-rs).
Enable `foctet-http/workers` for HTTP envelopes and Durable Object replay storage,
and `foctet-storage-wire/workers` for D1 and remote libSQL persistence. Cryptographic
operations remain in `foctet-core`; the storage adapters only handle opaque records.

| Surface | Integration |
| --- | --- |
| HTTP | `WorkersOpener` / `WorkersSealer`, with bounded request accumulation |
| Durable Objects | `DurableObjectReplayStore`, replay handler and alarm cleanup |
| D1 | `D1Driver` using the primary database binding |
| Remote libSQL | `LibsqlDriver` using Fetch and Hrana v2 |
| WebSocket messages | `WebsockMessageTransport` over the backend-neutral `WebSocketConnection` trait |
| Hyperdrive | Application SQL driver on `Hyperdrive::connect()` implementing `TextDriver` |
| KV / R2 | Store `TextRecord::as_str()` using SDK bindings; parse and verify at the endpoint |

## Database API

The following construction is intended inside a Worker request handler:

```rust,ignore
use foctet_storage_wire::{
    database::AsyncTextStore,
    workers::{D1Driver, LibsqlDriver},
};
use std::time::Duration;

let driver = D1Driver::new(env.d1("DB")?);
let mut store = AsyncTextStore::new(driver, 256 * 1024)?;
// Apply initialize() explicitly as a schema migration, not on every request.
let record = store.get(storage_key, trusted_version).await?;

let remote = LibsqlDriver::new(
    &database_url,
    database_token,
    256 * 1024,
    Duration::from_secs(10),
)?;
let mut remote_store = AsyncTextStore::new(remote, 256 * 1024)?;
```

Map `DatabaseError` to the application's HTTP error policy. Do not expose database
credentials or backend errors. Fetch requires HTTPS (or loopback HTTP for
fixtures), rejects redirects and URL credentials, and does not retry writes.
Configure the response budget at least as large as the store's record budget.
An ambiguous timeout is an error, not a failed CAS: reconcile before advancing a
trusted version checkpoint. The client bounds accumulated response bytes; SDK
chunks and D1 response allocation remain runtime-owned and require application quotas.

`TextDriver` accepts parameterized `Statement` values and returns exact affected
rows and text columns. Its futures do not require `Send` or `Sync`. An existing
MySQL/MariaDB driver can implement this trait on a request-scoped Hyperdrive socket;
Foctet does not implement the MySQL wire protocol, connection authentication or
pool management. Bind all arguments, distinguish duplicate primary keys from
other failures, preserve result shape, and bound network reads and timeouts.
Use InnoDB and authoritative reads with query caching disabled. `initialize()`
checks the table engine, but deployment routing and connection policy are application
responsibilities. The runtime fixture checks the socket and MariaDB greeting;
SQL authentication and queries through a particular Rust driver need that driver's
integration tests. JavaScript mysql2 SQL/CAS coverage is a separate test suite.

Parsing is not authentication. Call `TextRecord::open` with independently trusted
writer, namespace, record ID and revision at the decrypting endpoint. Do not put
private decryption keys into a blind Worker. KV is eventually consistent and is
not a durable replay authority; this API does not add atomic CAS to KV or R2.
See [portable storage](worker-databases.md) for the security boundary.

## SDK compatibility and verification

The workspace and standalone regression fixture use SDK 0.8.7 and wasm-bindgen
0.2.129. HTTP/storage and `foctet-transport/transport-websock` compile together in
one WASM dependency graph. The fixture runs `worker/http`, whose `HttpRequest`
and `HttpResponse` use SDK `TryFrom` conversions around Foctet's Worker adapters.
Avoid leaving converted request bodies unconsumed: SDK stream bridges can otherwise
defer cleanup beyond the request context. Foctet cancels rejected oversized streams
while the handler is active.

The default portable and WebSocket transport crates retain Rust 1.88. The optional
workers-rs 0.8.7 integration requires Rust 1.91. Match the wasm-bindgen CLI to the
resolved Rust crate version; CI uses CLI 0.2.129.

### WebSocket connections

Foctet uses `websock-proto` 0.6.1 for the shared connection interface. Its
`WebSocketConnection`, `Message`, limits and error types are identical to those
re-exported by `websock`; existing backend implementations retain type compatibility.
These types are also available from `foctet_transport::websock`. Native examples use `websock-tungstenite` directly.

A workers-rs application supplies a connection bridge to the trait, or implements
`MessageTransport` directly. The local fixture demonstrates a `WebSocketPair`
bridge and authenticated encrypted messages in both directions. It is a test
bridge, not a production queue manager: SDK event queues, handshake deadlines,
connection lifetime, backpressure and hibernation remain application responsibilities.
For SDK `MessageEvent::bytes()`, select ArrayBuffer delivery before accepting:

```rust,ignore
socket.as_ref().set_binary_type(worker::web_sys::BinaryType::Arraybuffer);
let events = socket.events()?;
socket.accept()?;
```

This is required because recent compatibility dates default to Blob delivery.
See [Cloudflare's binary-message documentation](https://developers.cloudflare.com/workers/runtime-apis/websockets/#binary-messages).

Foctet's `transport-websock-mux` is a native Tokio adapter. Worker applications
use a socket bridge for message transport.

Run `npm run test:workers-rs` in `packages/worker-storage` after `npm ci`, installing
`worker-build` 0.8.7 and the Rust WASM target first. Docker provides disposable
libSQL and MariaDB services. Tests exercise actual workerd execution, D1/libSQL
CAS races, signatures, stale/tampered records, persistence across restart, KV/R2,
Hyperdrive sockets, encrypted WebSocket messages, HTTP limits and Fetch failure handling. No production account
or deployment is used. Validate production TLS, routing, caching, quotas and
recovery separately.
