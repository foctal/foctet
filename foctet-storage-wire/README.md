# Portable signed TEXT storage

Driver-free signed TEXT encoding, independent of the storage backend, with
parameterized SQL plans for libSQL and MySQL-compatible drivers. Supports native Rust and wasm32 with Rust 1.88.
Parsing is not authentication: opening requires an independently trusted writer
and expected namespace, record ID and revision. SQL plans contain only scalar
text parameters and must be executed atomically by the application driver.

See the [storage documentation](https://github.com/foctal/foctet/blob/main/docs/storage-integration.md)
and [security policy](https://github.com/foctal/foctet/blob/main/SECURITY.md).

The `worker_fixture` example generates public synthetic test data for the local
Worker integration suite. Its fixed keys are not application credentials.

`database::AsyncTextStore` executes plans through a `TextDriver` with non-`Send`
futures. The optional `workers` feature provides workers-rs D1 and Fetch/libSQL
implementations (SDK 0.8.7 requires Rust 1.91). See [Rust Workers integration](https://github.com/foctal/foctet/blob/main/docs/workers-rs.md)
for SDK compatibility, connection responsibilities and runtime regression tests.
