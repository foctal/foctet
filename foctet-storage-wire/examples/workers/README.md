# workers-rs regression fixture

Local, unauthenticated test Worker. Never deploy it as an application. Its fixed
keys and cleartext verification endpoint are public synthetic test fixtures.

Run `npm run test:workers-rs` from `packages/worker-storage` after `npm ci`.
Requires Docker, the Rust `wasm32-unknown-unknown` target and `worker-build` 0.8.7.
The runner creates and removes its own containers and local persistence directory.

This standalone workspace pins worker 0.8.7 to test the latest supported SDK
together with Foctet HTTP/storage and the WebSocket message transport.
The test-only socket bridge uses public synthetic identity keys, selects binary
ArrayBuffer delivery explicitly, and checks encrypted messages in both directions.
Production applications must bound SDK event queues and connection lifetimes.
It compiles the default SDK interface and runs its `http` feature in workerd.
D1 and libSQL execute real storage statements; Hyperdrive coverage checks socket
connection and the MariaDB protocol greeting, not a Rust MySQL driver implementation.
