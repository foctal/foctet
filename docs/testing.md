# Testing

Run these checks from the workspace root:

```bash
cargo fmt --all -- --check
python3 scripts/check-test-fixtures.py
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

The [Rust workflow](../.github/workflows/rust.yml) runs these checks and builds
each native transport feature independently. Dependency advisories are checked
weekly by the [security workflow](../.github/workflows/security.yml).
The manually triggered [release rehearsal](../.github/workflows/release-rehearsal.yml)
adds API compatibility, packaging, WASM, and interoperability checks.

## Miri

Miri interprets `foctet-core` to catch memory-safety and undefined-behaviour
issues in the parser / state-machine / crypto-framing code.

Install once:

```bash
rustup toolchain install nightly --component miri
```

Run the filtered set covering the modules that handle parsing and cryptographic state
(replay bitmap shifting, TLV/control/frame parsing, sequence allocation, AEAD
framing). The full suite (handshakes, Ed25519) is impractically slow under Miri:

```bash
for filter in replay:: payload:: limits:: control:: sequence:: crypto:: frame::; do
  cargo +nightly miri test -p foctet-core --no-default-features --locked -- "$filter"
done
```

## Fuzzing

Run parser and authenticated-decryption fuzz targets with `cargo-fuzz`. See [`fuzz/README.md`](../fuzz/README.md).

## Transport feature isolation

The conformance suite exercises real loopback connections for muxtls,
WebSocket mux, Quinn, Quion, and both native WebTransport backends. Quion also
checks datagrams before and after stream rekeys, payload size boundaries,
pinned-identity rejection, and terminal behavior after connection close.

```bash
cargo test -p foctet-transport --all-features --locked
for feature in transport-muxtls transport-websock transport-websock-mux transport-quinn transport-quion transport-webtrans transport-webtrans-quion; do
  cargo check -p foctet --no-default-features --features "$feature" --locked
  cargo test -p foctet-transport --no-default-features --features "$feature" --test conformance --locked
done
cargo check -p foctet --no-default-features --features transport-websock,transport-webtrans-browser --target wasm32-unknown-unknown --locked
```

## Browser and JavaScript tests

See the [WASM SDK README](../foctet-wasm/README.md#browser-harness) for the browser
harness and native WebSocket/WebTransport examples. These tests require local
browser tooling and are separate from the default Rust workflow.

The [interop tests](../interop/README.md) verify the wire-format vectors with an
independent JavaScript implementation.

## Database and Worker regressions

The public regression suite uses synthetic keys and disposable loopback databases.
It must remain reproducible without production credentials. Test Worker handlers
have no application authorization and must not be deployed as applications.
See [native database testing](storage-integration.md) and
[portable adapter testing](worker-databases.md#verification) for commands.

Canonical public vectors live in `test-vectors/`. Tests that must also run from a
standalone crate use byte-identical copies in that crate's `tests/fixtures/`;
`check-test-fixtures.py` checks that these copies cannot silently drift.
Do not replace fixed vectors to make an incompatible implementation pass.


### Platform binding tests

From `foctet-http/examples/workers-echo`, run `npm ci`, `npm test`, and
`npm run test:storage`. These are local Wrangler/Miniflare tests. They cover the
Rust Worker replay lifecycle and opaque-byte preservation through the fixture's
KV, R2, D1, Durable Object, Queue and Cache bindings, including concurrent writes,
expiry, restart and failure handling. They do not validate production account
configuration or establish platform-wide support beyond the exercised interfaces.

Use the committed dependency lockfiles for runtime tests. Development dependency
overrides are part of that test environment; update them together with runtime
regressions and dependency audits. Test fixtures are not deployment templates.
