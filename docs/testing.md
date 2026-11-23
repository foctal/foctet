# Testing

Run these checks from the workspace root:

```bash
cargo fmt --all -- --check
python3 scripts/check-test-fixtures.py
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

The [Rust workflow](../.github/workflows/rust.yml) tests all features on Windows, Linux, and macOS.
Linux also runs formatting, lint, fixture, and isolated transport build checks.
The [security workflow](../.github/workflows/security.yml) checks dependency
advisories weekly.
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
  RUSTFLAGS='--cfg sha2_backend="soft"' \
    cargo +nightly miri test -p foctet-core --no-default-features --locked -- "$filter"
done
```

Use SHA-2's software backend for these interpreter runs because Miri does not
support every native cryptographic instruction, including AArch64 SHA-256.
Normal builds and native tests continue to use the default backend selection.

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

CI also runs the browser SDK harness and WebTransport tests in Chrome, covering
packet loss, reordering, rekeying, and reconnection. See the
[WASM SDK README](../foctet-wasm/README.md#browser-harness) for local commands and
WebSocket/WebTransport examples. Run the separate `wasm-bindgen-test` suite
locally using the [headless browser instructions](../foctet-wasm/README.md#headless-browser-tests).

The [interop tests](../interop/README.md) verify the wire-format vectors with an
independent JavaScript implementation.

## Database and Worker regressions

The integration tests use synthetic keys and disposable loopback databases.
The Worker fixtures run locally without application authorization.
See [native database testing](storage-integration.md) and
[portable adapter testing](worker-databases.md#verification) for commands.

Canonical public vectors live in `test-vectors/`. Tests that must also run from a
standalone crate use byte-identical copies in that crate's `tests/fixtures/`;
`check-test-fixtures.py` checks that these copies cannot silently drift.

### Platform binding tests

From `foctet-http/examples/workers-echo`, run `npm ci`, `npm test`, and
`npm run test:storage`. These are local Wrangler/Miniflare tests. They cover the
Rust Worker replay lifecycle and opaque-byte preservation through the fixture's
KV, R2, D1, Durable Object, Queue and Cache bindings, including concurrent writes,
expiry, restart and failure handling. They do not validate production account
configuration or establish platform-wide support beyond the exercised interfaces.
