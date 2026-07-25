# Test and hardening gates

The required push and pull-request workflow is intentionally lightweight:
`rust.yml` checks formatting, runs Clippy, and runs the workspace tests in one
job. `security.yml` checks dependency advisories weekly and on demand.
`release-rehearsal.yml` contains the broader maintainer-dispatched compatibility,
WASM, interoperability, packaging, and artifact checks. The commands below are
available for additional local verification.

## Miri

Miri interprets `foctet-core` to catch memory-safety and undefined-behaviour
issues in the parser / state-machine / crypto-framing code.

Install once:

```bash
rustup toolchain install nightly --component miri
```

Run the filtered set covering the modules where memory-safety subtleties live
(replay bitmap shifting, TLV/control/frame parsing, sequence allocation, AEAD
framing). The full suite (handshakes, Ed25519) is impractically slow under Miri:

```bash
for filter in replay:: payload:: limits:: control:: sequence:: crypto:: frame::; do
  cargo +nightly miri test -p foctet-core --no-default-features --locked -- "$filter"
done
```

## Fuzzing

Parser and AEAD-open hardening via `cargo-fuzz`. See [`fuzz/README.md`](../fuzz/README.md).
