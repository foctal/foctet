# Local test & hardening checks

Most tests run in CI (`.github/workflows/rust.yml`). A few heavier checks need a
nightly toolchain or extra tooling and are run locally instead — typically
before cutting a release.

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
cargo +nightly miri test -p foctet-core --no-default-features --locked -- \
  replay:: payload:: limits:: control:: sequence:: crypto:: frame::
```

## Fuzzing

Parser and AEAD-open hardening via `cargo-fuzz`. See [`fuzz/README.md`](../fuzz/README.md).
