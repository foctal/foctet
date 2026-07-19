# Test and hardening gates

All required checks run in CI. `rust.yml` covers normal Rust, WASM/browser,
Workers, and interoperability tests; `security.yml` covers Miri, dependency
policy, SBOMs, and reproducibility; `fuzz.yml` runs retained corpora daily; and
`release-rehearsal.yml` performs the maintainer-dispatched compatibility and
artifact rehearsal. The commands below remain useful for reproducing failures.

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
