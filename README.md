[crates-badge]: https://img.shields.io/crates/v/foctet.svg
[crates-url]: https://crates.io/crates/foctet
[doc-url]: https://docs.rs/foctet/latest/foctet
[license-badge]: https://img.shields.io/crates/l/foctet.svg
[examples-url]: https://github.com/foctal/foctet/tree/main/foctet/examples

# foctet [![Crates.io][crates-badge]][crates-url] ![License][license-badge]

Transport-agnostic end-to-end encryption layer for secure data transfer.

## Crates

- `foctet-core`: Framing, crypto, handshake/rekey state, replay protection.
- `foctet-http`: Thin HTTP adapter for `application/foctet` body envelopes.
- `foctet-archive`: Encrypted single-file and split archives with recipient key wrapping.
- `foctet-transport`: Thin split-stream adapters.
- `foctet`: Top-level re-export crate.

## Stability

- Current releases are `0.x`; breaking changes may occur while Draft v0 is finalized.
- Wire-level changes must update both `SPEC.md` and `test-vectors/`.
- Stable wire/API compatibility is planned for `v1`.

## Examples
See [examples][examples-url]
