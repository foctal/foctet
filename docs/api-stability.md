# API and format stability policy

The Rust crates, WASM/TypeScript package, wire frames and controls, HTTP
protected context/body format, and archive containers form one compatibility
release unit. A release must not freeze or version only one of them.

Before v1, breaking `0.x` changes require updated specification, canonical and
negative vectors, independent decoder fixtures, Rust API usage tests, generated
TypeScript declarations, and a changelog migration note in the same change.
Deprecated safe APIs remain for at least one minor release. Dangerous escape
hatches may be removed sooner for security, with a security changelog entry.

For v1 and later:

- Rust and TypeScript follow SemVer; removal or signature incompatibility waits
  for the next major version unless retaining it is unsafe.
- Wire/profile/archive/HTTP version bytes never silently fall back and never
  reuse an assigned value for different semantics.
- Additive fields require specified old/new-reader behavior and cross-version
  vectors before release.
- The manually dispatched release rehearsal compares Rust public APIs with the
  selected prior tag and smoke-tests all generated npm targets.
- Any intentional incompatibility requires an approved deprecation/removal
  entry naming the replacement, first deprecated release, earliest removal
  release, wire impact, and migration example.

Current planned removal: stateless full-request HTTP helpers remain behind
`dangerous-stateless-http` during the draft line and are removed at the v1 API
freeze. Raw body primitives remain explicitly replayable low-level building
blocks.
