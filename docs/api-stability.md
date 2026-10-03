# API and format stability

Foctet is experimental. Rust and TypeScript APIs and the Draft v0 wire format
may change incompatibly during the `0.x` release line. Check the specification
and test vectors when upgrading communicating peers together.

Package versions, wire-format versions, and crypto profile IDs are separate.
A package version change does not by itself identify a new wire format.
Unknown wire versions and profiles are rejected; there is no silent fallback.

Deprecated APIs remain available for at least one minor release during `0.x`,
unless a security issue requires earlier removal. Starting with v1, API
removals and incompatible signatures require a major version change.

The stateless full-request HTTP helpers are currently available only through
`dangerous-stateless-http` and are planned for removal at v1. Use the
protected-context APIs with a replay store instead. Low-level body-envelope
helpers remain available for applications that handle replay separately.

Wire changes must update [SPEC.md](../SPEC.md) and the
[test vectors](../test-vectors/README.md) together. See
[testing](testing.md) for compatibility checks and
[security policy](../SECURITY.md#supported-versions) for supported releases.
