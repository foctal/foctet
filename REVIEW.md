# Production-Readiness Review

**Review date:** 2026-06-22  
**Scope:** repository state at review time, including implementation, tests, CI, security posture, specifications, and user-facing docs.

## Verdict

**Not production-ready.** The project has a strong experimental security baseline: authenticated framing, fail-closed outbound sequencing, authenticate-before-replay handling, bounded parsing paths, property tests, and a passing all-feature Rust test suite. It is nevertheless not ready for a general-purpose production or v1 claim. The remaining blockers are primarily security-assurance, API-safe-default, operations, and compatibility work rather than a single newly observed cryptographic defect.

The existing `SECURITY.md` status of **experimental / Draft v0** remains the appropriate public position.

## Evidence collected

The following commands were run from the workspace root on 2026-06-22:

| Check | Result |
| --- | --- |
| `cargo test --workspace --all-features` | Passed: unit, integration, property, transport, and doctests |
| `cargo clippy --workspace --all-features -- -D warnings` | Passed |
| `cargo check -p foctet-http --features workers --target wasm32-unknown-unknown` | Passed |
| `cargo fmt --all -- --check` | **Failed**: existing formatting drift in `foctet-http`, `foctet-transport`, and `foctet-wasm` |

This review did not run a live Redis deployment, a Cloudflare Worker/Wrangler deployment, browser-runner tests, fuzzing, Miri/sanitizers, or an independent implementation/audit. Passing compile-time checks for those integrations must not be interpreted as operational validation.

## Findings

### P0 — release blockers

1. **No independent cryptographic design and implementation review.** The protocol, Rust implementation, HTTP mode, and WASM/JS boundary have not received the independent review required by `SECURITY.md` and `TODO.md`. Self-tests cannot substitute for this gate.
2. **The safe HTTP path is not the default.** Stateless body/request APIs remain publicly available and replayable by design, while production HTTP needs the context-bound path and an atomic, durable replay store. Redis support exists, but a Workers Durable Object solution and API/default enforcement are still absent. This makes misuse likely, especially in serverless or multi-instance deployments.
3. **The protocol/API contract is still Draft v0.** `SPEC.md` explicitly mixes implemented behavior and target behavior; there is no completed normative, versioned specification, compatibility policy, or independent vector consumer. A stable interoperability promise is premature.

### P1 — required before a broad production claim

1. **Transport claims exceed integration assurance.** Datagram primitives and QUIC/UDP adapters are present, but there is no shared byte-stream conformance suite for every advertised adapter, no browser WebTransport coverage, no concrete raw-WebSocket message adapter, and no complete rekey/MTU/anti-amplification operational story for datagrams.
2. **Rekey does not provide post-compromise security.** The current symmetric rotation is accurately documented, but the project must either explicitly retain that limitation in the supported production scope or specify, test, and independently review an authenticated ephemeral-DH ratchet. It must not imply PCS through the word "rekey."
3. **Supply-chain and CI release gates are incomplete.** CI runs Clippy, a default-feature workspace test command, a wasm check, and cargo-audit. It does not enforce formatting, locked/reproducible builds, MSRV, license/source policy, fuzzing with a corpus/time budget, sanitizers/Miri, or test coverage. Actions are version-tag pinned rather than immutable-SHA pinned.
4. **Current formatting gate fails.** `cargo fmt --all -- --check` reports formatting drift. Because CI does not run it, the branch can appear green while failing the expected Rust formatting check.
5. **Public documentation is internally inconsistent.** `README.md` and `SECURITY.md` still say that UDP/datagram and WASM/TypeScript are not provided, although the repository now includes a UDP adapter, a QUIC datagram adapter, and the `foctet-wasm` body-envelope SDK. README also says first-class HTTP context/replay integration is missing even though the code implements it. This obscures which safety conditions apply to each surface.
6. **Production operations are not fully specified.** Key-provider/keystore boundaries, supported versions, incident response, observability without secrets, durable replay-store deployment guidance, and concrete HTTP body limits/backpressure guidance remain incomplete.

## Positive observations

- Sequence exhaustion fails closed across stream, datagram, and message paths.
- Replay state is committed after successful AEAD authentication, and replay maps are bounded.
- The default native handshake requires authentication; unauthenticated use is explicit.
- Secret-bearing debug output is redacted and sensitive return values use `Zeroizing` where implemented.
- Parser/property tests, archive OOM regressions, protocol vectors, and real QUIC/UDP roundtrip tests provide a useful baseline.
- The HTTP context design binds request metadata and supports atomic Redis `SET NX PX` replay insertion; this is a sound direction when deployed with a durable store.

## Recommended release sequence

1. Restore formatting and make format, locked builds, all-feature tests, and the existing wasm check mandatory CI gates.
2. Correct README/SECURITY deployment claims and make the protected-context, durable-replay HTTP route the unmistakable production API; implement the Workers Durable Object path or exclude Workers from production guidance.
3. Publish a normative versioned spec, transport support matrix, threat model, operational/key-lifecycle policy, and independently consumable vectors.
4. Complete transport conformance/integration coverage and decide the precise rekey/PCS production promise.
5. Add supply-chain, fuzzing, MSRV, reproducibility, and browser/Workers validation gates; then commission and resolve an independent security review.

Until these items are closed, releases should remain clearly labelled experimental and should not make a general-purpose production-ready claim.
