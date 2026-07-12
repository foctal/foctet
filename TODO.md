# Foctet v1.0 Release-Blocking TODO

This is a security and reliability gate, not a feature wish list.  Foctet must
not claim a stable production API, stable wire format, or a general-purpose
E2EE deployment recommendation until every P0 and P1 item below is closed,
independently reviewed, and covered by regression tests.

The review assumes an active network and storage adversary that can replay,
reorder, truncate, inject, delay, drop, and duplicate input; can cause partial
writes, disconnects, restarts, and concurrent requests; and can supply every
public input, including apparently authenticated payloads.

## Exit criteria

- Every security-relevant state transition is atomic or has a specified,
  fail-closed recovery procedure.
- A caller cannot accidentally select an insecure production path through a
  normal public constructor.
- The specification, implementation, canonical vectors, and independent
  implementation agree for every supported wire format and error condition.
- All advertised first-class transports, including Cloudflare Workers and
  browser WebTransport, have end-to-end tests in the release CI.
- A qualified independent cryptographic/protocol audit has remediated all
  findings, and the audit scope, version, findings, and fixes are published.

## P0 — fix before any further production recommendation

### Implementation tracking (updated 2026-07-12)

- [ ] **P0-1** — Synchronous `SyncIo` and async `FoctetFramed` now reserve
  their sequence before output and permanently close after partial-write,
  write, or flush failure, with regression coverage. The equivalent failure
  contract still needs to be completed for control/handshake/rekey and all
  message/datagram transport adapters.
- [x] **P0-2** — A shared zeroizing X25519 helper rejects all-zero shared
  secrets for handshake, body envelopes (including streaming bodies), and
  archive wrapping/unwrapping. Regression coverage includes all-zero and a
  known low-order input on seal/open paths; documentation now specifies the
  non-oracle error behavior.
- [ ] **P0-3** — `Session` now supports an immutable prepare/commit rekey
  transaction; synchronous/async byte-stream automatic rekey and WASM use it,
  and the native immediate `force_rekey` convenience is now test-only. Datagram
  tests use it for their reliable control channel; real control-channel delivery
  integration for every datagram adapter remains.
- [ ] **P1-2** — Archive builders now cap in-memory plaintext at 512 MiB and
  use checked `u32` conversions for chunk counts, indices, lengths, and nonce
  inputs, preventing chunk-nonce repetition through truncation. The remaining
  cross-surface CPU/allocation limits and adversarial budget tests are open.
- [ ] **P1-1** — Message and datagram endpoints are now terminal after inbound
  authentication, parser, replay, key, or sequence failures, and reject all
  subsequent use. Sticky terminal policy for `Session`, `SyncIo`, framing,
  high-level channels, and WASM is still incomplete.

### P0-1: Prevent nonce reuse after a synchronous partial write or flush failure

**Finding.** `SyncIo::send_with_key` encrypts at the current sequence number,
writes the full frame, flushes, and only then commits `OutboundSequence`.
`write_all` may have sent a prefix (or the complete frame) before returning an
error; `flush` may fail after the peer has received the frame. Retrying then
encrypts a different plaintext with the same `(traffic key, key_id, stream_id,
seq)` nonce. This is catastrophic for XChaCha20-Poly1305 confidentiality and
integrity.

**Required work.**

- Redesign the synchronous outbound API around an explicit send state machine:
  reserve and durably mark a sequence before the first byte can reach the
  transport, retain the exact serialized frame until completion, and never
  re-encrypt it on retry.
- If an I/O error makes delivery ambiguous, make the channel terminal by
  default. Do not permit arbitrary `send` retry on the same session; expose
  only a narrowly specified resume/drain operation if it can prove it emits
  the retained bytes and cannot change plaintext, flags, stream ID, or key.
- Apply the same failure contract to control frames, handshake writes, rekey
  writes, `FoctetStream`, and every adapter built on blocking I/O.
- Add fault-injection tests for zero-byte failure, partial-frame failure,
  post-frame `write_all` failure, flush failure, retry, and connection close.
  Assert byte-for-byte single emission or permanent closure, and assert that
  no nonce tuple can be observed twice.
- Document the delivery semantics precisely: encrypted transport cannot infer
  whether an ambiguous failed send was received, so applications must use
  authenticated message IDs/idempotency where delivery matters.

### P0-2: Reject low-order / all-zero X25519 shared secrets in every recipient-wrap path

**Finding.** The native session handshake rejects an all-zero X25519 result,
but body-envelope and archive wrapping call `StaticSecret::diffie_hellman`
without this check. Supplying an all-zero recipient public key makes the
wrapping shared secret predictable; an observer can derive the wrapping key
from public envelope/archive fields and decrypt the wrapped content key. This
also contradicts the current `SECURITY.md` claim that all-zero shared secrets
are rejected.

**Required work.**

- Create one internal, zeroizing X25519 helper that rejects an all-zero shared
  secret and use it for handshake, body envelopes, streaming bodies, storage
  records, archive wrapping, archive unwrapping, and WASM-exposed paths.
- Reject malformed or low-order recipient keys before sealing, and reject
  malicious ephemeral public keys before opening. Return typed errors without
  leaking whether a recipient key matched.
- Add cross-crate regression tests using all-zero and known low-order inputs;
  test both seal and open paths and verify no content/wrapping key is emitted.
- Correct the specification and security documentation so the guarantee and
  error behavior are exact.

### P0-3: Make automatic rekey transactional with outbound delivery

**Finding.** `Session::on_outbound_payload` calls `force_rekey`, which mutates
the local ratchet and active key before the rekey control frame is queued or
written. If queuing is rejected (for example by the async TX cap) or I/O fails,
the peer remains on the old key while the local session has advanced. The API
has no rollback or mandatory terminal state, so callers can continue from a
diverged ratchet.

**Required work.**

- Model rekey as a two-phase operation: prepare immutable next-state and the
  old-key control frame, atomically enqueue/send it under the old key, then
  commit the new state only at the documented commit point.
- Define failure behavior for each transport. An ambiguous transmission must
  close the session unless a protocol-level acknowledgement/resynchronization
  design proves both peers' ratchet generation.
- Ensure automatic threshold rekey, explicit `force_rekey`, native transport
  builders, WASM `FoctetSession`, and datagram-control workflows use the same
  transaction.
- Add deterministic tests for full outbound buffers, allocation failure hooks,
  partial control writes, dropped rekey controls, duplicate controls, and
  concurrent send/rekey attempts. Test that no path silently continues with
  different roots or key IDs.

## P1 — required for v1 API and security claims

### P1-1: Define and enforce a terminal error/state policy

- Classify every `CoreError`, HTTP error, parser error, and transport error as
  recoverable, frame-local, or connection/session-terminal.
- Make terminal state sticky in `Session`, `SyncIo`, `FoctetFramed`, message,
  datagram, and WASM endpoints. After an authentication/state/sequence/key
  failure, reject further use unless a specified safe recovery exists.
- Do not leave this decision to callers for invalid control messages, ratchet
  divergence, key/sequence exhaustion, ambiguous send, or malformed handshake
  input. Add state-transition and misuse tests for each class.

### P1-2: Bound all attacker-controlled work, not only allocations

- Establish per-surface limits for handshake/control messages, identity and
  channel-binding sizes, number of recipient entries/keyring keys, HTTP header
  values and bound-header list, archive recipients/chunks/parts, and concurrent
  streams/sessions.
- Enforce limits before copying, hashing, AEAD, signature verification, HKDF,
  or unbounded iteration. Review `Vec::with_capacity`, `to_vec`, map growth,
  and `usize`/`u32` conversions under hostile maximum values.
- Add a checked archive-build bound for `total_chunks`; `idx as u32` and
  `total_chunks as u32` must never truncate or repeat a chunk nonce. Define a
  maximum plaintext/archive size compatible with the format.
- Add adversarial CPU and memory budget tests, including many-recipient body
  envelopes, deep keyrings, replay-window churn, huge context headers, and
  archive split manifests.

### P1-3: Make secure APIs the only practical production APIs

- At the v1 API break, remove or feature-gate deprecated stateless full HTTP
  request open/seal helpers. Keep raw body primitives explicitly named as
  replayable building blocks and impossible to mistake for request protection.
- Provide production constructors that require either pinned peer identity or
  a typed authenticated-channel binding. Keep unauthenticated mode test-only
  or behind an unmistakable dangerous feature/API name.
- Avoid public constructors that accept raw active traffic keys/session parts
  without an explicit nonce-persistence and ownership contract.
- Add compile-fail/API-usage tests showing the recommended constructors reject
  insecure defaults and that all dangerous escape hatches are discoverable.

### P1-4: Finish HTTP replay, request/response binding, and Workers semantics

- Require an atomic durable replay store in all multi-instance/serverless
  production examples. Cloudflare KV alone is not a valid atomic
  check-and-insert backend; document Durable Objects (or another proven
  transactional store) as the Workers production path and remove wording that
  implies KV satisfies this contract.
- Add a real `wrangler` integration test that deploys/runs a Worker plus its
  Durable Object, races duplicate requests across concurrent invocations,
  exercises expiry/alarm behavior, restarts, and backend errors.
- Bind and validate the response's `request_message_id` against the initiating
  request in a high-level client API; do not leave response correlation only as
  optional caller discipline.
- Specify proxy-safe canonicalization for authority, path, query, duplicate
  headers, percent encoding, and HTTP/1.1 versus HTTP/2/3. Reject ambiguous
  duplicate carrier headers instead of relying on `HeaderMap::get` first-value
  behavior.
- Give streaming request and response helpers equivalent context, replay,
  finalization, cancellation, backpressure, and resource-limit guarantees.

### P1-5: Complete transport-specific security contracts

- Build a transport matrix that states exactly which channels are supported,
  ordering/reliability requirements, max frame/message/datagram sizes, control
  channel requirements, close/error behavior, and anti-amplification duties.
- Make raw UDP peer validation and anti-amplification safe by construction for
  server/listener use, or explicitly keep that adapter low-level. Test source
  spoofing, path-MTU reduction, oversize receive/send, loss, reordering, and
  rekey races on real sockets.
- Run end-to-end browser WebTransport tests against a real HTTP/3 server, not
  only in-page stream mocks. Cover reconnect, cancellation, backpressure,
  datagram loss/reorder, and control/data interleavings.
- Add real Cloudflare Workers integration coverage as a first-class CI gate,
  including encrypted storage, replay protection, limits, and error mapping.

### P1-6: Complete protocol specification and interoperability contract

- Reconcile every normative claim in `SPEC.md`, `SECURITY.md`, threat model,
  examples, and public rustdoc with executable behavior. In particular correct
  the all-zero-X25519 statement, rekey failure semantics, and Workers replay
  backend guidance.
- Specify handshake transcript format, authentication/channel-binding
  requirements, control stream identity, error/close behavior, replay-window
  behavior across rekey, and concurrency rules without relying on source code.
- Before freezing v1, decide the supported version/profile negotiation and
  downgrade-resistant migration story. It must authenticate offers and choices;
  unknown values must fail closed; no silent fallback is allowed.
- Expand independent vectors to cover negative cases and boundary conditions:
  low-order DH, signature failures, malformed controls, exhausted counters,
  rekey races, replay boundaries, body/stream truncation, archive corruption,
  and cross-language failures. Maintain at least one independently authored
  implementation and differential test suite.

## P2 — reliability, performance, and operational release gates

### P2-1: Verification and assurance pipeline

- Add `cargo deny check --all-features` and a RustSec advisory check to CI;
  this review could not run `cargo audit` locally because the subcommand is not
  installed. Revisit every temporary advisory exception on a fixed cadence.
- Run fuzz targets continuously with corpus retention, sanitizers where
  applicable, OSS-Fuzz or equivalent long-running coverage, and a documented
  triage/SLA path. Add fuzz targets for handshake state, rekey transactions,
  HTTP context/header parsing, Workers adapters, and all archive encoders.
- Add model/property/state-machine tests for concurrent operations, error
  injection, retry, restart, replay, and ratchet ordering. Use differential
  testing between synchronous, async, message, datagram, and WASM paths.
- Make Miri, feature/target matrices, WASM browser tests, interop tests,
  reproducible-build checks, SBOM generation, and dependency/license review
  release gates rather than best-effort local commands.

### P2-2: Independent review and cryptographic assurance

- Commission an independent audit covering the protocol design, X25519/KDF/AEAD
  composition, nonce domains, ratchet, transcript authentication, replay,
  parsing/DoS, Rust/WASM FFI, HTTP, archive, and Cloudflare Workers adapters.
- Publish a threat-model-to-test traceability matrix and audit remediation log.
  Do not mark a finding fixed solely because a unit test passes; include code
  review, regression proof, and cross-implementation evidence.
- Define a security-contact key, supported-version window, advisory process,
  CVE/RustSec policy, and incident runbooks that take effect on v1.

### P2-3: Availability, observability, and performance

- Publish safe default limits and sizing guidance per runtime/transport, with
  benchmarked throughput/latency/memory ceilings and backpressure behavior.
- Provide structured, secret-free metrics for handshakes, AEAD failures,
  replays, limit hits, rekeys, ambiguous sends, and Workers replay-store
  failures. Include rate-limiting guidance for pre-authentication work.
- Test graceful shutdown, cancellation, partial reads/writes, task aborts,
  reconnect policy, and process restarts. State clearly which guarantees are
  unavailable without application-level persistence/idempotency.

### P2-4: API, ecosystem, and release readiness

- Publish and test the npm package with generated TypeScript declarations,
  semver compatibility tests, browser/Node/bundler smoke tests, and a clear
  key-extractability posture. Do not claim HSM/WebCrypto non-extractable key
  support until it exists and is tested.
- Replace ignored security-critical doctests with compiled, runnable examples
  where feasible; ensure every example uses authenticated configuration and a
  durable replay store when applicable.
- Add an API stability test suite and explicit deprecation/removal plan. Freeze
  the public Rust, WASM/TypeScript, wire, archive, and HTTP surfaces together.
- Perform a clean-room release rehearsal: fresh checkout, locked builds,
  target matrix, vector verification, artifact checksum/signing process, and
  rollback/incident procedure. Publishing and release execution remain manual.

## Reference deployment acceptance scenarios

These scenarios are v1 acceptance gates for Foctet's *cryptographic transport
and storage layer*. They do not expand Foctet into an identity provider, user
directory, authorization service, content-ID system, relay, synchronization
engine, or storage control plane. Each reference implementation must state
which security properties are enforced by Foctet and which remain the
application's responsibility.

### R1: Secure encrypted-state synchronization

Foctet v1 may support an encrypted-state synchronization engine only when a
reference deployment proves secure operation with an untrusted synchronization
service.

- Encrypt each record (or authenticated batch) with record identity,
  collection identifier, device/principal scope, monotonically increasing version,
  operation type, and schema version bound as associated data. Never treat an
  opaque object key, HTTP path, or storage location as authenticated context.
- Define a client-held, authenticated anti-rollback root/version mechanism.
  `StorageRecord.version` alone is insufficient if the attacker can roll back
  both ciphertext and the application's expected version. Test rollback,
  equivocation (different valid histories to different devices), deletion,
  stale-device merge, and backup/restore attacks.
- Define conflict and merge semantics above Foctet (for example a signed,
  authenticated operation log or a deterministic CRDT). Foctet must preserve
  operation identity and ordering context without making unsafe delivery or
  consistency claims.
- Prove multi-device enrollment, device revocation, recipient-key rotation,
  lost-device recovery, and key-compromise response. A newly enrolled device
  must not silently obtain historic data unless the application explicitly
  wraps/re-encrypts it for that device.
- Test crash/retry at every synchronization boundary, including local durable state versus
  remote upload acknowledgement. Do not persist a live Foctet traffic session;
  establish a new authenticated session after restart.
- Include independent end-to-end tests against an adversarial object store that
  replays, substitutes, omits, forks, and corrupts encrypted objects and their
  metadata. Measure object-size, item-count, and metadata leakage.

### R2: Private end-to-end encrypted messaging

Foctet v1 may provide a secure transport substrate for pairwise messaging only
after a reference deployment demonstrates the following. Multi-party messaging
is out of scope unless a separately specified group key-management protocol is
implemented and audited; wrapping the same payload to several recipients is not
a substitute for group membership, sender authentication, or removal.

- Pin and authenticate peer identities, bind account/device/conversation IDs
  and protocol version into the handshake/application context, and present
  explicit identity-change signals to the application. TLS, a relay, or a
  server account alone must not be treated as the E2EE authentication boundary.
- Define durable message IDs, conversation IDs, idempotency, acknowledgement,
  delivery ordering, offline queues, and retry behavior above the encrypted
  channel. Ambiguous transmission must never cause nonce reuse or a false
  exactly-once claim.
- Test a malicious relay that reorders, duplicates, delays, withholds,
  truncates, injects, and cross-conversation substitutes ciphertext. Verify
  replay rejection and that metadata minimization is documented, including
  what the relay still learns (participants, timing, size, and routing unless
  an outer privacy system hides them).
- Define reconnect and multi-device behavior: every new transport session must
  perform an authenticated fresh handshake, and ratchet/rekey failure must
  fail closed. Test concurrent sends, one-directional traffic, offline peers,
  dropped rekey controls, and endpoint compromise/recovery claims.
- If higher-level features with deletion, notification, receipt, attachment, or
  indexing semantics are demonstrated, document them as application protocols
  with their own leakage and deletion limitations; Foctet encryption cannot
  guarantee deletion from an already compromised endpoint.

### R3: Direct, relayed, and stored encrypted-object delivery

Foctet v1 may support direct transfer and delivery through untrusted temporary
or durable storage once a reference deployment covers both the archive and
transport paths.

- Use randomized archive builders in production. Bind file/content ID,
  sender/recipient authorization context, intended object metadata,
  manifest identity/version, and application-level expiry/revocation policy
  through authenticated context or an authenticated outer manifest. Do not
  regard an object-store key as authorization.
- Test single and split archives stored under adversary-controlled locations:
  reordered parts, missing parts, duplicated parts, substituted manifests,
  substituted archives, stale versions, corrupted chunks, extra trailing data,
  and independently fetched parts. The recipient must verify completeness and
  manifest/hash binding before exposing any final file as successful.
- Specify streaming-to-disk behavior and bounded-memory limits for large files.
  Current byte-vector archive APIs are not sufficient by themselves for a
  general large-file v1 claim; provide authenticated streaming archive
  encode/decode or explicitly cap the supported file size.
- Define recipient addition/removal and revocation honestly. Existing copies
  and archives already wrapped to a recipient cannot be revoked cryptographically;
  removal requires creating a new DEK/archive for remaining recipients and
  controlling storage access separately.
- Exercise direct, relayed, and stored-object transfer under cancellation,
  resume, partial transfer, path-MTU changes, range reads, and concurrent
  downloads. Use a fresh authenticated Foctet session for transfer resumption
  unless a future persistence protocol is specified and audited.
- Include a real edge-runtime/object-storage example and CI integration test
  that demonstrates the service sees only the intended opaque ciphertext and
  metadata, together with a documented metadata-leakage inventory.

## Review evidence (2026-07-12)

- `cargo test --workspace --all-features` passed locally.
- `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` passed locally.
- `cargo audit` was unavailable locally (`cargo-audit` is not installed); no
  dependency-vulnerability conclusion follows from that absence.
- The existing suite and documentation are substantial, but passing tests are
  not evidence that the P0 transactional-send and recipient-DH invariants hold;
  both findings arise from tracing the actual production code paths.
