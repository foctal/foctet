# Foctet Threat Model

**Document version:** 1.0 (2026-07-02) · applies to the Draft v0 wire format /
the `0.x` release line.

This document describes what Foctet defends against, what it explicitly does
not, and which residual risks an integrating application must handle itself.
It complements `SPEC.md` (wire format, §3 summarizes the adversary),
`SECURITY.md` (current posture, reporting), and
`docs/recommended-deployments.md` (composition guidance). Where this document
and the code disagree, that is a bug — please report it.

---

## 1. System model

A Foctet deployment has up to four kinds of parties:

- **Endpoints** — the two peers that run the Foctet handshake (or install
  shared traffic keys) and hold the plaintext. Native apps, servers, browsers
  (WASM), Workers.
- **Relays** — nodes that forward Foctet frames without holding traffic keys
  (TCP/WS relays, TURN-like forwarders, message brokers).
- **Storage** — anything that holds sealed bytes at rest: object stores (R2,
  S3), databases, file systems, CDN caches holding sealed HTTP bodies or
  archives.
- **Infrastructure** — the transport path itself (networks, load balancers,
  TLS terminators) and platform services (Redis / Durable Objects used as
  replay stores).

Foctet's core promise: **only endpoints see plaintext.** Relays, storage, and
infrastructure are untrusted for confidentiality and integrity (at most
honest-but-curious, potentially malicious).

## 2. Adversary capabilities

We assume an active network adversary who can:

- observe, drop, delay, reorder, duplicate, and inject any packet, frame,
  datagram, HTTP request, or stored blob;
- operate any relay or storage node, including serving modified or replayed
  content;
- open connections to any endpoint and speak the protocol (including partial
  or malformed handshakes);
- spoof source addresses on connectionless transports (UDP);
- but **cannot** break the underlying cryptography (X25519, Ed25519,
  HKDF-SHA-256, XChaCha20-Poly1305) and does not hold an endpoint's secret
  keys unless a scenario below says otherwise.

Out of scope entirely: compromise of the OS/hardware while the process runs
(a root-level attacker reads memory regardless), malicious dependencies in the
consumer's build, and correctness of the platform's CSPRNG (`getrandom`).

## 3. Threats and defenses

### 3.1 Active man-in-the-middle (MITM)

**Threat.** An attacker on the path substitutes their own X25519 ephemeral in
the handshake, splitting one session into two.

**Defense.** The native handshake is **authenticated by default and fails
closed**: a default `SessionAuthConfig` refuses to complete without peer
authentication. Two production mechanisms exist:

- **Ed25519 identity authentication** — each side signs the handshake
  transcript hash (which covers both ephemerals and the session salt) with a
  long-term identity key; the peer verifies against a **pinned** identity
  (`PeerIdentity`). The verified key is exposed as
  `Session::authenticated_peer()`. Signing can be delegated to an HSM/KMS via
  the `HandshakeSigner` trait so the identity secret never enters process
  memory.
- **Channel binding** — `SessionAuthConfig::bound_to_channel(..)` folds an
  outer-channel value (e.g. a TLS exporter) into the transcript hash, so the
  handshake only completes inside that specific outer channel. Suitable when
  the outer channel already authenticates the peer (mutual TLS).

Running unauthenticated requires the deliberately alarming
`unauthenticated_for_testing()` opt-in.

**Residual risk.** Identity distribution/pinning is the application's problem:
Foctet verifies "the peer holds the key you pinned", not "the key belongs to
Alice". A wrong or attacker-supplied pinned key defeats authentication.
Trust-on-first-use, directories, and revocation are out of scope for v0
(see §3.9 on key loss).

### 3.2 Replay

**Threat.** The attacker re-delivers a previously valid ciphertext: a frame in
a session, a datagram, a sealed HTTP request, a whole streaming body.

**Defenses, per shape:**

- **Stream/message/datagram sessions** — every frame carries
  `(key_id, stream_id, seq)`; receivers keep a sliding replay window per
  `(key_id, stream_id)` and reject duplicates. Replay state is committed
  **only after AEAD authentication**, so a forged high sequence number cannot
  desynchronize the window (this ordering is regression-tested). The number of
  tracked windows is capped (`max_replay_windows`) to bound memory.
- **HTTP one-shot and streaming bodies** — the `*_with_context` path binds a
  `ProtectedContext` (method, path, query, direction, timestamp, expiry, a
  random 16-byte message ID) into the AEAD as associated data, and consumes
  the message ID **exactly once** through an atomic `ReplayStore`
  (`check_and_insert`). Multi-instance deployments must use a shared, durable
  store — Redis (`SET NX PX`) or the Cloudflare Durable Object adapter; a
  per-instance in-memory store cannot see replays that arrive at another
  instance. Freshness (timestamp/expiry, clock skew) bounds how long an entry
  must be retained.
- **Archives / stored blobs** — replay of a stored object is *by definition*
  the read path; single-use semantics for stored data are an application
  concern (e.g. bind the archive to a purpose via its encrypted metadata).

**Residual risk.** The deprecated stateless HTTP family
(`seal_request`/`open_request` without context) is replayable by design and
kept only for migration; production code must use the context-bound path. TTL
choice matters: a replay-store entry must outlive the freshness window.

### 3.3 Reordering, truncation, and stream splicing

**Threat.** The attacker reorders frames, truncates a stream early, or splices
ciphertext from one context into another.

**Defense.** Byte-stream and message sessions enforce ordering via the replay
window; the streaming body format requires strictly sequential chunk indices,
authenticates chunk position (`index` in the AAD), and requires exactly one
authenticated FINAL chunk — a truncated, extended, reordered, or duplicated
stream fails to verify (`is_finished()` must be true before the plaintext is
trusted). Frames are bound to their `(direction, key_id, stream_id, seq)` via
nonce + AAD, so cross-context splicing fails authentication. Datagram mode
tolerates loss and reordering by design (per-datagram independence) — an
application needing ordering on datagrams must layer it.

### 3.4 Rollback / downgrade

**Threats and defenses:**

- **Version/profile downgrade** — the profile ID rides in the authenticated
  header (AAD); v0 ships exactly one mandatory profile
  (X25519+HKDF-SHA-256+XChaCha20-Poly1305), so there is no weaker suite to
  negotiate down to. Future profiles must fold negotiation into the
  transcript (see `docs/POLICIES.md`).
- **Key rollback** — a `Rekey` control message must name the **current**
  active `old_key_id` and `new_key_id = old + 1`; stale, replayed, or jumped
  rekeys are rejected, and the rekey transcript binding covers the new
  ratchet public key. An attacker cannot force traffic back onto an old key:
  retained previous keys are decrypt-only and bounded
  (`max_retained_keys`).
- **Sequence rollback (self-inflicted)** — restoring session state with reset
  counters would reuse nonces. Foctet ships **no session-persistence format**
  and the spec forbids restoring outbound sequence state; after a crash,
  establish a fresh session.

### 3.5 Endpoint compromise (key exposure over time)

**Threat.** An attacker obtains an endpoint's keys at some point in time.

**Properties:**

- **Between sessions** — each session runs a fresh ephemeral X25519 handshake:
  compromise of one session's traffic keys does not decrypt other sessions
  (forward secrecy at session granularity).
- **Within a session** — rekey is a **DH ratchet**: each rekey mixes a fresh
  ephemeral DH output into a root chain, and rekeys alternate between peers.
  Keys before the compromise stay safe (forward secrecy); after a compromise,
  security heals once both peers have taken a ratchet turn
  (post-compromise security). Under one-directional traffic the alternation
  stalls (the quiet side never takes its turn); rekey periodically from both
  ends.
- **Long-term identity compromise** — an attacker holding the Ed25519 identity
  key can impersonate the endpoint in *new* handshakes (it cannot decrypt
  past traffic — the identity key only signs). Revocation/rotation of
  identities is the application's responsibility (see `docs/POLICIES.md`);
  using a `HandshakeSigner` backed by an HSM/KMS reduces exfiltration risk.

**In-process hygiene** (reduces exposure window, not a boundary): traffic-key
bytes live in exactly one place (`TrafficKeys` is non-`Clone`, shared via
`KeyHandle`), are zeroized on drop, redacted in `Debug` output, and compared
in constant time; secret-returning APIs are `expose_`-prefixed and return
`Zeroizing` buffers. On WASM, zeroization cannot be guaranteed across the JS
boundary (JS engines copy freely) and keys are extractable bytes — treat a
compromised page/extension context as a compromised endpoint.

### 3.6 Relay and storage compromise

**Threat.** A malicious relay or storage provider reads, modifies, reorders,
or selectively drops what passes through it.

**Defense.** Relays and storage never hold traffic keys; payloads are AEAD-
protected end to end, headers are authenticated as AAD, and archive metadata
(file names, content types) is encrypted — a relay sees only routing-level
framing (see §3.8 for what leaks). Modification anywhere fails authentication
at the endpoint. Split archives authenticate each part and bind parts to the
manifest, so a storage provider cannot swap or truncate parts undetected.

**Residual risk.** Availability: a malicious relay can always drop or delay
traffic — Foctet detects, it does not prevent. Traffic analysis: see §3.8.

### 3.7 Denial of service and resource exhaustion

**Threat.** An attacker feeds crafted input to exhaust memory/CPU, or uses an
endpoint as an amplifier.

**Defenses:**

- All attacker-controlled lengths are validated against explicit limits before
  allocation (`ProtocolLimits`: max ciphertext length; `BodyEnvelopeLimits`;
  `DatagramConfig::max_datagram_size`; archive limits). Replay-window count is
  capped. Handshake reads are bounded by timeouts on both the Tokio path
  (`DEFAULT_HANDSHAKE_TIMEOUT`) and the runtime-agnostic futures path.
- **Authenticate-before-commit** everywhere: forged input cannot mutate
  replay/session state, so an off-path attacker cannot poison a session.
- **UDP anti-amplification** — the raw-UDP adapter rejects unconnected sockets,
  and its unvalidated-server constructor always installs a QUIC-style 3x
  limiter. Until validation, an endpoint cannot send more than three times the
  bytes received. QUIC/WebTransport enforce this at the transport layer.
- Parsers for every attacker-facing format are fuzzed continuously (7 targets,
  seeded, time-budgeted in CI).

**Residual risk.** The transport crate provides token-bucket handshake rate
limiting and RAII concurrency admission, but applications must install and
share those limiters at every listener. Perimeter SYN/routing controls remain
outside Foctet.

### 3.8 Metadata leakage (traffic analysis)

**What an observer sees, by design:**

- Frame headers ride in plaintext (authenticated, not encrypted): version,
  flags (control vs data), profile, `key_id`, `stream_id`, `seq`, and exact
  ciphertext length. Handshake control messages (ephemeral publics, salt) are
  plaintext.
- Sealed HTTP requests expose normal HTTP metadata (method, path, headers,
  timing) plus the `x-foctet-*` carrier headers; the *protected context* is
  authenticated, not hidden.
- Archives expose a minimal plaintext header (magic, version, sizes); names
  and content metadata are encrypted.
- Timing, frequency, direction, and sizes of traffic are visible everywhere.

**Non-defenses.** Foctet does not pad, batch, or otherwise shape traffic, and
does not hide who talks to whom. Applications needing resistance to traffic
analysis must add padding/cover traffic or route over an anonymity network.
An optional relay-facing outer envelope (SPEC §9.2) can wrap frames when even
Foctet's own header must be hidden from a specific hop.

### 3.9 Key loss (availability of data)

**Threat.** The holder of the only decryption key loses it.

**Position.** Foctet is strictly end-to-end: there is **no key escrow and no
recovery path**. Losing the recipient secret for a body envelope or archive
makes the data permanently unreadable; losing an identity key means
re-establishing trust out of band. Archives support **multiple recipients**
(the DEK is wrapped per recipient), which is the supported mitigation: wrap to
a backup/escrow recipient key *that the application controls* if recovery is a
requirement. Key backup, rotation cadence, and compromise response are
specified in `docs/POLICIES.md`.

### 3.10 Cross-language / WASM boundary

**Threats specific to the JS/WASM SDK:**

- Keys and plaintext cross the JS boundary as `Uint8Array`s; JS engines may
  copy them arbitrarily — zeroization guarantees stop at the boundary.
- No non-extractable key storage: WebCrypto has no portable non-extractable
  X25519/Ed25519 type, so a compromised page context (XSS, malicious
  extension) can exfiltrate keys. Treat the browsing context as the endpoint's
  trust boundary and apply standard web hardening (CSP, no untrusted scripts).
- The wasm runtime has no monotonic clock: age-based rekey is disabled there
  (frame/byte-count thresholds still apply); long-lived WASM sessions should
  drive rekey explicitly.

Wire compatibility between Rust and JS is pinned by interop fixtures (Node
opens Rust-produced envelopes) and in-browser tests in CI.

## 4. Explicit non-goals

- Anonymity, unlinkability, or traffic-analysis resistance (§3.8).
- Availability against an on-path adversary (drop/delay always possible).
- Multi-device identity, group messaging semantics, or key directories.
- Deniability (Ed25519 transcript signatures are non-repudiable to anyone
  holding the transcript).
- Protection of a compromised endpoint's own plaintext.

## 5. Assurance status

Defenses above are implemented and regression-tested (unit, property,
conformance across real transports, fuzzing in CI, cross-language interop,
in-browser runtime tests). Report suspected gaps via the process in
`SECURITY.md`.
