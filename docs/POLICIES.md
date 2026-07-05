# Foctet Policies: Compatibility, Keys, and Incident Response

**Document version:** 1.0 (2026-07-02) · applies to the Draft v0 wire format /
the `0.x` release line.

This document collects the operational policies referenced by `SPEC.md`,
`SECURITY.md`, and `docs/THREAT_MODEL.md`: how versions and compatibility are
managed, how keys should live and die, and what happens when something goes
wrong.

---

## 1. Versioning and compatibility

### 1.1 What is versioned

Three things version independently:

- **Wire format** — the frame layout, body-envelope format, archive format,
  and handshake/control messages. Currently **Draft v0** (`version` byte `0x00`
  in the frame header; envelope/archive magics carry their own version bytes).
- **Crypto profile** — the algorithm suite, named by the `profile_id` header
  byte. v0 defines exactly one mandatory profile:
  `0x01 = X25519 + HKDF-SHA-256 + XChaCha20-Poly1305`.
- **Crates / npm package** — SemVer on the Rust crates (`0.x` line) and the
  (not yet published) npm package.

### 1.2 Draft v0 policy (current)

- The `0.x` line **may include breaking changes**, both API and wire. Breaking
  wire changes MUST update `SPEC.md` and the canonical vectors under
  `test-vectors/` in the same change; CI regression tests pin the vectors.
- Within `0.x`, API deprecations get at least **one minor release** of
  `#[deprecated]` warning before removal (e.g. the stateless HTTP
  `seal_request`/`open_request` family, deprecated since 0.3.0, will be
  removed or gated no earlier than the API-freeze release).
- Only the **latest published `0.x` release** receives fixes; there are no
  backport branches during draft.

### 1.3 Version negotiation

There is deliberately **no in-band version or cipher negotiation in v0**:
both peers must speak Draft v0 / profile `0x01`, and a frame with an unknown
version or profile is rejected. This removes downgrade surface while the
format is unstable.

When a v1 (or a second profile) exists, the following rules apply:

- Version/profile selection MUST be folded into the handshake transcript so a
  MITM cannot strip or alter the offered set undetected (downgrade
  resistance).
- An endpoint MUST NOT silently fall back to an older wire version; fallback,
  if offered at all, must be an explicit application decision.
- New profiles are additive: `profile_id` values are never reused, and
  removing a profile is a breaking (major) change.

### 1.4 v1 commitment (future)

Declaring v1 requires the release gates described in the project security and
compatibility documentation (spec complete and matching code+vectors, stable
compatibility policy, operational readiness, etc.). From v1 on:

- the wire format is stable within a major version; frames, envelopes, and
  archives produced by any v1.x implementation are readable by any other;
- a supported-versions table replaces the "latest 0.x only" rule, with a
  minimum security-fix window announced at release;
- deprecations follow SemVer: deprecate in a minor, remove no earlier than
  the next major.

## 2. Key lifecycle

Foctet uses four kinds of keys. Per-kind guidance:

| Key | Lives | Rotation | Notes |
| --- | --- | --- | --- |
| Ephemeral X25519 (handshake/ratchet) | one handshake / one ratchet step | automatic | never persisted; zeroized on drop |
| Traffic keys (per-direction AEAD) | one `key_id` generation within a session | automatic via rekey thresholds (frames / bytes / age) or `force_rekey` | non-`Clone`, single-owner, zeroized; never persist |
| Recipient X25519 (body envelopes / archives) | long-lived, application-managed | application policy (see below) | `key_id` field routes to the right key |
| Ed25519 identity (handshake auth) | long-lived, application-managed | application policy (see below) | prefer `HandshakeSigner` over raw bytes |

### 2.1 Session (traffic) keys

- Rekey thresholds (`RekeyThresholds`) default to bounded frames/bytes/age;
  tune them to your traffic profile. Every rekey is a DH-ratchet step and
  rekeys alternate between peers — under one-directional traffic, drive
  `force_rekey` periodically from both ends so the ratchet keeps healing.
- On WASM the age threshold is inactive (no monotonic clock): drive rekey by
  count thresholds or explicitly.
- **Never persist session state.** There is no session-resumption format; a
  restored outbound sequence counter can reuse a nonce. After a crash,
  handshake again.

### 2.2 Long-lived recipient and identity keys

- **Generation:** from the platform CSPRNG (the library uses `getrandom`).
- **Storage:** identity signing should go through the `HandshakeSigner` trait
  backed by an HSM / cloud KMS / OS keystore where available, so the secret
  never enters process memory. Raw-byte keys (`IdentityKeyPair`,
  envelope recipient secrets) should live in a secrets manager, be loaded via
  the `expose_`-prefixed APIs (returning `Zeroizing` buffers), and never be
  logged — `Debug` output is redacted, but application logging of raw buffers
  defeats that.
- **Rotation:** rotate on a schedule appropriate to exposure (e.g. yearly for
  offline-stored keys, more often for keys on internet-facing hosts) and
  immediately on suspected compromise. Envelope/archive recipients are
  identified by `key_id`, so rotation is: publish the new public key under a
  new `key_id`, keep the old secret only as long as data sealed to it must
  remain readable, then destroy it.
- **Multiple recipients as backup:** archives and envelopes can wrap the DEK
  to several recipients. If data recovery is a requirement, wrap to an
  application-controlled backup key stored offline — Foctet itself has no
  escrow or recovery path (`THREAT_MODEL.md` §3.9).
- **Identity distribution and revocation** are the application's
  responsibility: Foctet pins the exact public key you configure. Keep an
  application-level mapping of "who currently holds which identity key" and
  treat unpinning/replacing a key as a security-relevant, audited action.

## 3. Incident response

### 3.1 For a vulnerability in Foctet itself

Follow `SECURITY.md`: private reporting (GitHub private vulnerability
reporting or maintainer email), acknowledgement target 7 days, coordinated
disclosure. Fixes land in the latest release line; wire-affecting fixes come
with updated vectors and a CHANGELOG **Security** entry, and (post-v1) a
RustSec advisory for the affected crates.

### 3.2 For a key compromise in a deployment

Suggested playbook, by key type:

1. **Traffic key / single session** — close the session; a new handshake
   derives unrelated keys. Past traffic before the compromised generation
   stays protected (forward secrecy); if the exposure window is unknown,
   assume everything under that session's current and later generations until
   re-handshake.
2. **Identity (Ed25519) key** — stop using it immediately (new handshakes with
   it are impersonatable); distribute and pin the replacement out of band;
   audit for handshakes authenticated by the old key during the exposure
   window. Past recorded traffic is *not* retroactively decryptable from an
   identity key alone.
3. **Recipient (X25519) key for envelopes/archives** — everything ever sealed
   to that key must be considered readable by the attacker. Rotate the
   `key_id`, re-seal still-sensitive data to the new key, and destroy the old
   secret once re-sealing is complete.
4. **Replay-store compromise** (Redis/DO) — the store holds message IDs, not
   keys or plaintext; the impact is replay-protection loss. Restore an atomic
   store before continuing to accept context-bound requests, and treat
   requests accepted during the outage as potentially replayed.

### 3.3 Operational monitoring

Failures that warrant alerting in a deployment: sustained AEAD authentication
failures (active tampering or key mismatch), replay-store rejections above
baseline (replay attempt), handshake timeouts/auth failures spikes (probing),
and `SequenceExhausted`/`ReplayCapacityExceeded` errors (limits tuned too low
or abuse). Foctet surfaces these as typed errors; wiring them to metrics is
application-side (observability hooks are tracked in `TODO.md` §7).
