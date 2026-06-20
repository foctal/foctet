# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Security

- **Fix nonce reuse on synchronous sequence exhaustion (P0).** `SyncIo` now fails
  closed with `SequenceExhausted` instead of wrapping the sequence counter, so it
  can no longer reuse an XChaCha20-Poly1305 `(key_id, stream_id, seq)` nonce. This
  matches the async `FoctetFramed` policy.
- **Commit replay-window state only after AEAD authentication (P1).** All receive
  paths (`SyncIo::recv`, `SyncIo::recv_application_with_session`, and
  `FoctetFramed`'s decoder) now authenticate the ciphertext before recording the
  sequence number, preventing a forged high-sequence frame from desynchronizing or
  DoS-ing the receiver.
- **Authenticated-by-default native handshake (P1).** A default `SessionAuthConfig`
  now fails closed; an unauthenticated handshake requires an explicit
  `SessionAuthConfig::unauthenticated_for_testing()` /
  `allow_unauthenticated(true)` opt-in.
- **Bounded replay-window map (P2).** `ReplayProtector` caps the number of distinct
  `(key_id, stream_id)` windows (`DEFAULT_MAX_REPLAY_WINDOWS`), returning
  `ReplayCapacityExceeded` rather than growing unbounded.

### Added

- `seal_body_with_context` / `open_body_with_context` /
  `open_body_for_key_id_with_context`: bind an application-supplied context into the
  body-envelope AEAD as associated data (foundation for HTTP context binding /
  anti-replay). Empty context is byte-identical to the previous output.
- `SessionAuthConfig::unauthenticated_for_testing` / `allow_unauthenticated` /
  `allows_unauthenticated`.
- `ReplayProtector::with_max_windows` / `tracked_windows`;
  `DEFAULT_MAX_REPLAY_WINDOWS`; `CoreError::ReplayCapacityExceeded`.
- `SECURITY.md` documenting the security posture, threat model, reporting process,
  supported versions, and known limitations.

### Changed

- README and SPEC corrected to reflect the implemented surface: stream-oriented
  only; UDP/datagram and TypeScript/WASM SDK are not implemented; in-session rekey
  is symmetric traffic-key rotation, not post-compromise security.
