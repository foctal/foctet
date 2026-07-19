//! Centralized protocol resource limits for the stream-oriented Foctet paths.
//!
//! [`ProtocolLimits`] gathers the DoS-relevant bounds that the framed
//! (`FoctetFramed`) and blocking (`SyncIo`) transports previously hardcoded as
//! scattered magic numbers, so a single value documents and configures them in
//! one place. The defaults are the recommended production values.
//!
//! Datagram (`DatagramConfig`) and one-shot body (`BodyEnvelopeLimits`) shapes
//! keep their own limit types because their bounds differ in kind (a single
//! datagram is MTU-bounded; a body envelope is whole-buffer). They share the
//! same default ciphertext ceiling constant ([`DEFAULT_MAX_CIPHERTEXT_LEN`])
//! where it applies.

use std::time::Duration;

use crate::replay::{
    DEFAULT_MAX_REPLAY_WINDOWS, DEFAULT_REPLAY_WINDOW, MAX_REPLAY_WINDOW, MAX_REPLAY_WINDOWS,
    ReplayProtector,
};

/// Default upper bound on a single inbound frame's ciphertext length (16 MiB).
///
/// A receiver rejects a frame whose declared `ct_len` exceeds this before
/// allocating a buffer for it, so a hostile peer cannot force an unbounded
/// allocation by advertising a huge length field.
pub const DEFAULT_MAX_CIPHERTEXT_LEN: usize = 16 * 1024 * 1024;

/// Default upper bound on a single outbound frame's plaintext length.
///
/// Chosen so that the resulting ciphertext (plaintext + 16-byte AEAD tag) never
/// exceeds [`DEFAULT_MAX_CIPHERTEXT_LEN`]: a frame a sender emits under the
/// default limits is always accepted by a receiver running the default limits.
pub const DEFAULT_MAX_PLAINTEXT_LEN: usize = DEFAULT_MAX_CIPHERTEXT_LEN - 16;

/// Default upper bound on encrypted frames buffered for sending (64 MiB).
///
/// The async framed transport queues encrypted frames when the underlying
/// socket is not immediately writable. This cap bounds that queue so a stalled
/// or slow peer cannot cause unbounded sender-side memory growth; once
/// exceeded, enqueueing fails with [`crate::CoreError::OutboundBufferLimitExceeded`]
/// until the buffer is drained (`poll_flush` / `poll_ready`).
pub const DEFAULT_MAX_BUFFERED_TX_BYTES: usize = 64 * 1024 * 1024;

/// Default deadline for a native handshake to complete (10 seconds).
///
/// Enforced by the transport builders (`foctet-transport`), which race the
/// handshake against a timer and fail with
/// [`crate::CoreError::HandshakeTimeout`] on expiry, so a peer that connects
/// and then stalls cannot pin handshake state indefinitely.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default number of *previous* traffic-key generations retained for decrypting
/// in-flight frames across a rekey. The active key is always kept in addition to
/// these, so the receiver tolerates frames that were encrypted just before a
/// rekey took effect.
pub const DEFAULT_MAX_RETAINED_KEYS: usize = 2;

/// Hard upper bound on previous traffic-key generations retained by one endpoint.
pub const MAX_RETAINED_KEYS: usize = 16;

/// Default maximum number of distinct active outbound stream IDs.
pub const DEFAULT_MAX_OUTBOUND_STREAMS: usize = 1024;

/// Hard upper bound on distinct active outbound stream IDs.
pub const MAX_OUTBOUND_STREAMS: usize = 4096;

/// Centralized resource limits for the stream-oriented transports.
///
/// Construct with [`ProtocolLimits::default`] for the recommended production
/// values and adjust individual fields with the builder methods, or build a
/// value directly. All limits are clamped to a safe minimum on construction via
/// the builder methods (`0` is never accepted where it would disable a bound).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimits {
    /// Maximum accepted inbound ciphertext length, in bytes, per frame.
    pub max_ciphertext_len: usize,
    /// Maximum outbound plaintext length, in bytes, per frame. Send paths
    /// reject a larger payload with [`crate::CoreError::FrameTooLarge`] before
    /// encrypting it.
    pub max_plaintext_len: usize,
    /// Maximum bytes of encrypted frames buffered for sending before the
    /// underlying I/O accepts them. Exceeding it fails with
    /// [`crate::CoreError::OutboundBufferLimitExceeded`]. Only the buffering
    /// (async framed) path uses this; the blocking path writes through.
    pub max_buffered_tx_bytes: usize,
    /// Number of previous traffic keys retained for decryption across rekeys.
    pub max_retained_keys: usize,
    /// Per-`(key_id, stream_id)` sliding replay-window size, in sequence slots.
    pub replay_window: u64,
    /// Maximum number of distinct `(key_id, stream_id)` replay windows tracked
    /// simultaneously, bounding replay-map memory growth.
    ///
    /// Because one window is tracked per `(key_id, stream_id)`, this is also
    /// the bound on how many **distinct inbound stream IDs** a peer can force
    /// the receiver to track state for.
    pub max_replay_windows: usize,
    /// Deadline for a native handshake to complete. Enforced by the
    /// `foctet-transport` builders ([`crate::CoreError::HandshakeTimeout`] on
    /// expiry); the core state machine itself is poll-driven and has no clock.
    pub handshake_timeout: Duration,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_ciphertext_len: DEFAULT_MAX_CIPHERTEXT_LEN,
            max_plaintext_len: DEFAULT_MAX_PLAINTEXT_LEN,
            max_buffered_tx_bytes: DEFAULT_MAX_BUFFERED_TX_BYTES,
            max_retained_keys: DEFAULT_MAX_RETAINED_KEYS,
            replay_window: DEFAULT_REPLAY_WINDOW,
            max_replay_windows: DEFAULT_MAX_REPLAY_WINDOWS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

impl ProtocolLimits {
    /// Returns the recommended production limits (same as [`Default`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum accepted inbound ciphertext length per frame.
    #[must_use]
    pub fn with_max_ciphertext_len(mut self, max_len: usize) -> Self {
        self.max_ciphertext_len = max_len;
        self
    }

    /// Sets the maximum outbound plaintext length per frame.
    ///
    /// Clamped to a minimum of `1`.
    #[must_use]
    pub fn with_max_plaintext_len(mut self, max_len: usize) -> Self {
        self.max_plaintext_len = max_len.max(1);
        self
    }

    /// Sets the maximum bytes of encrypted frames buffered for sending.
    ///
    /// Clamped to a minimum of `1`. Must be large enough to hold at least one
    /// complete encrypted frame (header + plaintext + AEAD tag), otherwise
    /// every send fails.
    #[must_use]
    pub fn with_max_buffered_tx_bytes(mut self, max: usize) -> Self {
        self.max_buffered_tx_bytes = max.max(1);
        self
    }

    /// Sets the handshake completion deadline enforced by transport builders.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Sets the number of previous traffic keys retained for decryption.
    ///
    /// Clamped to a minimum of `1`: at least one previous key must be retained
    /// to decrypt frames still in flight when a rekey takes effect.
    #[must_use]
    pub fn with_max_retained_keys(mut self, max: usize) -> Self {
        self.max_retained_keys = max.clamp(1, MAX_RETAINED_KEYS);
        self
    }

    /// Sets the per-stream replay-window size, in sequence slots.
    ///
    /// Clamped to a minimum of `1` so the window can always record at least the
    /// most recently seen sequence number.
    #[must_use]
    pub fn with_replay_window(mut self, window: u64) -> Self {
        self.replay_window = window.clamp(1, MAX_REPLAY_WINDOW);
        self
    }

    /// Sets the maximum number of distinct replay windows tracked at once.
    ///
    /// Clamped to a minimum of `1`.
    #[must_use]
    pub fn with_max_replay_windows(mut self, max: usize) -> Self {
        self.max_replay_windows = max.clamp(1, MAX_REPLAY_WINDOWS);
        self
    }

    /// Builds a [`ReplayProtector`] configured from these limits (window size
    /// and distinct-window cap).
    pub fn replay_protector(&self) -> ReplayProtector {
        ReplayProtector::new(self.replay_window).with_max_windows(self.max_replay_windows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_documented_constants() {
        let limits = ProtocolLimits::default();
        assert_eq!(limits.max_ciphertext_len, DEFAULT_MAX_CIPHERTEXT_LEN);
        assert_eq!(limits.max_plaintext_len, DEFAULT_MAX_PLAINTEXT_LEN);
        assert_eq!(limits.max_buffered_tx_bytes, DEFAULT_MAX_BUFFERED_TX_BYTES);
        assert_eq!(limits.max_retained_keys, DEFAULT_MAX_RETAINED_KEYS);
        assert_eq!(limits.replay_window, DEFAULT_REPLAY_WINDOW);
        assert_eq!(limits.max_replay_windows, DEFAULT_MAX_REPLAY_WINDOWS);
        assert_eq!(limits.handshake_timeout, DEFAULT_HANDSHAKE_TIMEOUT);
    }

    #[test]
    fn default_plaintext_limit_fits_the_default_ciphertext_limit() {
        // plaintext + 16-byte AEAD tag must not exceed the inbound ceiling.
        let limits = ProtocolLimits::default();
        assert!(limits.max_plaintext_len + 16 <= limits.max_ciphertext_len);
    }

    #[test]
    fn builders_clamp_to_safe_minimums() {
        let limits = ProtocolLimits::default()
            .with_max_plaintext_len(0)
            .with_max_buffered_tx_bytes(0)
            .with_max_retained_keys(0)
            .with_replay_window(0)
            .with_max_replay_windows(0);
        assert_eq!(limits.max_plaintext_len, 1);
        assert_eq!(limits.max_buffered_tx_bytes, 1);
        assert_eq!(limits.max_retained_keys, 1);
        assert_eq!(limits.replay_window, 1);
        assert_eq!(limits.max_replay_windows, 1);
    }

    #[test]
    fn builders_clamp_allocation_sensitive_limits_to_safe_maximums() {
        let limits = ProtocolLimits::default()
            .with_max_retained_keys(usize::MAX)
            .with_replay_window(u64::MAX)
            .with_max_replay_windows(usize::MAX);
        assert_eq!(limits.max_retained_keys, MAX_RETAINED_KEYS);
        assert_eq!(limits.replay_window, MAX_REPLAY_WINDOW);
        assert_eq!(limits.max_replay_windows, MAX_REPLAY_WINDOWS);
    }

    #[test]
    fn builders_set_explicit_values() {
        let limits = ProtocolLimits::new()
            .with_max_ciphertext_len(1234)
            .with_max_plaintext_len(1000)
            .with_max_buffered_tx_bytes(4096)
            .with_max_retained_keys(5)
            .with_replay_window(256)
            .with_max_replay_windows(64)
            .with_handshake_timeout(Duration::from_secs(3));
        assert_eq!(limits.max_ciphertext_len, 1234);
        assert_eq!(limits.max_plaintext_len, 1000);
        assert_eq!(limits.max_buffered_tx_bytes, 4096);
        assert_eq!(limits.max_retained_keys, 5);
        assert_eq!(limits.replay_window, 256);
        assert_eq!(limits.max_replay_windows, 64);
        assert_eq!(limits.handshake_timeout, Duration::from_secs(3));
    }
}
