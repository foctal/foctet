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

use crate::replay::{DEFAULT_MAX_REPLAY_WINDOWS, DEFAULT_REPLAY_WINDOW, ReplayProtector};

/// Default upper bound on a single inbound frame's ciphertext length (16 MiB).
///
/// A receiver rejects a frame whose declared `ct_len` exceeds this before
/// allocating a buffer for it, so a hostile peer cannot force an unbounded
/// allocation by advertising a huge length field.
pub const DEFAULT_MAX_CIPHERTEXT_LEN: usize = 16 * 1024 * 1024;

/// Default number of *previous* traffic-key generations retained for decrypting
/// in-flight frames across a rekey. The active key is always kept in addition to
/// these, so the receiver tolerates frames that were encrypted just before a
/// rekey took effect.
pub const DEFAULT_MAX_RETAINED_KEYS: usize = 2;

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
    /// Number of previous traffic keys retained for decryption across rekeys.
    pub max_retained_keys: usize,
    /// Per-`(key_id, stream_id)` sliding replay-window size, in sequence slots.
    pub replay_window: u64,
    /// Maximum number of distinct `(key_id, stream_id)` replay windows tracked
    /// simultaneously, bounding replay-map memory growth.
    pub max_replay_windows: usize,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_ciphertext_len: DEFAULT_MAX_CIPHERTEXT_LEN,
            max_retained_keys: DEFAULT_MAX_RETAINED_KEYS,
            replay_window: DEFAULT_REPLAY_WINDOW,
            max_replay_windows: DEFAULT_MAX_REPLAY_WINDOWS,
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

    /// Sets the number of previous traffic keys retained for decryption.
    ///
    /// Clamped to a minimum of `1`: at least one previous key must be retained
    /// to decrypt frames still in flight when a rekey takes effect.
    #[must_use]
    pub fn with_max_retained_keys(mut self, max: usize) -> Self {
        self.max_retained_keys = max.max(1);
        self
    }

    /// Sets the per-stream replay-window size, in sequence slots.
    ///
    /// Clamped to a minimum of `1` so the window can always record at least the
    /// most recently seen sequence number.
    #[must_use]
    pub fn with_replay_window(mut self, window: u64) -> Self {
        self.replay_window = window.max(1);
        self
    }

    /// Sets the maximum number of distinct replay windows tracked at once.
    ///
    /// Clamped to a minimum of `1`.
    #[must_use]
    pub fn with_max_replay_windows(mut self, max: usize) -> Self {
        self.max_replay_windows = max.max(1);
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
        assert_eq!(limits.max_retained_keys, DEFAULT_MAX_RETAINED_KEYS);
        assert_eq!(limits.replay_window, DEFAULT_REPLAY_WINDOW);
        assert_eq!(limits.max_replay_windows, DEFAULT_MAX_REPLAY_WINDOWS);
    }

    #[test]
    fn builders_clamp_to_safe_minimums() {
        let limits = ProtocolLimits::default()
            .with_max_retained_keys(0)
            .with_replay_window(0)
            .with_max_replay_windows(0);
        assert_eq!(limits.max_retained_keys, 1);
        assert_eq!(limits.replay_window, 1);
        assert_eq!(limits.max_replay_windows, 1);
    }

    #[test]
    fn builders_set_explicit_values() {
        let limits = ProtocolLimits::new()
            .with_max_ciphertext_len(1234)
            .with_max_retained_keys(5)
            .with_replay_window(256)
            .with_max_replay_windows(64);
        assert_eq!(limits.max_ciphertext_len, 1234);
        assert_eq!(limits.max_retained_keys, 5);
        assert_eq!(limits.replay_window, 256);
        assert_eq!(limits.max_replay_windows, 64);
    }
}
