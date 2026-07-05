use std::collections::HashMap;

use crate::CoreError;

/// Recommended replay-window size for Draft v0.
pub const DEFAULT_REPLAY_WINDOW: u64 = 4096;

/// Default cap on the number of distinct `(key_id, stream_id)` replay windows a
/// single receiver will track before rejecting new ones. Bounds attacker- or
/// peer-driven memory growth in the replay map.
pub const DEFAULT_MAX_REPLAY_WINDOWS: usize = 1024;

/// Sliding replay window for sequence-number validation.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    window_size: u64,
    max_seen: Option<u64>,
    bits: Vec<u64>,
}

impl ReplayWindow {
    /// Creates a replay window with the specified size.
    pub fn new(window_size: u64) -> Self {
        let words = window_size.div_ceil(64) as usize;
        Self {
            window_size,
            max_seen: None,
            bits: vec![0u64; words.max(1)],
        }
    }

    /// Validates `seq` against the window and records it when accepted.
    pub fn check_and_record(&mut self, seq: u64) -> Result<(), CoreError> {
        match self.max_seen {
            None => {
                self.max_seen = Some(seq);
                self.clear_all();
                self.set_bit(0);
                Ok(())
            }
            Some(max_seen) if seq > max_seen => {
                let advance = seq - max_seen;
                self.shift_left(advance);
                self.max_seen = Some(seq);
                self.set_bit(0);
                Ok(())
            }
            Some(max_seen) => {
                let offset = max_seen - seq;
                if offset >= self.window_size {
                    return Err(CoreError::ReplayWindowExceeded);
                }
                if self.get_bit(offset) {
                    return Err(CoreError::Replay);
                }
                self.set_bit(offset);
                Ok(())
            }
        }
    }

    fn clear_all(&mut self) {
        self.bits.fill(0);
    }

    fn shift_left(&mut self, shift: u64) {
        if shift >= self.window_size {
            self.clear_all();
            return;
        }

        let word_shift = (shift / 64) as usize;
        let bit_shift = (shift % 64) as usize;
        let mut out = vec![0u64; self.bits.len()];

        for (i, slot) in out.iter_mut().enumerate() {
            if i < word_shift {
                continue;
            }
            let src_idx = i - word_shift;
            let mut val = self.bits[src_idx] << bit_shift;
            if bit_shift != 0 && src_idx > 0 {
                val |= self.bits[src_idx - 1] >> (64 - bit_shift);
            }
            *slot = val;
        }

        let remainder = (self.window_size % 64) as usize;
        if remainder != 0 {
            let last_mask = (1u64 << remainder) - 1;
            if let Some(last) = out.last_mut() {
                *last &= last_mask;
            }
        }

        self.bits = out;
    }

    fn get_bit(&self, offset: u64) -> bool {
        let w = (offset / 64) as usize;
        let b = (offset % 64) as u32;
        (self.bits[w] & (1u64 << b)) != 0
    }

    fn set_bit(&mut self, offset: u64) {
        let w = (offset / 64) as usize;
        let b = (offset % 64) as u32;
        self.bits[w] |= 1u64 << b;
    }
}

/// Replay protection state keyed by `(key_id, stream_id)`.
#[derive(Clone, Debug)]
pub struct ReplayProtector {
    windows: HashMap<(u8, u32), ReplayWindow>,
    window_size: u64,
    max_windows: usize,
    rejections: u64,
}

impl ReplayProtector {
    /// Creates replay protection map with a default per-stream window size and
    /// the default cap on the number of tracked windows.
    pub fn new(window_size: u64) -> Self {
        Self {
            windows: HashMap::new(),
            window_size,
            max_windows: DEFAULT_MAX_REPLAY_WINDOWS,
            rejections: 0,
        }
    }

    /// Overrides the maximum number of distinct `(key_id, stream_id)` windows
    /// tracked simultaneously. A value of `0` is treated as `1`.
    pub fn with_max_windows(mut self, max_windows: usize) -> Self {
        self.max_windows = max_windows.max(1);
        self
    }

    /// Returns the number of distinct windows currently tracked.
    pub fn tracked_windows(&self) -> usize {
        self.windows.len()
    }

    /// Returns how many frames this protector has rejected (duplicates,
    /// frames outside the window, and window-capacity rejections) since
    /// creation.
    ///
    /// This is an observability counter, not a security signal by itself:
    /// lossy/reordering transports legitimately produce occasional
    /// rejections, but a sustained rise indicates replay or flooding
    /// activity. It carries no key material.
    pub fn rejections(&self) -> u64 {
        self.rejections
    }

    /// Validates and records sequence number for `(key_id, stream_id)`.
    ///
    /// Returns [`CoreError::ReplayCapacityExceeded`] when a previously unseen
    /// `(key_id, stream_id)` pair would exceed the configured window cap, so a
    /// peer cannot force unbounded replay-map growth.
    pub fn check_and_record(
        &mut self,
        key_id: u8,
        stream_id: u32,
        seq: u64,
    ) -> Result<(), CoreError> {
        let result = match self.windows.get_mut(&(key_id, stream_id)) {
            Some(w) => w.check_and_record(seq),
            None => {
                if self.windows.len() >= self.max_windows {
                    Err(CoreError::ReplayCapacityExceeded)
                } else {
                    let mut w = ReplayWindow::new(self.window_size);
                    let result = w.check_and_record(seq);
                    self.windows.insert((key_id, stream_id), w);
                    result
                }
            }
        };
        if result.is_err() {
            self.rejections = self.rejections.saturating_add(1);
        }
        result
    }
}

impl Default for ReplayProtector {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_detects_duplicate_and_old() {
        let mut replay = ReplayWindow::new(8);

        replay.check_and_record(100).expect("accept 100");
        replay
            .check_and_record(99)
            .expect("accept 99 within window");
        replay
            .check_and_record(98)
            .expect("accept 98 within window");

        let dup = replay
            .check_and_record(99)
            .expect_err("duplicate must be rejected");
        assert!(matches!(dup, CoreError::Replay));

        replay.check_and_record(120).expect("advance window");
        let old = replay
            .check_and_record(100)
            .expect_err("old frame must be rejected");
        assert!(matches!(old, CoreError::ReplayWindowExceeded));
    }

    #[test]
    fn replay_window_accepts_out_of_order_within_window_once() {
        let mut replay = ReplayWindow::new(16);
        replay.check_and_record(10).expect("accept 10");
        replay.check_and_record(11).expect("accept 11");
        replay.check_and_record(12).expect("accept 12");

        replay.check_and_record(9).expect("accept 9 within window");
        replay.check_and_record(8).expect("accept 8 within window");
        replay.check_and_record(7).expect("accept 7 within window");

        let dup = replay
            .check_and_record(9)
            .expect_err("duplicate out-of-order frame must be rejected");
        assert!(matches!(dup, CoreError::Replay));
    }

    #[test]
    fn replay_window_rejects_exact_window_boundary() {
        let mut replay = ReplayWindow::new(8);
        replay.check_and_record(100).expect("accept 100");
        replay.check_and_record(107).expect("advance to 107");

        let boundary = replay
            .check_and_record(99)
            .expect_err("offset equal to window size must be rejected");
        assert!(matches!(boundary, CoreError::ReplayWindowExceeded));
    }

    #[test]
    fn replay_window_large_advance_clears_old_bitmap() {
        let mut replay = ReplayWindow::new(8);
        replay.check_and_record(10).expect("accept 10");
        replay.check_and_record(9).expect("accept 9");

        replay.check_and_record(30).expect("large forward jump");

        replay
            .check_and_record(23)
            .expect("frame still inside the new window should be accepted");
        let too_old = replay
            .check_and_record(22)
            .expect_err("outside window must be rejected");
        assert!(matches!(too_old, CoreError::ReplayWindowExceeded));
    }

    #[test]
    fn replay_protector_caps_distinct_windows() {
        let mut protector = ReplayProtector::new(64).with_max_windows(2);
        // Two distinct (key_id, stream_id) windows are accepted.
        protector.check_and_record(0, 0, 1).expect("first window");
        protector.check_and_record(0, 1, 1).expect("second window");
        assert_eq!(protector.tracked_windows(), 2);
        // A third distinct window exceeds the cap and is rejected.
        let err = protector
            .check_and_record(0, 2, 1)
            .expect_err("third distinct window must be rejected");
        assert!(matches!(err, CoreError::ReplayCapacityExceeded));
        // Existing windows keep working and do not count against the cap again.
        protector
            .check_and_record(0, 0, 2)
            .expect("existing window still accepts new sequences");
        assert_eq!(protector.tracked_windows(), 2);
    }

    #[test]
    fn replay_window_handles_u64_high_values() {
        let mut replay = ReplayWindow::new(32);
        let near_max = u64::MAX - 1;

        replay.check_and_record(near_max).expect("accept near max");
        replay.check_and_record(u64::MAX).expect("accept max");

        let dup = replay
            .check_and_record(near_max)
            .expect_err("duplicate near max");
        assert!(matches!(dup, CoreError::Replay));
    }
}
