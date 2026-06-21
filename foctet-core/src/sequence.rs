//! Internal fail-closed outbound sequence allocation.
//!
//! All outbound Foctet shapes share this small type so exhaustion handling
//! cannot drift between blocking, async, message, and datagram transports.

use crate::CoreError;

/// Tracks the sequence number to use for the next outbound frame.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OutboundSequence(u64);

impl OutboundSequence {
    /// Returns the sequence number for the frame currently being built.
    pub(crate) fn current(self) -> u64 {
        self.0
    }

    /// Returns the post-send state without modifying this allocator.
    ///
    /// Call this before emitting a frame, then [`Self::commit`] only after the
    /// frame has been accepted by the respective transport buffer or writer.
    pub(crate) fn prepared_next(self) -> Result<Self, CoreError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(CoreError::SequenceExhausted)
    }

    /// Commits a previously prepared post-send state.
    pub(crate) fn commit(&mut self, next: Self) {
        *self = next;
    }

    #[cfg(test)]
    pub(crate) fn set_for_test(&mut self, sequence: u64) {
        self.0 = sequence;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustion_is_fail_closed() {
        let last = OutboundSequence(u64::MAX - 1);
        let exhausted = last.prepared_next().expect("last sequence is usable");
        assert_eq!(exhausted.current(), u64::MAX);
        assert!(matches!(
            exhausted.prepared_next(),
            Err(CoreError::SequenceExhausted)
        ));
    }
}
