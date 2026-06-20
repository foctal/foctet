//! Anti-replay storage for HTTP protected contexts.
//!
//! A protected context binds a unique message ID and an absolute expiry into a
//! body envelope. The [`ReplayStore`] records message IDs that have been
//! accepted so a captured-and-resent request is rejected on its second use. The
//! contract is a single **atomic check-and-insert**: an implementation must, in
//! one indivisible step, report whether the ID was already present and record
//! it if not. The store is consulted **after** the envelope authenticates, so
//! unauthenticated input can never populate it.

use std::collections::HashMap;
use std::sync::Mutex;

use thiserror::Error;

use crate::context::MESSAGE_ID_LEN;

/// Default cap on the number of retained message IDs in [`InMemoryReplayStore`].
pub const DEFAULT_MAX_REPLAY_ENTRIES: usize = 1 << 20;

/// Error returned by a [`ReplayStore`] implementation.
#[derive(Debug, Error)]
pub enum ReplayStoreError {
    /// The store has reached its capacity and cannot accept a new entry.
    #[error("replay store is at capacity")]
    AtCapacity,
    /// A backend-specific failure occurred.
    #[error("replay store backend error: {0}")]
    Backend(String),
}

/// Outcome of an atomic check-and-insert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayCheck {
    /// The message ID had not been seen before and was recorded.
    Accepted,
    /// The message ID was already present: this is a replay.
    Replay,
}

impl ReplayCheck {
    /// Returns `true` when the message was a replay.
    pub fn is_replay(self) -> bool {
        matches!(self, ReplayCheck::Replay)
    }
}

/// Anti-replay store with an atomic check-and-insert contract.
pub trait ReplayStore {
    /// Atomically records `message_id` (valid until `expires_at_secs`) and
    /// reports whether it had already been seen.
    ///
    /// `now_secs` lets the implementation evict expired entries. The operation
    /// MUST be atomic: concurrent calls with the same ID must yield exactly one
    /// [`ReplayCheck::Accepted`].
    fn check_and_insert(
        &self,
        message_id: &[u8; MESSAGE_ID_LEN],
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<ReplayCheck, ReplayStoreError>;
}

/// Single-process in-memory [`ReplayStore`].
///
/// Suitable for a single server instance. It is **not** shared across processes
/// or across serverless isolates (e.g. Cloudflare Workers), which require a
/// durable backend implementing [`ReplayStore`] over shared storage.
#[derive(Debug)]
pub struct InMemoryReplayStore {
    entries: Mutex<HashMap<[u8; MESSAGE_ID_LEN], u64>>,
    max_entries: usize,
}

impl InMemoryReplayStore {
    /// Creates a store with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_REPLAY_ENTRIES)
    }

    /// Creates a store with an explicit capacity (`0` is treated as `1`).
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: max_entries.max(1),
        }
    }

    /// Returns the number of retained (not yet evicted) entries.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("replay store mutex").len()
    }

    /// Returns whether the store currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryReplayStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn check_and_insert(
        &self,
        message_id: &[u8; MESSAGE_ID_LEN],
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<ReplayCheck, ReplayStoreError> {
        let mut entries = self.entries.lock().expect("replay store mutex");

        // Drop expired entries so the cap reflects live, still-replayable IDs.
        entries.retain(|_, &mut expiry| expiry > now_secs);

        if entries.contains_key(message_id) {
            return Ok(ReplayCheck::Replay);
        }
        if entries.len() >= self.max_entries {
            return Err(ReplayStoreError::AtCapacity);
        }
        entries.insert(*message_id, expires_at_secs);
        Ok(ReplayCheck::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_accepted_second_use_is_replay() {
        let store = InMemoryReplayStore::new();
        let id = [9u8; MESSAGE_ID_LEN];
        assert_eq!(
            store.check_and_insert(&id, 100, 10).expect("first"),
            ReplayCheck::Accepted
        );
        assert_eq!(
            store.check_and_insert(&id, 100, 10).expect("second"),
            ReplayCheck::Replay
        );
    }

    #[test]
    fn expired_entries_are_evicted_and_capacity_enforced() {
        let store = InMemoryReplayStore::with_capacity(1);
        let id_a = [1u8; MESSAGE_ID_LEN];
        let id_b = [2u8; MESSAGE_ID_LEN];

        assert_eq!(
            store.check_and_insert(&id_a, 100, 10).expect("a"),
            ReplayCheck::Accepted
        );
        // At capacity while id_a is still live.
        assert!(matches!(
            store.check_and_insert(&id_b, 200, 50),
            Err(ReplayStoreError::AtCapacity)
        ));
        // After id_a expires it is evicted and id_b fits.
        assert_eq!(
            store.check_and_insert(&id_b, 200, 150).expect("b after expiry"),
            ReplayCheck::Accepted
        );
        assert_eq!(store.len(), 1);
    }
}
