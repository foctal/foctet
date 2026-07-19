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

/// Asynchronous anti-replay store for durable / networked backends.
///
/// This is the trait to implement for stores that must perform I/O — Redis with
/// an atomic conditional write, a Durable Object, or a transactional SQL table
/// shared across instances — which is required once requests are served by more
/// than one process or serverless isolate (an [`InMemoryReplayStore`] is
/// single-process only). Cloudflare KV does **not** provide the required atomic
/// check-and-insert contract and must not be used for replay decisions.
///
/// The futures intentionally do **not** require `Send`, so the trait is usable
/// from `!Send` runtimes such as Cloudflare Workers. Implementations must keep
/// the same **atomic check-and-insert** contract as [`ReplayStore`].
///
/// Every synchronous [`ReplayStore`] is also an [`AsyncReplayStore`] via a
/// blanket implementation, so an [`InMemoryReplayStore`] works with the async
/// opener path too.
#[allow(async_fn_in_trait)]
pub trait AsyncReplayStore {
    /// Atomically records `message_id` (valid until `expires_at_secs`) and
    /// reports whether it had already been seen.
    async fn check_and_insert(
        &self,
        message_id: &[u8; MESSAGE_ID_LEN],
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<ReplayCheck, ReplayStoreError>;
}

impl<T> AsyncReplayStore for T
where
    T: ReplayStore + ?Sized,
{
    async fn check_and_insert(
        &self,
        message_id: &[u8; MESSAGE_ID_LEN],
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<ReplayCheck, ReplayStoreError> {
        ReplayStore::check_and_insert(self, message_id, expires_at_secs, now_secs)
    }
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

/// Encodes a replay-store key as `{prefix}{hex(message_id)}`.
#[cfg(any(feature = "redis", test))]
fn replay_key(prefix: &str, message_id: &[u8; MESSAGE_ID_LEN]) -> String {
    use std::fmt::Write;
    let mut key = String::with_capacity(prefix.len() + MESSAGE_ID_LEN * 2);
    key.push_str(prefix);
    for byte in message_id {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

/// Durable, multi-instance [`AsyncReplayStore`] backed by Redis.
///
/// Uses a single atomic `SET key 1 NX PX <ttl>` per check: Redis sets the key
/// only if absent and reports whether it did, giving the required atomic
/// check-and-insert, while `PX` lets Redis expire entries at the context's
/// expiry so the keyspace stays bounded without manual eviction.
///
/// Requires the `redis` feature and a reachable Redis server.
#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisReplayStore {
    client: redis::Client,
    prefix: String,
}

#[cfg(feature = "redis")]
impl RedisReplayStore {
    /// Default key prefix.
    pub const DEFAULT_PREFIX: &'static str = "foctet:replay:";

    /// Creates a store from an existing Redis client.
    pub fn new(client: redis::Client) -> Self {
        Self {
            client,
            prefix: Self::DEFAULT_PREFIX.to_string(),
        }
    }

    /// Opens a Redis client from a connection URL (e.g. `redis://127.0.0.1/`).
    pub fn open(url: &str) -> Result<Self, redis::RedisError> {
        Ok(Self::new(redis::Client::open(url)?))
    }

    /// Overrides the key prefix used for replay entries.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }
}

#[cfg(feature = "redis")]
impl AsyncReplayStore for RedisReplayStore {
    async fn check_and_insert(
        &self,
        message_id: &[u8; MESSAGE_ID_LEN],
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<ReplayCheck, ReplayStoreError> {
        let key = replay_key(&self.prefix, message_id);
        let ttl_ms = expires_at_secs
            .saturating_sub(now_secs)
            .max(1)
            .saturating_mul(1000);

        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| ReplayStoreError::Backend(e.to_string()))?;

        // `SET key 1 NX PX ttl` returns "OK" when the key was set (first use)
        // and nil (→ None) when it already existed (replay).
        let set: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(1i64)
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut conn)
            .await
            .map_err(|e| ReplayStoreError::Backend(e.to_string()))?;

        Ok(if set.is_some() {
            ReplayCheck::Accepted
        } else {
            ReplayCheck::Replay
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_key_is_prefixed_hex() {
        let mut id = [0u8; MESSAGE_ID_LEN];
        id[0] = 0xAB;
        id[15] = 0x01;
        assert_eq!(
            replay_key("foctet:replay:", &id),
            "foctet:replay:ab000000000000000000000000000001"
        );
    }

    #[tokio::test]
    async fn async_blanket_impl_enforces_replay() {
        // Any sync ReplayStore is also an AsyncReplayStore.
        let store = InMemoryReplayStore::new();
        let id = [5u8; MESSAGE_ID_LEN];
        assert_eq!(
            AsyncReplayStore::check_and_insert(&store, &id, 100, 10)
                .await
                .expect("first"),
            ReplayCheck::Accepted
        );
        assert_eq!(
            AsyncReplayStore::check_and_insert(&store, &id, 100, 10)
                .await
                .expect("second"),
            ReplayCheck::Replay
        );
    }

    #[test]
    fn first_use_accepted_second_use_is_replay() {
        let store = InMemoryReplayStore::new();
        let id = [9u8; MESSAGE_ID_LEN];
        assert_eq!(
            ReplayStore::check_and_insert(&store, &id, 100, 10).expect("first"),
            ReplayCheck::Accepted
        );
        assert_eq!(
            ReplayStore::check_and_insert(&store, &id, 100, 10).expect("second"),
            ReplayCheck::Replay
        );
    }

    #[test]
    fn expired_entries_are_evicted_and_capacity_enforced() {
        let store = InMemoryReplayStore::with_capacity(1);
        let id_a = [1u8; MESSAGE_ID_LEN];
        let id_b = [2u8; MESSAGE_ID_LEN];

        assert_eq!(
            ReplayStore::check_and_insert(&store, &id_a, 100, 10).expect("a"),
            ReplayCheck::Accepted
        );
        // At capacity while id_a is still live.
        assert!(matches!(
            ReplayStore::check_and_insert(&store, &id_b, 200, 50),
            Err(ReplayStoreError::AtCapacity)
        ));
        // After id_a expires it is evicted and id_b fits.
        assert_eq!(
            ReplayStore::check_and_insert(&store, &id_b, 200, 150).expect("b after expiry"),
            ReplayCheck::Accepted
        );
        assert_eq!(store.len(), 1);
    }
}
