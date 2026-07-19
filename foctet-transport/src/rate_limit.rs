//! Connection-level handshake admission control.
//!
//! A native Foctet handshake costs the responder an X25519 exchange, an HKDF
//! run, and (when identity auth is on) an Ed25519 verification before the peer
//! has proven anything. [`HandshakeRateLimiter`] bounds how fast a listener
//! accepts new handshakes so a hostile client (or a stampede of well-meaning
//! ones) cannot pin the accept loop's CPU: admission is a token bucket with a
//! sustained rate and a burst capacity, shared across connections by cloning
//! the limiter (clones share one bucket).
//!
//! ```rust,ignore
//! use foctet_transport::HandshakeRateLimiter;
//!
//! // Sustained 100 handshakes/second, bursts up to 200.
//! let limiter = HandshakeRateLimiter::new(100.0, 200);
//! loop {
//!     let (stream, _addr) = listener.accept().await?;
//!     limiter.admit()?; // fails fast with HandshakeRateLimited when saturated
//!     let limiter_task = builder.establish_responder_with_auth_and_timeout(
//!         stream, thresholds, auth.clone(), timeout);
//!     // ...
//! }
//! ```
//!
//! # Cancellation
//!
//! All `establish_*` handshake futures in this crate are **drop-cancellable**:
//! dropping the future (e.g. via `tokio::select!`, a surrounding
//! `tokio::time::timeout`, or task abort) abandons the handshake without
//! leaking protocol state — all session state lives inside the future, and the
//! underlying I/O object is simply dropped or returned to the caller. A
//! rejected or cancelled handshake consumes nothing beyond the admission token
//! already taken.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use foctet_core::CoreError;

/// Hard maximum concurrent admissions accepted by one limiter.
pub const MAX_CONCURRENT_HANDSHAKES: usize = 65_536;

/// Shared cap for concurrent handshakes or sessions.
#[derive(Clone, Debug)]
pub struct HandshakeConcurrencyLimiter {
    inner: Arc<ConcurrencyState>,
}

#[derive(Debug)]
struct ConcurrencyState {
    active: AtomicUsize,
    max: usize,
}

/// RAII admission permit. Dropping it releases one concurrent slot.
#[derive(Debug)]
pub struct HandshakePermit {
    inner: Arc<ConcurrencyState>,
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        self.inner.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl HandshakeConcurrencyLimiter {
    /// Creates a shared limiter, clamped to `1..=MAX_CONCURRENT_HANDSHAKES`.
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            inner: Arc::new(ConcurrencyState {
                active: AtomicUsize::new(0),
                max: max_concurrent.clamp(1, MAX_CONCURRENT_HANDSHAKES),
            }),
        }
    }

    /// Acquires one slot or fails before handshake allocation and cryptography.
    pub fn acquire(&self) -> Result<HandshakePermit, CoreError> {
        self.inner
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.inner.max).then_some(active + 1)
            })
            .map_err(|_| CoreError::HandshakeConcurrencyLimited)?;
        Ok(HandshakePermit {
            inner: self.inner.clone(),
        })
    }

    /// Returns the number of currently held permits.
    pub fn active(&self) -> usize {
        self.inner.active.load(Ordering::Acquire)
    }

    /// Returns the effective concurrent admission cap.
    pub fn max_concurrent(&self) -> usize {
        self.inner.max
    }
}

/// Token-bucket admission control for inbound (or outbound) handshakes.
///
/// Cheap to clone; all clones share the same bucket, so one limiter can guard
/// every connection a listener accepts. Thread-safe.
#[derive(Clone, Debug)]
pub struct HandshakeRateLimiter {
    inner: Arc<Mutex<Bucket>>,
}

#[derive(Debug)]
struct Bucket {
    /// Tokens currently available (fractional to keep refill precise).
    tokens: f64,
    /// Sustained refill rate, tokens per second.
    rate_per_sec: f64,
    /// Maximum tokens the bucket holds (burst capacity).
    burst: f64,
    /// Last refill timestamp.
    last_refill: Instant,
}

impl HandshakeRateLimiter {
    /// Creates a limiter allowing `rate_per_sec` sustained handshakes per
    /// second with bursts of up to `burst` (clamped to at least 1). The bucket
    /// starts full, so the first `burst` admissions succeed immediately.
    pub fn new(rate_per_sec: f64, burst: u32) -> Self {
        let burst = f64::from(burst.max(1));
        let rate_per_sec = if rate_per_sec.is_finite() && rate_per_sec > 0.0 {
            rate_per_sec
        } else {
            1.0
        };
        Self {
            inner: Arc::new(Mutex::new(Bucket {
                tokens: burst,
                rate_per_sec,
                burst,
                last_refill: Instant::now(),
            })),
        }
    }

    /// Attempts to admit one handshake now.
    ///
    /// Consumes one token on success; fails with
    /// [`CoreError::HandshakeRateLimited`] when the bucket is empty. This
    /// never blocks or sleeps — callers decide whether to drop the connection,
    /// queue it, or back off.
    pub fn admit(&self) -> Result<(), CoreError> {
        if self.try_admit() {
            Ok(())
        } else {
            Err(CoreError::HandshakeRateLimited)
        }
    }

    /// Non-erroring form of [`Self::admit`]: `true` if a token was consumed.
    pub fn try_admit(&self) -> bool {
        let mut bucket = self.inner.lock().expect("rate-limiter mutex poisoned");
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.rate_per_sec).min(bucket.burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_is_admitted_then_saturates() {
        let limiter = HandshakeRateLimiter::new(1000.0, 3);
        assert!(limiter.try_admit());
        assert!(limiter.try_admit());
        assert!(limiter.try_admit());
        // The bucket refills at 1000/s, so a tiny amount may trickle back in
        // between calls; drain whatever fraction accrued and then expect
        // saturation.
        let mut extra = 0;
        while limiter.try_admit() {
            extra += 1;
            assert!(extra < 100, "bucket must saturate near its burst size");
        }
        assert!(matches!(
            limiter.admit(),
            Err(CoreError::HandshakeRateLimited)
        ));
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = HandshakeRateLimiter::new(1000.0, 1);
        assert!(limiter.try_admit());
        assert!(!limiter.try_admit());
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limiter.try_admit(), "5ms at 1000/s must refill a token");
    }

    #[test]
    fn clones_share_one_bucket() {
        let limiter = HandshakeRateLimiter::new(0.001, 1);
        let clone = limiter.clone();
        assert!(limiter.try_admit());
        assert!(
            !clone.try_admit(),
            "a clone must observe the shared bucket as drained"
        );
    }

    #[test]
    fn degenerate_parameters_are_clamped() {
        let limiter = HandshakeRateLimiter::new(f64::NAN, 0);
        assert!(limiter.try_admit(), "burst clamps to 1");
        assert!(!limiter.try_admit());
    }

    #[test]
    fn concurrency_permits_bound_and_release_active_work() {
        let limiter = HandshakeConcurrencyLimiter::new(2);
        let first = limiter.acquire().expect("first");
        let second = limiter.acquire().expect("second");
        assert_eq!(limiter.active(), 2);
        assert!(matches!(
            limiter.acquire(),
            Err(CoreError::HandshakeConcurrencyLimited)
        ));
        drop(first);
        let replacement = limiter.acquire().expect("released slot");
        assert_eq!(limiter.active(), 2);
        drop((second, replacement));
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn concurrency_limit_clamps_hostile_configuration() {
        let limiter = HandshakeConcurrencyLimiter::new(usize::MAX);
        assert_eq!(limiter.max_concurrent(), MAX_CONCURRENT_HANDSHAKES);
    }
}
