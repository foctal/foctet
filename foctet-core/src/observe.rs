//! Observability hooks for session lifecycle events.
//!
//! [`SessionObserver`] lets applications receive handshake, rekey, and control
//! rejection events without exposing key material or plaintext. [`SessionEvent`]
//! carries only public metadata, so observers can feed metrics or tracing
//! directly.
//!
//! Replay-protection rejections are exposed separately as counters on the
//! receiving endpoints.
//!
//! Observer callbacks run synchronously on the protocol path, so they should be
//! cheap and non-blocking.

use std::{fmt, sync::Arc};

use crate::session::HandshakeRole;

/// Stable, secret-free metric categories for protocol outcomes.
///
/// The labels returned by [`Self::as_str`] are intentionally low-cardinality
/// and contain no peer identifiers, key identifiers, plaintext, or wire input.
/// Applications can increment a counter after an operation returns an error
/// without logging the error's attacker-controlled details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecurityMetric {
    /// A handshake completed successfully.
    HandshakeCompleted,
    /// Peer authentication or handshake validation failed.
    HandshakeFailed,
    /// An AEAD authentication or encryption operation failed.
    AeadFailure,
    /// Replay protection rejected an inbound frame.
    ReplayRejected,
    /// A configured resource or admission limit was reached.
    LimitHit,
    /// A rekey generation was committed or applied.
    RekeyCompleted,
    /// An outbound result was ambiguous and the channel became terminal.
    AmbiguousSend,
}

impl SecurityMetric {
    /// Returns a stable metric label suitable for counters and traces.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HandshakeCompleted => "foctet.handshake.completed",
            Self::HandshakeFailed => "foctet.handshake.failed",
            Self::AeadFailure => "foctet.aead.failure",
            Self::ReplayRejected => "foctet.replay.rejected",
            Self::LimitHit => "foctet.limit.hit",
            Self::RekeyCompleted => "foctet.rekey.completed",
            Self::AmbiguousSend => "foctet.send.ambiguous",
        }
    }
}

/// A session lifecycle event. Carries only public metadata — no key material,
/// plaintext, or identity secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// The native handshake completed and traffic keys are installed.
    HandshakeCompleted {
        /// This side's handshake role.
        role: HandshakeRole,
        /// Whether the peer proved a pinned Ed25519 identity (a handshake
        /// relying solely on a channel binding reports `false`).
        peer_authenticated: bool,
    },
    /// This side initiated a DH-ratchet rekey and rotated its keys.
    RekeyInitiated {
        /// Key identifier rotated away from.
        old_key_id: u8,
        /// Newly active key identifier.
        new_key_id: u8,
    },
    /// A peer-initiated DH-ratchet rekey was verified and applied.
    RekeyApplied {
        /// Key identifier rotated away from.
        old_key_id: u8,
        /// Newly active key identifier.
        new_key_id: u8,
    },
    /// An inbound control message was rejected (failed validation,
    /// authentication, or arrived unexpectedly for the current state).
    /// A sustained stream of these is a probe/attack signal.
    ControlRejected,
}

impl SessionEvent {
    /// Maps this lifecycle event to a stable metric category.
    pub const fn metric(self) -> Option<SecurityMetric> {
        match self {
            Self::HandshakeCompleted { .. } => Some(SecurityMetric::HandshakeCompleted),
            Self::RekeyInitiated { .. } | Self::RekeyApplied { .. } => {
                Some(SecurityMetric::RekeyCompleted)
            }
            Self::ControlRejected => None,
        }
    }
}

/// Callback invoked by [`crate::Session`] on lifecycle events.
///
/// Implementations must be cheap and non-blocking; they run synchronously on
/// the protocol path. See the [module docs](self) for the security contract.
pub trait SessionObserver: Send + Sync {
    /// Called once per event.
    fn on_session_event(&self, event: SessionEvent);
}

/// Internal shareable, optional observer slot that keeps `Session`'s derived
/// `Clone`/`Debug` working (`dyn SessionObserver` itself is neither).
#[derive(Clone, Default)]
pub(crate) struct ObserverHandle(Option<Arc<dyn SessionObserver>>);

impl ObserverHandle {
    pub(crate) fn set(&mut self, observer: Arc<dyn SessionObserver>) {
        self.0 = Some(observer);
    }

    pub(crate) fn emit(&self, event: SessionEvent) {
        if let Some(observer) = &self.0 {
            observer.on_session_event(event);
        }
    }
}

impl fmt::Debug for ObserverHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(_) => f.write_str("ObserverHandle(Some(..))"),
            None => f.write_str("ObserverHandle(None)"),
        }
    }
}
