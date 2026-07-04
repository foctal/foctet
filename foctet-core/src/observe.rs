//! Observability hooks for session lifecycle events.
//!
//! Production deployments need to see handshake outcomes, key rotations, and
//! rejected control traffic without scraping logs or exposing key material.
//! [`SessionObserver`] is a pluggable callback the [`crate::Session`] invokes
//! at those points; [`SessionEvent`] deliberately carries **only public
//! metadata** (roles, key *identifiers*, counts) — never key bytes, plaintext,
//! or identity secrets — so an observer can be wired straight into metrics or
//! tracing with no redaction layer.
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use foctet_core::{Session, RekeyThresholds, observe::{SessionEvent, SessionObserver}};
//!
//! struct Metrics;
//! impl SessionObserver for Metrics {
//!     fn on_session_event(&self, event: SessionEvent) {
//!         match event {
//!             SessionEvent::HandshakeCompleted { .. } => { /* counter += 1 */ }
//!             SessionEvent::RekeyApplied { new_key_id, .. } => { /* gauge = new_key_id */ }
//!             _ => {}
//!         }
//!     }
//! }
//!
//! let (session, hello) = Session::new_initiator(RekeyThresholds::default());
//! let session = session.with_observer(Arc::new(Metrics));
//! ```
//!
//! Replay-protection rejections are surfaced separately as counters on the
//! receiving endpoints (e.g. `FoctetFramed::replay_rejections`,
//! `SyncIo::replay_rejections`, `MessageEndpoint::replay_rejections`,
//! `DatagramEndpoint::replay_rejections`): datagram transports legitimately
//! duplicate packets, so per-event callbacks there would be noisy, but a
//! rising counter is a monitoring signal for replay/DoS activity.
//!
//! Observer callbacks run synchronously on the protocol path: keep them cheap
//! (increment a counter, push to a channel) and never block.

use std::{fmt, sync::Arc};

use crate::session::HandshakeRole;

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
