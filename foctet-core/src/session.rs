use std::{sync::Arc, time::Duration};

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use self::mono::MonoInstant;

/// Monotonic clock abstraction for the age-based rekey threshold.
///
/// On native targets this is `std::time::Instant`. On `wasm32-unknown-unknown`
/// there is no monotonic clock, so `Instant::now()` aborts the module; there the
/// age-based rekey threshold is disabled (`elapsed()` always reports zero) while
/// the frame-count and byte-count thresholds still apply, and callers are
/// expected to drive rekey explicitly. See `SECURITY.md` for the WASM posture.
mod mono {
    use std::time::Duration;

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Clone, Copy, Debug)]
    pub(super) struct MonoInstant(std::time::Instant);

    #[cfg(not(target_arch = "wasm32"))]
    impl MonoInstant {
        pub(super) fn now() -> Self {
            Self(std::time::Instant::now())
        }

        pub(super) fn elapsed(&self) -> Duration {
            self.0.elapsed()
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[derive(Clone, Copy, Debug)]
    pub(super) struct MonoInstant;

    #[cfg(target_arch = "wasm32")]
    impl MonoInstant {
        pub(super) fn now() -> Self {
            Self
        }

        pub(super) fn elapsed(&self) -> Duration {
            Duration::ZERO
        }
    }
}

use crate::{
    CoreError,
    auth::{AuthenticatedPeer, HandshakeAuth, SessionAuthConfig},
    control::ControlMessage,
    crypto::{
        Direction, EphemeralKeyPair, KeyHandle, derive_ratchet_root, derive_traffic_keys,
        dh_ratchet_step, random_session_salt,
    },
    observe::{ObserverHandle, SessionEvent, SessionObserver},
};

/// Role of this endpoint in the native handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeRole {
    /// Endpoint starts handshake with `ClientHello`.
    Initiator,
    /// Endpoint waits for `ClientHello` and replies with `ServerHello`.
    Responder,
}

/// Session lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Session object was created but not started.
    Init,
    /// Waiting for peer handshake/control message.
    WaitingPeerHello,
    /// Handshake complete and traffic keys are available.
    Active,
    /// Session closed.
    Closed,
}

/// Rekey thresholds and key-retention policy.
#[derive(Clone, Debug)]
pub struct RekeyThresholds {
    /// Trigger rekey when outbound frame count reaches this value.
    pub max_frames: u64,
    /// Trigger rekey when outbound plaintext bytes reaches this value.
    pub max_bytes: u64,
    /// Trigger rekey when elapsed time since last rekey reaches this value.
    pub max_age: Duration,
    /// Number of previous keys retained for inbound compatibility.
    pub max_previous_keys: usize,
}

/// An immutable, not-yet-committed outbound DH-ratchet transition.
///
/// A prepared rekey contains the control message that must be encrypted with
/// the current (old) traffic key. It changes no session state until consumed by
/// [`Session::commit_rekey`]. Transport integrations must enqueue that exact
/// control message first, then commit; if output is rejected or ambiguous they
/// must close rather than use the prepared next generation.
pub struct PreparedRekey {
    message: ControlMessage,
    old_key_id: u8,
    new_key_id: u8,
    local_eph: EphemeralKeyPair,
    ratchet_root: Zeroizing<[u8; 32]>,
    next_keys: KeyHandle,
}

impl core::fmt::Debug for PreparedRekey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedRekey")
            .field("message", &self.message)
            .field("old_key_id", &self.old_key_id)
            .field("new_key_id", &self.new_key_id)
            .field("local_eph", &self.local_eph)
            .field("ratchet_root", &"<redacted>")
            .field("next_keys", &self.next_keys)
            .finish()
    }
}

impl PreparedRekey {
    /// Returns the old-key control message to enqueue exactly once.
    pub fn control_message(&self) -> &ControlMessage {
        &self.message
    }

    /// Returns the key identifier that protects [`Self::control_message`].
    pub fn old_key_id(&self) -> u8 {
        self.old_key_id
    }
}

impl Default for RekeyThresholds {
    fn default() -> Self {
        Self {
            max_frames: 1 << 20,
            max_bytes: 1 << 30,
            max_age: Duration::from_secs(600),
            max_previous_keys: 2,
        }
    }
}

/// Handshake + rekey state machine for Foctet Core.
#[derive(Clone, Debug)]
pub struct Session {
    role: HandshakeRole,
    state: SessionState,
    local_eph: EphemeralKeyPair,
    peer_eph_public: Option<[u8; 32]>,
    session_salt: [u8; 32],
    /// DH-ratchet root key, advanced by a fresh DH output at every rekey.
    ratchet_root: [u8; 32],
    /// Whether this side may initiate the next rekey. The DH ratchet alternates:
    /// after initiating a rekey this becomes `false` until the peer rekeys.
    can_rekey: bool,
    active_keys: Option<KeyHandle>,
    previous_keys: Vec<KeyHandle>,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    peer_authenticated: bool,
    authenticated_peer_key: Option<[u8; 32]>,
    outbound_frames: u64,
    outbound_bytes: u64,
    last_rekey_at: MonoInstant,
    observer: ObserverHandle,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.ratchet_root.zeroize();
        self.session_salt.zeroize();
    }
}

impl Session {
    /// Creates an initiator session and returns the initial `ClientHello`.
    pub fn new_initiator(thresholds: RekeyThresholds) -> (Self, ControlMessage) {
        Self::new_initiator_with_auth(thresholds, SessionAuthConfig::default())
    }

    /// Creates an initiator session with explicit authentication configuration.
    pub fn new_initiator_with_auth(
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
    ) -> (Self, ControlMessage) {
        let local_eph = EphemeralKeyPair::generate();
        let session_salt = random_session_salt();
        let binding =
            client_hello_binding(local_eph.public, session_salt, auth.channel_binding_bytes());
        let auth_payload = auth.local_signer().map(|signer| {
            HandshakeAuth::sign(
                signer,
                &client_auth_message(local_eph.public, session_salt, binding),
            )
        });

        let msg = ControlMessage::ClientHello {
            eph_public: local_eph.public,
            session_salt,
            transcript_binding: binding,
            auth: auth_payload,
        };

        (
            Self {
                role: HandshakeRole::Initiator,
                state: SessionState::WaitingPeerHello,
                local_eph,
                peer_eph_public: None,
                session_salt,
                ratchet_root: [0u8; 32],
                can_rekey: false,
                active_keys: None,
                previous_keys: Vec::new(),
                thresholds,
                auth,
                peer_authenticated: false,
                authenticated_peer_key: None,
                outbound_frames: 0,
                outbound_bytes: 0,
                last_rekey_at: MonoInstant::now(),
                observer: ObserverHandle::default(),
            },
            msg,
        )
    }

    /// Creates a responder session waiting for a peer `ClientHello`.
    pub fn new_responder(thresholds: RekeyThresholds) -> Self {
        Self::new_responder_with_auth(thresholds, SessionAuthConfig::default())
    }

    /// Creates a responder session with explicit authentication configuration.
    pub fn new_responder_with_auth(thresholds: RekeyThresholds, auth: SessionAuthConfig) -> Self {
        Self {
            role: HandshakeRole::Responder,
            state: SessionState::WaitingPeerHello,
            local_eph: EphemeralKeyPair::generate(),
            peer_eph_public: None,
            session_salt: [0u8; 32],
            ratchet_root: [0u8; 32],
            can_rekey: false,
            active_keys: None,
            previous_keys: Vec::new(),
            thresholds,
            auth,
            peer_authenticated: false,
            authenticated_peer_key: None,
            outbound_frames: 0,
            outbound_bytes: 0,
            last_rekey_at: MonoInstant::now(),
            observer: ObserverHandle::default(),
        }
    }

    /// Returns current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns configured handshake role.
    pub fn role(&self) -> HandshakeRole {
        self.role
    }

    /// Returns whether the peer presented and passed handshake authentication.
    pub fn peer_authenticated(&self) -> bool {
        self.peer_authenticated
    }

    /// Returns the peer whose Ed25519 identity was proven during the handshake,
    /// if any.
    ///
    /// This is the typed form of [`Session::peer_authenticated`]: it returns
    /// `Some` only after a successful handshake in which the remote presented a
    /// valid identity signature. A handshake authenticated solely by a
    /// [`crate::ChannelBinding`] (no Foctet identity) returns `None`.
    pub fn authenticated_peer(&self) -> Option<AuthenticatedPeer> {
        self.authenticated_peer_key.map(AuthenticatedPeer::new)
    }

    /// Returns outbound traffic direction for this role.
    pub fn outbound_direction(&self) -> Direction {
        match self.role {
            HandshakeRole::Initiator => Direction::C2S,
            HandshakeRole::Responder => Direction::S2C,
        }
    }

    /// Returns inbound traffic direction for this role.
    pub fn inbound_direction(&self) -> Direction {
        match self.role {
            HandshakeRole::Initiator => Direction::S2C,
            HandshakeRole::Responder => Direction::C2S,
        }
    }

    /// Installs an observer notified of session lifecycle events
    /// (see [`crate::observe`]). Events carry no key material.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn SessionObserver>) -> Self {
        self.observer.set(observer);
        self
    }

    /// Installs an observer on an existing session; see [`Self::with_observer`].
    pub fn set_observer(&mut self, observer: Arc<dyn SessionObserver>) {
        self.observer.set(observer);
    }

    /// Applies an incoming control message and optionally returns a response.
    pub fn handle_control(
        &mut self,
        msg: &ControlMessage,
    ) -> Result<Option<ControlMessage>, CoreError> {
        let result = self.handle_control_inner(msg);
        if result.is_err() {
            self.observer.emit(SessionEvent::ControlRejected);
        }
        result
    }

    fn handle_control_inner(
        &mut self,
        msg: &ControlMessage,
    ) -> Result<Option<ControlMessage>, CoreError> {
        match (self.role, self.state, msg) {
            (
                HandshakeRole::Responder,
                SessionState::WaitingPeerHello,
                ControlMessage::ClientHello {
                    eph_public,
                    session_salt,
                    transcript_binding,
                    auth,
                },
            ) => {
                let expected = client_hello_binding(
                    *eph_public,
                    *session_salt,
                    self.auth.channel_binding_bytes(),
                );
                if transcript_binding != &expected {
                    return Err(CoreError::InvalidControlMessage);
                }
                let authenticated_peer = self.verify_client_auth(
                    *eph_public,
                    *session_salt,
                    *transcript_binding,
                    auth.as_ref(),
                )?;

                self.peer_eph_public = Some(*eph_public);
                self.session_salt = *session_salt;
                let mut shared = self.local_eph.shared_secret(*eph_public)?;
                let keys = derive_traffic_keys(&shared, &self.session_salt, 0)?;
                self.ratchet_root = derive_ratchet_root(&self.session_salt, &shared)?;
                shared.zeroize();

                self.active_keys = Some(KeyHandle::new(keys));
                self.state = SessionState::Active;
                // The DH ratchet alternates; the initiator takes the first turn.
                self.can_rekey = false;
                self.peer_authenticated = authenticated_peer.is_some();
                self.authenticated_peer_key = authenticated_peer;
                self.last_rekey_at = MonoInstant::now();
                self.observer.emit(SessionEvent::HandshakeCompleted {
                    role: self.role,
                    peer_authenticated: self.peer_authenticated,
                });

                let server_binding = server_hello_binding(
                    *eph_public,
                    self.local_eph.public,
                    self.session_salt,
                    self.auth.channel_binding_bytes(),
                );
                let server_auth = self.auth.local_signer().map(|signer| {
                    HandshakeAuth::sign(
                        signer,
                        &server_auth_message(
                            *eph_public,
                            self.local_eph.public,
                            self.session_salt,
                            server_binding,
                        ),
                    )
                });
                Ok(Some(ControlMessage::ServerHello {
                    eph_public: self.local_eph.public,
                    transcript_binding: server_binding,
                    auth: server_auth,
                }))
            }
            (
                HandshakeRole::Initiator,
                SessionState::WaitingPeerHello,
                ControlMessage::ServerHello {
                    eph_public,
                    transcript_binding,
                    auth,
                },
            ) => {
                let expected = server_hello_binding(
                    self.local_eph.public,
                    *eph_public,
                    self.session_salt,
                    self.auth.channel_binding_bytes(),
                );
                if transcript_binding != &expected {
                    return Err(CoreError::InvalidControlMessage);
                }
                let authenticated_peer =
                    self.verify_server_auth(*eph_public, *transcript_binding, auth.as_ref())?;

                self.peer_eph_public = Some(*eph_public);
                let mut shared = self.local_eph.shared_secret(*eph_public)?;
                let keys = derive_traffic_keys(&shared, &self.session_salt, 0)?;
                self.ratchet_root = derive_ratchet_root(&self.session_salt, &shared)?;
                shared.zeroize();

                self.active_keys = Some(KeyHandle::new(keys));
                self.state = SessionState::Active;
                // The initiator takes the first DH-ratchet turn.
                self.can_rekey = true;
                self.peer_authenticated = authenticated_peer.is_some();
                self.authenticated_peer_key = authenticated_peer;
                self.last_rekey_at = MonoInstant::now();
                self.observer.emit(SessionEvent::HandshakeCompleted {
                    role: self.role,
                    peer_authenticated: self.peer_authenticated,
                });
                Ok(None)
            }
            (
                _,
                SessionState::Active,
                ControlMessage::Rekey {
                    old_key_id,
                    new_key_id,
                    ratchet_public,
                    transcript_binding,
                },
            ) => {
                let active = self
                    .active_keys
                    .as_ref()
                    .ok_or(CoreError::InvalidSessionState)?;
                if *old_key_id != active.key_id {
                    return Err(CoreError::UnexpectedControlMessage);
                }
                if *new_key_id != old_key_id.wrapping_add(1) {
                    return Err(CoreError::InvalidControlMessage);
                }

                let expected =
                    rekey_binding(*old_key_id, *new_key_id, ratchet_public, self.session_salt);
                if transcript_binding != &expected {
                    return Err(CoreError::InvalidControlMessage);
                }

                // DH-ratchet receive step: mix DH(my current ratchet key, the
                // peer's fresh ratchet public) into the root chain, then adopt
                // the peer's new public. After receiving it becomes our turn to
                // initiate the next rekey.
                let mut dh = self.local_eph.shared_secret(*ratchet_public)?;
                let (new_root, next) = dh_ratchet_step(&self.ratchet_root, &dh, *new_key_id)?;
                dh.zeroize();
                self.peer_eph_public = Some(*ratchet_public);
                self.ratchet_root = new_root;
                self.install_new_active_key(next);
                self.can_rekey = true;
                self.last_rekey_at = MonoInstant::now();
                self.observer.emit(SessionEvent::RekeyApplied {
                    old_key_id: *old_key_id,
                    new_key_id: *new_key_id,
                });
                Ok(None)
            }
            (_, SessionState::Active, ControlMessage::Error { .. }) => Ok(None),
            _ => Err(CoreError::UnexpectedControlMessage),
        }
    }

    /// Returns a handle to the currently active traffic keys, if session is
    /// active.
    ///
    /// The returned [`KeyHandle`] shares the underlying key bytes by reference
    /// count; it does not copy the secret material.
    pub fn active_keys(&self) -> Option<KeyHandle> {
        self.active_keys.clone()
    }

    /// Returns handles to the active key followed by retained previous keys.
    pub fn active_and_previous_keys(&self) -> Option<Vec<KeyHandle>> {
        let mut out = Vec::new();
        let active = self.active_keys.clone()?;
        out.push(active);
        out.extend(self.previous_keys.iter().cloned());
        Some(out)
    }

    /// Returns current key ring as transport-ready list of handles.
    pub fn key_ring(&self) -> Result<Vec<KeyHandle>, CoreError> {
        self.active_and_previous_keys()
            .ok_or(CoreError::InvalidSessionState)
    }

    /// Records outbound payload usage and emits rekey control when needed.
    pub(crate) fn on_outbound_payload(
        &mut self,
        plaintext_len: usize,
    ) -> Result<Option<PreparedRekey>, CoreError> {
        if self.state != SessionState::Active {
            return Err(CoreError::InvalidSessionState);
        }

        self.outbound_frames = self.outbound_frames.saturating_add(1);
        self.outbound_bytes = self.outbound_bytes.saturating_add(plaintext_len as u64);

        // Threshold-driven rekey is best-effort and respects the DH-ratchet
        // turn: if it is the peer's turn to ratchet, defer rather than fail —
        // we keep using the current key until the peer rekeys (which hands the
        // turn back) or the threshold is re-checked on a later send.
        if self.should_rekey() && self.can_rekey {
            return self.prepare_rekey().map(Some);
        }

        Ok(None)
    }

    /// Whether it is this side's turn to initiate the next DH-ratchet rekey.
    ///
    /// Rekeys strictly alternate: the initiator holds the first turn, and each
    /// applied rekey hands the turn to the other side. When this returns
    /// `false`, [`Session::prepare_rekey`] fails with
    /// [`CoreError::RekeyNotPermitted`].
    pub fn can_rekey(&self) -> bool {
        self.state == SessionState::Active && self.can_rekey
    }

    /// Prepares an immediate rekey without changing this session.
    ///
    /// The returned control message MUST be accepted by the transport under
    /// `old_key_id` before calling [`Self::commit_rekey`]. Dropping it leaves
    /// the session unchanged.
    pub fn prepare_rekey(&self) -> Result<PreparedRekey, CoreError> {
        if self.state != SessionState::Active {
            return Err(CoreError::InvalidSessionState);
        }
        if !self.can_rekey {
            return Err(CoreError::RekeyNotPermitted);
        }

        let active = self
            .active_keys
            .clone()
            .ok_or(CoreError::InvalidSessionState)?;
        let old_key_id = active.key_id;
        let new_key_id = old_key_id.checked_add(1).ok_or(CoreError::KeyIdExhausted)?;
        let peer_public = self
            .peer_eph_public
            .ok_or(CoreError::MissingSessionSecret)?;

        // DH-ratchet send step: rotate to a fresh ephemeral key and mix
        // DH(new ephemeral, peer's current ratchet public) into the root chain.
        let new_eph = EphemeralKeyPair::generate();
        let mut dh = new_eph.shared_secret(peer_public)?;
        let (new_root, next) = dh_ratchet_step(&self.ratchet_root, &dh, new_key_id)?;
        dh.zeroize();
        let ratchet_public = new_eph.public;
        let transcript_binding =
            rekey_binding(old_key_id, new_key_id, &ratchet_public, self.session_salt);
        Ok(PreparedRekey {
            message: ControlMessage::Rekey {
                old_key_id,
                new_key_id,
                ratchet_public,
                transcript_binding,
            },
            old_key_id,
            new_key_id,
            local_eph: new_eph,
            ratchet_root: Zeroizing::new(new_root),
            next_keys: KeyHandle::new(next),
        })
    }

    /// Commits a rekey that was already accepted for outbound delivery.
    pub fn commit_rekey(&mut self, prepared: PreparedRekey) -> Result<(), CoreError> {
        let active = self
            .active_keys
            .as_ref()
            .ok_or(CoreError::InvalidSessionState)?;
        if self.state != SessionState::Active
            || !self.can_rekey
            || active.key_id != prepared.old_key_id
            || prepared.next_keys.key_id != prepared.new_key_id
        {
            return Err(CoreError::InvalidSessionState);
        }

        let PreparedRekey {
            old_key_id,
            new_key_id,
            local_eph,
            ratchet_root,
            next_keys,
            ..
        } = prepared;
        self.local_eph = local_eph;
        self.ratchet_root.zeroize();
        self.ratchet_root = *ratchet_root;
        self.install_new_active_key(next_keys);
        self.can_rekey = false;
        self.outbound_frames = 0;
        self.outbound_bytes = 0;
        self.last_rekey_at = MonoInstant::now();
        self.observer.emit(SessionEvent::RekeyInitiated {
            old_key_id,
            new_key_id,
        });
        Ok(())
    }

    /// Test-only convenience that commits a prepared rekey immediately.
    ///
    /// Production code must use [`Self::prepare_rekey`] and
    /// [`Self::commit_rekey`] around its atomic output transaction.
    #[cfg(test)]
    pub fn force_rekey(&mut self) -> Result<ControlMessage, CoreError> {
        let prepared = self.prepare_rekey()?;
        let message = prepared.control_message().clone();
        self.commit_rekey(prepared)?;
        Ok(message)
    }

    fn should_rekey(&self) -> bool {
        self.outbound_frames >= self.thresholds.max_frames
            || self.outbound_bytes >= self.thresholds.max_bytes
            || self.last_rekey_at.elapsed() >= self.thresholds.max_age
    }

    fn install_new_active_key(&mut self, next: impl Into<KeyHandle>) {
        if let Some(current) = self.active_keys.take() {
            self.previous_keys.insert(0, current);
            if self.previous_keys.len() > self.thresholds.max_previous_keys {
                self.previous_keys
                    .truncate(self.thresholds.max_previous_keys);
            }
        }
        self.active_keys = Some(next.into());
    }

    fn verify_client_auth(
        &self,
        eph_public: [u8; 32],
        session_salt: [u8; 32],
        transcript_binding: [u8; 32],
        auth: Option<&HandshakeAuth>,
    ) -> Result<Option<[u8; 32]>, CoreError> {
        let message = client_auth_message(eph_public, session_salt, transcript_binding);
        self.verify_auth_payload(auth, &message)
    }

    fn verify_server_auth(
        &self,
        server_public: [u8; 32],
        transcript_binding: [u8; 32],
        auth: Option<&HandshakeAuth>,
    ) -> Result<Option<[u8; 32]>, CoreError> {
        let message = server_auth_message(
            self.local_eph.public,
            server_public,
            self.session_salt,
            transcript_binding,
        );
        self.verify_auth_payload(auth, &message)
    }

    /// Verifies an optional handshake auth payload.
    ///
    /// Returns `Ok(Some(identity_public_key))` when the peer proved a (possibly
    /// pinned) Ed25519 identity, `Ok(None)` when the peer presented no identity
    /// and that is explicitly permitted, and an error otherwise.
    fn verify_auth_payload(
        &self,
        auth: Option<&HandshakeAuth>,
        message: &[u8],
    ) -> Result<Option<[u8; 32]>, CoreError> {
        match auth {
            Some(auth) => {
                auth.verify(message)?;
                if let Some(peer_identity) = self.auth.peer_identity()
                    && auth.identity_public_key != peer_identity.public_key
                {
                    return Err(CoreError::PeerIdentityMismatch);
                }
                Ok(Some(auth.identity_public_key))
            }
            // Peer presented no authentication. Fail closed unless the caller
            // explicitly opted into an unauthenticated handshake. A pinned peer
            // identity or an explicit requirement always demands authentication.
            None if self.auth.requires_peer_authentication()
                || self.auth.peer_identity().is_some() =>
            {
                Err(CoreError::MissingPeerAuthentication)
            }
            None if self.auth.allows_unauthenticated() => Ok(None),
            None => Err(CoreError::MissingPeerAuthentication),
        }
    }
}

/// Mixes an optional outer-channel binding into a transcript hash.
///
/// When `channel_binding` is empty this is a no-op, so a handshake configured
/// without a binding hashes byte-identically to before this field existed. When
/// present it is added length-prefixed under a domain separator so distinct
/// bindings can never collide with other transcript fields.
fn mix_channel_binding(hasher: &mut Sha256, channel_binding: &[u8]) {
    if !channel_binding.is_empty() {
        hasher.update(b"foctet channel-binding");
        hasher.update((channel_binding.len() as u64).to_be_bytes());
        hasher.update(channel_binding);
    }
}

fn client_hello_binding(
    client_public: [u8; 32],
    session_salt: [u8; 32],
    channel_binding: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"foctet hs client");
    hasher.update(client_public);
    hasher.update(session_salt);
    mix_channel_binding(&mut hasher, channel_binding);
    hasher.finalize().into()
}

fn client_auth_message(
    client_public: [u8; 32],
    session_salt: [u8; 32],
    transcript_binding: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(19 + 32 + 32 + 32);
    out.extend_from_slice(b"foctet auth client");
    out.extend_from_slice(&client_public);
    out.extend_from_slice(&session_salt);
    out.extend_from_slice(&transcript_binding);
    out
}

fn server_hello_binding(
    client_public: [u8; 32],
    server_public: [u8; 32],
    session_salt: [u8; 32],
    channel_binding: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"foctet hs server");
    hasher.update(client_public);
    hasher.update(server_public);
    hasher.update(session_salt);
    mix_channel_binding(&mut hasher, channel_binding);
    hasher.finalize().into()
}

fn server_auth_message(
    client_public: [u8; 32],
    server_public: [u8; 32],
    session_salt: [u8; 32],
    transcript_binding: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(19 + 32 + 32 + 32 + 32);
    out.extend_from_slice(b"foctet auth server");
    out.extend_from_slice(&client_public);
    out.extend_from_slice(&server_public);
    out.extend_from_slice(&session_salt);
    out.extend_from_slice(&transcript_binding);
    out
}

fn rekey_binding(
    old_key_id: u8,
    new_key_id: u8,
    ratchet_public: &[u8; 32],
    session_salt: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"foctet rekey");
    hasher.update([old_key_id]);
    hasher.update([new_key_id]);
    hasher.update(ratchet_public);
    hasher.update(session_salt);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdentityKeyPair, PeerIdentity};

    #[test]
    fn session_handshake_and_rekey() {
        let (mut client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );

        let server_hello = server
            .handle_control(&hello)
            .expect("server handle client hello")
            .expect("server hello response");

        client
            .handle_control(&server_hello)
            .expect("client handle server hello");

        assert_eq!(client.state(), SessionState::Active);
        assert_eq!(server.state(), SessionState::Active);

        let rekey = client.force_rekey().expect("client force rekey");
        server.handle_control(&rekey).expect("server handle rekey");

        let client_key = client.active_keys().expect("client active key");
        let server_key = server.active_keys().expect("server active key");
        assert_eq!(client_key.key_id, server_key.key_id);
        // The DH-ratchet step must derive byte-identical traffic keys on both
        // sides, or the channel would desync after rekey.
        assert_eq!(client_key, server_key);
    }

    #[test]
    fn dh_ratchet_alternates_and_rotates_both_sides_keys() {
        let (mut client, mut server) = active_pair();

        // The initiator takes the first turn; the responder cannot rekey yet.
        assert!(matches!(
            server.force_rekey(),
            Err(CoreError::RekeyNotPermitted)
        ));

        let mut last_key: Option<KeyHandle> = None;
        // Several alternating rounds: client, server, client, server, ...
        for round in 0..4 {
            let (rekeyer, receiver) = if round % 2 == 0 {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };

            // The side out of turn cannot initiate.
            assert!(matches!(
                receiver.force_rekey(),
                Err(CoreError::RekeyNotPermitted)
            ));

            let rekey = rekeyer.force_rekey().expect("force rekey on turn");
            // Having just rekeyed, the same side may not rekey again.
            assert!(matches!(
                rekeyer.force_rekey(),
                Err(CoreError::RekeyNotPermitted)
            ));
            receiver.handle_control(&rekey).expect("peer applies rekey");

            let ck = client.active_keys().expect("client key");
            let sk = server.active_keys().expect("server key");
            assert_eq!(ck.key_id, (round as u8) + 1);
            assert_eq!(ck, sk, "both sides must derive the same key");
            // Each ratchet step must yield a fresh key, never a repeat.
            if let Some(prev) = &last_key {
                assert_ne!(prev, &ck, "rekey must rotate to a fresh key");
            }
            last_key = Some(ck.clone());
        }
    }

    #[test]
    fn rekey_with_a_jumped_new_key_id_is_rejected() {
        let (mut client, mut server) = active_pair();
        let mut rekey = client.force_rekey().expect("client force rekey");
        if let ControlMessage::Rekey { new_key_id, .. } = &mut rekey {
            *new_key_id = 5; // not old_key_id + 1
        }
        let err = server
            .handle_control(&rekey)
            .expect_err("a non-sequential new_key_id must be rejected");
        assert!(matches!(err, CoreError::InvalidControlMessage));
    }

    #[test]
    fn session_authenticates_pinned_peer_identities() {
        let client_identity = IdentityKeyPair::from_secret_key_bytes([0x41; 32]);
        let server_identity = IdentityKeyPair::from_secret_key_bytes([0x61; 32]);
        let client_auth = SessionAuthConfig::new()
            .with_local_identity(client_identity.clone())
            .with_peer_identity(PeerIdentity::new(server_identity.public_key()))
            .require_peer_authentication(true);
        let server_auth = SessionAuthConfig::new()
            .with_local_identity(server_identity.clone())
            .with_peer_identity(PeerIdentity::new(client_identity.public_key()))
            .require_peer_authentication(true);

        let (mut client, hello) =
            Session::new_initiator_with_auth(RekeyThresholds::default(), client_auth);
        let mut server = Session::new_responder_with_auth(RekeyThresholds::default(), server_auth);

        let server_hello = server
            .handle_control(&hello)
            .expect("server handle client hello")
            .expect("server hello response");
        client
            .handle_control(&server_hello)
            .expect("client handle server hello");

        assert!(client.peer_authenticated());
        assert!(server.peer_authenticated());

        // The typed authenticated-peer record names the verified identity.
        let server_seen = client.authenticated_peer().expect("client sees a peer");
        assert_eq!(
            server_seen.identity_public_key(),
            server_identity.public_key()
        );
        assert!(server_seen.matches(&PeerIdentity::new(server_identity.public_key())));
        let client_seen = server.authenticated_peer().expect("server sees a peer");
        assert_eq!(
            client_seen.identity_public_key(),
            client_identity.public_key()
        );
    }

    #[test]
    fn external_handshake_signer_authenticates_like_a_software_identity() {
        use crate::HandshakeSigner;

        // A stand-in for a hardware/KMS signer: it implements `HandshakeSigner`
        // without being an `IdentityKeyPair`, exercising `with_local_signer` and
        // the `&dyn HandshakeSigner` handshake path.
        struct ExternalSigner(IdentityKeyPair);
        impl HandshakeSigner for ExternalSigner {
            fn public_key(&self) -> [u8; 32] {
                self.0.public_key()
            }
            fn sign(&self, message: &[u8]) -> [u8; 64] {
                self.0.sign(message)
            }
        }

        let client_identity = IdentityKeyPair::from_secret_key_bytes([0x71; 32]);
        let server_identity = IdentityKeyPair::from_secret_key_bytes([0x72; 32]);
        let client_pub = client_identity.public_key();
        let server_pub = server_identity.public_key();

        let client_auth = SessionAuthConfig::new()
            .with_local_signer(ExternalSigner(client_identity))
            .with_peer_identity(PeerIdentity::new(server_pub))
            .require_peer_authentication(true);
        let server_auth = SessionAuthConfig::new()
            .with_local_signer(ExternalSigner(server_identity))
            .with_peer_identity(PeerIdentity::new(client_pub))
            .require_peer_authentication(true);

        let (mut client, hello) =
            Session::new_initiator_with_auth(RekeyThresholds::default(), client_auth);
        let mut server = Session::new_responder_with_auth(RekeyThresholds::default(), server_auth);

        let server_hello = server
            .handle_control(&hello)
            .expect("server handles client hello")
            .expect("server hello");
        client
            .handle_control(&server_hello)
            .expect("client finalizes");

        assert!(client.peer_authenticated() && server.peer_authenticated());
        assert_eq!(
            client
                .authenticated_peer()
                .expect("peer")
                .identity_public_key(),
            server_pub
        );
        assert_eq!(
            server
                .authenticated_peer()
                .expect("peer")
                .identity_public_key(),
            client_pub
        );
    }

    #[test]
    fn channel_binding_only_handshake_has_no_authenticated_peer() {
        use crate::ChannelBinding;
        let binding = ChannelBinding::new(b"tls-exporter:no-identity".to_vec());
        let (mut client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::bound_to_channel(binding.clone()),
        );
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::bound_to_channel(binding),
        );
        let server_hello = server
            .handle_control(&hello)
            .expect("server handles hello")
            .expect("server hello");
        client
            .handle_control(&server_hello)
            .expect("client finalizes");

        // No Foctet identity was proven, so there is no authenticated peer even
        // though the handshake completed (its MITM resistance is the channel).
        assert!(client.authenticated_peer().is_none());
        assert!(server.authenticated_peer().is_none());
    }

    #[test]
    fn matching_channel_binding_completes_handshake_without_identity() {
        use crate::ChannelBinding;
        let binding = ChannelBinding::new(b"tls-exporter:matching-outer-channel".to_vec());
        let (mut client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::bound_to_channel(binding.clone()),
        );
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::bound_to_channel(binding),
        );

        let server_hello = server
            .handle_control(&hello)
            .expect("server accepts a matching channel binding")
            .expect("server hello response");
        client
            .handle_control(&server_hello)
            .expect("client accepts a matching channel binding");

        assert_eq!(client.state(), SessionState::Active);
        assert_eq!(server.state(), SessionState::Active);
        // The channel — not a Foctet identity — provided MITM resistance.
        assert!(!client.peer_authenticated());
        assert!(!server.peer_authenticated());
    }

    #[test]
    fn mismatched_channel_binding_fails_handshake() {
        use crate::ChannelBinding;
        // Models a relay: each side is bound to a different outer channel.
        let (_client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::bound_to_channel(ChannelBinding::new(b"channel-A".to_vec())),
        );
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::bound_to_channel(ChannelBinding::new(b"channel-B".to_vec())),
        );

        let err = server
            .handle_control(&hello)
            .expect_err("a channel-binding mismatch must fail closed");
        assert!(matches!(err, CoreError::InvalidControlMessage));
    }

    #[test]
    fn channel_binding_must_be_present_on_both_sides() {
        use crate::ChannelBinding;
        // The initiator binds to a channel; the responder does not.
        let (_client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::bound_to_channel(ChannelBinding::new(b"channel-A".to_vec())),
        );
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );

        let err = server
            .handle_control(&hello)
            .expect_err("a one-sided channel binding must fail closed");
        assert!(matches!(err, CoreError::InvalidControlMessage));
    }

    #[test]
    fn channel_binding_strengthens_identity_authenticated_handshake() {
        use crate::ChannelBinding;
        let client_identity = IdentityKeyPair::from_secret_key_bytes([0x41; 32]);
        let server_identity = IdentityKeyPair::from_secret_key_bytes([0x61; 32]);
        let binding = ChannelBinding::new(b"tls-exporter:bound".to_vec());
        let client_auth = SessionAuthConfig::new()
            .with_local_identity(client_identity.clone())
            .with_peer_identity(PeerIdentity::new(server_identity.public_key()))
            .require_peer_authentication(true)
            .with_channel_binding(binding.clone());
        let server_auth = SessionAuthConfig::new()
            .with_local_identity(server_identity.clone())
            .with_peer_identity(PeerIdentity::new(client_identity.public_key()))
            .require_peer_authentication(true)
            .with_channel_binding(binding);

        let (mut client, hello) =
            Session::new_initiator_with_auth(RekeyThresholds::default(), client_auth);
        let mut server = Session::new_responder_with_auth(RekeyThresholds::default(), server_auth);

        let server_hello = server
            .handle_control(&hello)
            .expect("server handle client hello")
            .expect("server hello response");
        client
            .handle_control(&server_hello)
            .expect("client handle server hello");

        assert!(client.peer_authenticated());
        assert!(server.peer_authenticated());
    }

    #[test]
    fn responder_rejects_unauthenticated_hello_by_default() {
        // A default (fail-closed) responder must refuse a ClientHello that
        // carries no authentication, even though the transcript binding is
        // valid. This is the baseline downgrade/MITM defense.
        let (_client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut server = Session::new_responder(RekeyThresholds::default());
        let err = server
            .handle_control(&hello)
            .expect_err("default responder must reject unauthenticated hello");
        assert!(matches!(err, CoreError::MissingPeerAuthentication));
        assert_eq!(server.state(), SessionState::WaitingPeerHello);
    }

    #[test]
    fn initiator_rejects_unauthenticated_server_hello_by_default() {
        // The initiator is fail-closed: an unauthenticated ServerHello is
        // rejected unless the caller explicitly allowed unauthenticated mode.
        let (mut client, hello) = Session::new_initiator(RekeyThresholds::default());
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let server_hello = server
            .handle_control(&hello)
            .expect("responder accepts hello in unauthenticated test mode")
            .expect("server hello");
        let err = client
            .handle_control(&server_hello)
            .expect_err("default initiator must reject unauthenticated server hello");
        assert!(matches!(err, CoreError::MissingPeerAuthentication));
    }

    #[test]
    fn unauthenticated_handshake_requires_explicit_opt_in_on_both_sides() {
        let (mut client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let server_hello = server
            .handle_control(&hello)
            .expect("server handle hello")
            .expect("server hello");
        client
            .handle_control(&server_hello)
            .expect("client handle server hello");
        assert_eq!(client.state(), SessionState::Active);
        assert_eq!(server.state(), SessionState::Active);
        // No identities were configured, so neither side is authenticated.
        assert!(!client.peer_authenticated());
        assert!(!server.peer_authenticated());
    }

    fn active_pair() -> (Session, Session) {
        let (mut client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let server_hello = server
            .handle_control(&hello)
            .expect("server handle client hello")
            .expect("server hello response");
        client
            .handle_control(&server_hello)
            .expect("client handle server hello");
        (client, server)
    }

    #[test]
    fn replayed_rekey_message_is_rejected_after_a_real_rekey() {
        // A Rekey control message names the `old_key_id` it rotates away
        // from. Once that rotation has happened, the same message replayed
        // (e.g. captured off the wire) must be rejected: `old_key_id` no
        // longer matches the active key, so it cannot be re-applied or roll
        // the session back to the previous key.
        let (mut client, mut server) = active_pair();

        let rekey = client.force_rekey().expect("client force rekey");
        server
            .handle_control(&rekey)
            .expect("server applies first rekey");

        let err = server
            .handle_control(&rekey)
            .expect_err("replaying the same rekey message must be rejected");
        assert!(matches!(err, CoreError::UnexpectedControlMessage));
    }

    #[test]
    fn prepared_rekey_does_not_mutate_until_committed() {
        let (mut client, mut server) = active_pair();
        let old = client.active_keys().expect("active key");

        let prepared = client.prepare_rekey().expect("prepare rekey");
        assert_eq!(prepared.old_key_id(), old.key_id);
        assert_eq!(client.active_keys().expect("still old key"), old);
        assert!(client.can_rekey(), "prepare must not hand over the turn");

        let message = prepared.control_message().clone();
        client.commit_rekey(prepared).expect("commit rekey");
        assert_eq!(
            client.active_keys().expect("new key").key_id,
            old.key_id + 1
        );
        assert!(!client.can_rekey());
        server
            .handle_control(&message)
            .expect("peer applies committed rekey");
        assert_eq!(client.active_keys(), server.active_keys());
    }

    #[test]
    fn rekey_message_with_stale_old_key_id_is_rejected() {
        // A rekey collision/out-of-order scenario: the responder is still on
        // key 0, but receives a `Rekey` claiming to rotate away from a key it
        // never activated. It must reject this instead of silently
        // installing a derived key the two sides disagree about.
        let (_client, mut server) = active_pair();
        let forged_rekey = ControlMessage::Rekey {
            old_key_id: 99,
            new_key_id: 100,
            ratchet_public: [0x42; 32],
            transcript_binding: [0u8; 32],
        };
        let err = server
            .handle_control(&forged_rekey)
            .expect_err("rekey from an unrecognized old_key_id must be rejected");
        assert!(matches!(err, CoreError::UnexpectedControlMessage));
    }

    #[test]
    fn observer_sees_handshake_rekey_and_rejections_without_secrets() {
        use std::sync::Mutex;

        #[derive(Default)]
        struct Recorder(Mutex<Vec<SessionEvent>>);
        impl SessionObserver for Recorder {
            fn on_session_event(&self, event: SessionEvent) {
                self.0.lock().expect("recorder lock").push(event);
            }
        }

        let client_events = Arc::new(Recorder::default());
        let server_events = Arc::new(Recorder::default());

        let (client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut client = client.with_observer(client_events.clone());
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        )
        .with_observer(server_events.clone());

        let server_hello = server
            .handle_control(&hello)
            .expect("server handles hello")
            .expect("server hello");
        client
            .handle_control(&server_hello)
            .expect("client finalizes");

        assert_eq!(
            *client_events.0.lock().expect("lock"),
            vec![SessionEvent::HandshakeCompleted {
                role: HandshakeRole::Initiator,
                peer_authenticated: false,
            }]
        );
        assert_eq!(
            *server_events.0.lock().expect("lock"),
            vec![SessionEvent::HandshakeCompleted {
                role: HandshakeRole::Responder,
                peer_authenticated: false,
            }]
        );

        // Rekey: initiator emits RekeyInitiated, receiver RekeyApplied.
        let rekey = client.force_rekey().expect("client rekeys");
        server.handle_control(&rekey).expect("server applies");
        assert_eq!(
            client_events.0.lock().expect("lock").last(),
            Some(&SessionEvent::RekeyInitiated {
                old_key_id: 0,
                new_key_id: 1,
            })
        );
        assert_eq!(
            server_events.0.lock().expect("lock").last(),
            Some(&SessionEvent::RekeyApplied {
                old_key_id: 0,
                new_key_id: 1,
            })
        );

        // A rejected control message (replayed rekey) emits ControlRejected.
        assert!(server.handle_control(&rekey).is_err());
        assert_eq!(
            server_events.0.lock().expect("lock").last(),
            Some(&SessionEvent::ControlRejected)
        );
    }

    #[test]
    fn rekey_delivered_ahead_of_order_is_rejected_and_state_is_unchanged() {
        // Out-of-order delivery in the *forward* direction: the receiver is
        // active on key `k`, but a `Rekey` arrives that rotates away from
        // `k + 1` — the transition a *future* rekey would name, as if a later
        // ratchet message overtook the pending one. Even with a transcript
        // binding that is internally consistent for its own key ids, it must
        // be rejected (the ratchet chain cannot skip a step), and the session
        // must remain usable: the correctly ordered rekey still applies.
        let (mut client, mut server) = active_pair();

        let active_id = server.active_keys().expect("server active key").key_id;
        let ahead_old = active_id.wrapping_add(1);
        let ahead_new = active_id.wrapping_add(2);
        let ratchet_public = [0x42; 32];
        let ahead_rekey = ControlMessage::Rekey {
            old_key_id: ahead_old,
            new_key_id: ahead_new,
            ratchet_public,
            transcript_binding: rekey_binding(
                ahead_old,
                ahead_new,
                &ratchet_public,
                server.session_salt,
            ),
        };

        let err = server
            .handle_control(&ahead_rekey)
            .expect_err("a rekey skipping ahead of the active key must be rejected");
        assert!(matches!(err, CoreError::UnexpectedControlMessage));

        // No key was installed and the ratchet did not advance: the genuine
        // in-order rekey from the peer still lands on both sides.
        assert_eq!(
            server.active_keys().expect("server key").key_id,
            active_id,
            "rejected rekey must not rotate the active key"
        );
        let rekey = client.force_rekey().expect("client force rekey");
        server
            .handle_control(&rekey)
            .expect("in-order rekey still applies after the rejected one");
        assert_eq!(
            client.active_keys().expect("client key"),
            server.active_keys().expect("server key"),
            "both sides must still converge on the same key"
        );
    }

    #[test]
    fn rekey_message_with_forged_transcript_binding_is_rejected() {
        // Even with a correct `old_key_id`, a `Rekey` whose transcript
        // binding doesn't match the recomputed hash (tampered `rekey_salt`,
        // wrong `new_key_id`, or wrong binding outright) must be rejected
        // rather than installing an attacker-influenced key.
        let (mut client, mut server) = active_pair();
        let mut forged_rekey = client.force_rekey().expect("client force rekey");
        if let ControlMessage::Rekey {
            transcript_binding, ..
        } = &mut forged_rekey
        {
            transcript_binding[0] ^= 0xff;
        }
        let err = server
            .handle_control(&forged_rekey)
            .expect_err("tampered rekey transcript binding must be rejected");
        assert!(matches!(err, CoreError::InvalidControlMessage));
    }

    #[test]
    fn control_message_unexpected_for_current_state_is_rejected() {
        // A ClientHello/ServerHello replayed onto an already-Active session
        // (or any control message that doesn't match the (role, state)
        // dispatch table) must be rejected rather than reprocessed as a new
        // handshake, which would let a captured hello desynchronize or
        // downgrade an established session.
        let (mut client, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut server = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let server_hello = server
            .handle_control(&hello)
            .expect("server handle client hello")
            .expect("server hello response");
        client
            .handle_control(&server_hello)
            .expect("client handle server hello");
        assert_eq!(server.state(), SessionState::Active);

        let err = server
            .handle_control(&hello)
            .expect_err("replayed ClientHello onto an active session must be rejected");
        assert!(matches!(err, CoreError::UnexpectedControlMessage));
    }
}
