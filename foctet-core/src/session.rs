use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    CoreError,
    auth::{AuthenticatedPeer, HandshakeAuth, SessionAuthConfig},
    control::ControlMessage,
    crypto::{
        Direction, EphemeralKeyPair, KeyHandle, TrafficKeys, derive_rekey_traffic_keys,
        derive_traffic_keys, random_session_salt,
    },
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
    shared_secret: Option<[u8; 32]>,
    session_salt: [u8; 32],
    active_keys: Option<KeyHandle>,
    previous_keys: Vec<KeyHandle>,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    peer_authenticated: bool,
    authenticated_peer_key: Option<[u8; 32]>,
    outbound_frames: u64,
    outbound_bytes: u64,
    last_rekey_at: Instant,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(shared) = &mut self.shared_secret {
            shared.zeroize();
        }
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
                shared_secret: None,
                session_salt,
                active_keys: None,
                previous_keys: Vec::new(),
                thresholds,
                auth,
                peer_authenticated: false,
                authenticated_peer_key: None,
                outbound_frames: 0,
                outbound_bytes: 0,
                last_rekey_at: Instant::now(),
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
            shared_secret: None,
            session_salt: [0u8; 32],
            active_keys: None,
            previous_keys: Vec::new(),
            thresholds,
            auth,
            peer_authenticated: false,
            authenticated_peer_key: None,
            outbound_frames: 0,
            outbound_bytes: 0,
            last_rekey_at: Instant::now(),
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

    /// Applies an incoming control message and optionally returns a response.
    pub fn handle_control(
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
                let shared = self.local_eph.shared_secret(*eph_public)?;
                let keys = derive_traffic_keys(&shared, &self.session_salt, 0)?;

                self.shared_secret = Some(shared);
                self.active_keys = Some(KeyHandle::new(keys));
                self.state = SessionState::Active;
                self.peer_authenticated = authenticated_peer.is_some();
                self.authenticated_peer_key = authenticated_peer;
                self.last_rekey_at = Instant::now();

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
                let shared = self.local_eph.shared_secret(*eph_public)?;
                let keys = derive_traffic_keys(&shared, &self.session_salt, 0)?;

                self.shared_secret = Some(shared);
                self.active_keys = Some(KeyHandle::new(keys));
                self.state = SessionState::Active;
                self.peer_authenticated = authenticated_peer.is_some();
                self.authenticated_peer_key = authenticated_peer;
                self.last_rekey_at = Instant::now();
                Ok(None)
            }
            (
                _,
                SessionState::Active,
                ControlMessage::Rekey {
                    old_key_id,
                    new_key_id,
                    rekey_salt,
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

                let expected =
                    rekey_binding(*old_key_id, *new_key_id, *rekey_salt, self.session_salt);
                if transcript_binding != &expected {
                    return Err(CoreError::InvalidControlMessage);
                }

                let shared = self.shared_secret.ok_or(CoreError::MissingSessionSecret)?;
                let next = derive_rekey_traffic_keys(
                    &shared,
                    &self.session_salt,
                    rekey_salt,
                    *new_key_id,
                )?;
                self.install_new_active_key(next);
                self.last_rekey_at = Instant::now();
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
    pub fn on_outbound_payload(
        &mut self,
        plaintext_len: usize,
    ) -> Result<Option<ControlMessage>, CoreError> {
        if self.state != SessionState::Active {
            return Err(CoreError::InvalidSessionState);
        }

        self.outbound_frames = self.outbound_frames.saturating_add(1);
        self.outbound_bytes = self.outbound_bytes.saturating_add(plaintext_len as u64);

        if self.should_rekey() {
            let msg = self.force_rekey()?;
            return Ok(Some(msg));
        }

        Ok(None)
    }

    /// Forces immediate rekey and returns the `Rekey` control message.
    pub fn force_rekey(&mut self) -> Result<ControlMessage, CoreError> {
        if self.state != SessionState::Active {
            return Err(CoreError::InvalidSessionState);
        }

        let active = self
            .active_keys
            .clone()
            .ok_or(CoreError::InvalidSessionState)?;
        let old_key_id = active.key_id;
        let new_key_id = old_key_id.checked_add(1).ok_or(CoreError::KeyIdExhausted)?;

        let mut rekey_salt = [0u8; 32];
        OsRng.fill_bytes(&mut rekey_salt);

        let shared = self.shared_secret.ok_or(CoreError::MissingSessionSecret)?;
        let next = derive_rekey_traffic_keys(&shared, &self.session_salt, &rekey_salt, new_key_id)?;
        self.install_new_active_key(next);

        self.outbound_frames = 0;
        self.outbound_bytes = 0;
        self.last_rekey_at = Instant::now();

        let transcript_binding =
            rekey_binding(old_key_id, new_key_id, rekey_salt, self.session_salt);
        Ok(ControlMessage::Rekey {
            old_key_id,
            new_key_id,
            rekey_salt,
            transcript_binding,
        })
    }

    fn should_rekey(&self) -> bool {
        self.outbound_frames >= self.thresholds.max_frames
            || self.outbound_bytes >= self.thresholds.max_bytes
            || self.last_rekey_at.elapsed() >= self.thresholds.max_age
    }

    fn install_new_active_key(&mut self, next: TrafficKeys) {
        if let Some(current) = self.active_keys.take() {
            self.previous_keys.insert(0, current);
            if self.previous_keys.len() > self.thresholds.max_previous_keys {
                self.previous_keys
                    .truncate(self.thresholds.max_previous_keys);
            }
        }
        self.active_keys = Some(KeyHandle::new(next));
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
    rekey_salt: [u8; 32],
    session_salt: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"foctet rekey");
    hasher.update([old_key_id]);
    hasher.update([new_key_id]);
    hasher.update(rekey_salt);
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
    fn rekey_message_with_stale_old_key_id_is_rejected() {
        // A rekey collision/out-of-order scenario: the responder is still on
        // key 0, but receives a `Rekey` claiming to rotate away from a key it
        // never activated. It must reject this instead of silently
        // installing a derived key the two sides disagree about.
        let (_client, mut server) = active_pair();
        let forged_rekey = ControlMessage::Rekey {
            old_key_id: 99,
            new_key_id: 100,
            rekey_salt: [0x42; 32],
            transcript_binding: [0u8; 32],
        };
        let err = server
            .handle_control(&forged_rekey)
            .expect_err("rekey from an unrecognized old_key_id must be rejected");
        assert!(matches!(err, CoreError::UnexpectedControlMessage));
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
