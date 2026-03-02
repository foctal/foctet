use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    CoreError,
    control::ControlMessage,
    crypto::{
        Direction, EphemeralKeyPair, TrafficKeys, derive_rekey_traffic_keys, derive_traffic_keys,
        random_session_salt,
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
    active_keys: Option<TrafficKeys>,
    previous_keys: Vec<TrafficKeys>,
    thresholds: RekeyThresholds,
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
        let local_eph = EphemeralKeyPair::generate();
        let session_salt = random_session_salt();
        let binding = client_hello_binding(local_eph.public, session_salt);

        let msg = ControlMessage::ClientHello {
            eph_public: local_eph.public,
            session_salt,
            transcript_binding: binding,
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
                outbound_frames: 0,
                outbound_bytes: 0,
                last_rekey_at: Instant::now(),
            },
            msg,
        )
    }

    /// Creates a responder session waiting for a peer `ClientHello`.
    pub fn new_responder(thresholds: RekeyThresholds) -> Self {
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
                },
            ) => {
                let expected = client_hello_binding(*eph_public, *session_salt);
                if transcript_binding != &expected {
                    return Err(CoreError::InvalidControlMessage);
                }

                self.peer_eph_public = Some(*eph_public);
                self.session_salt = *session_salt;
                let shared = self.local_eph.shared_secret(*eph_public);
                let keys = derive_traffic_keys(&shared, &self.session_salt, 0)?;

                self.shared_secret = Some(shared);
                self.active_keys = Some(keys);
                self.state = SessionState::Active;
                self.last_rekey_at = Instant::now();

                let server_binding =
                    server_hello_binding(*eph_public, self.local_eph.public, self.session_salt);
                Ok(Some(ControlMessage::ServerHello {
                    eph_public: self.local_eph.public,
                    transcript_binding: server_binding,
                }))
            }
            (
                HandshakeRole::Initiator,
                SessionState::WaitingPeerHello,
                ControlMessage::ServerHello {
                    eph_public,
                    transcript_binding,
                },
            ) => {
                let expected =
                    server_hello_binding(self.local_eph.public, *eph_public, self.session_salt);
                if transcript_binding != &expected {
                    return Err(CoreError::InvalidControlMessage);
                }

                self.peer_eph_public = Some(*eph_public);
                let shared = self.local_eph.shared_secret(*eph_public);
                let keys = derive_traffic_keys(&shared, &self.session_salt, 0)?;

                self.shared_secret = Some(shared);
                self.active_keys = Some(keys);
                self.state = SessionState::Active;
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

    /// Returns the currently active traffic keys, if session is active.
    pub fn active_keys(&self) -> Option<TrafficKeys> {
        self.active_keys.clone()
    }

    /// Returns active key followed by retained previous keys.
    pub fn active_and_previous_keys(&self) -> Option<Vec<TrafficKeys>> {
        let mut out = Vec::new();
        let active = self.active_keys.clone()?;
        out.push(active);
        out.extend(self.previous_keys.iter().cloned());
        Some(out)
    }

    /// Returns current key ring as transport-ready list.
    pub fn key_ring(&self) -> Result<Vec<TrafficKeys>, CoreError> {
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
        let new_key_id = old_key_id.wrapping_add(1);

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
        self.active_keys = Some(next);
    }
}

fn client_hello_binding(client_public: [u8; 32], session_salt: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"foctet hs client");
    hasher.update(client_public);
    hasher.update(session_salt);
    hasher.finalize().into()
}

fn server_hello_binding(
    client_public: [u8; 32],
    server_public: [u8; 32],
    session_salt: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"foctet hs server");
    hasher.update(client_public);
    hasher.update(server_public);
    hasher.update(session_salt);
    hasher.finalize().into()
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

    #[test]
    fn session_handshake_and_rekey() {
        let (mut client, hello) = Session::new_initiator(RekeyThresholds::default());
        let mut server = Session::new_responder(RekeyThresholds::default());

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
}
