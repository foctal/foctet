//! Framed Foctet session over WebAssembly.
//!
//! This module exposes the native Foctet handshake and per-message seal/open to
//! JavaScript so a browser (or any JS runtime) can run a full authenticated,
//! ordered, replay-protected Foctet session — not just the one-shot body
//! envelope.
//!
//! # I/O ownership
//!
//! WebAssembly does the cryptography and the handshake state machine; **the JS
//! side owns the transport** (a browser `WebSocket`, `WebTransport` stream, or
//! anything that moves whole messages). Handshake control messages and sealed
//! data frames both cross the boundary as `Uint8Array`; JS is responsible for
//! sending and receiving them in order over its transport. This keeps the WASM
//! surface transport-agnostic and lets it run on platforms whose socket APIs
//! Rust cannot portably bind.
//!
//! # Lifecycle
//!
//! ```text
//! initiator: newInitiator(auth) → initialHandshakeMessage() ──send──▶
//!            ◀──recv── handleHandshakeMessage(serverHello) → (none)
//! responder: newResponder(auth)
//!            ◀──recv── handleHandshakeMessage(clientHello) → serverHello ──send──▶
//! both:      isEstablished() == true → sealMessage()/openMessage()
//! ```
//!
//! Each `sealMessage` produces exactly one frame to send as one transport
//! message; each `openMessage` consumes exactly one. Replay state is committed
//! only after a frame authenticates.
//!
//! # Scope
//!
//! In-session rekey is **not** driven over this message API yet (the control
//! channel is used only for the initial handshake), matching the datagram and
//! native message-shape limitation. Establish a fresh session rather than
//! reusing one indefinitely.

use foctet_core::{
    ControlMessage, CoreError, DecodedMessage, IdentityKeyPair, MessageEndpoint, PeerIdentity,
    RekeyThresholds, Session, SessionAuthConfig, SessionState,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::KEY_LEN;

fn core_to_js(err: CoreError) -> JsError {
    JsError::new(&err.to_string())
}

fn to_key32_js(bytes: &[u8]) -> Result<[u8; KEY_LEN], JsError> {
    <[u8; KEY_LEN]>::try_from(bytes).map_err(|_| JsError::new("expected a 32-byte key"))
}

/// An Ed25519 long-term identity key pair used to authenticate a handshake.
#[wasm_bindgen(js_name = IdentityKeyPair)]
pub struct WasmIdentityKeyPair {
    inner: IdentityKeyPair,
}

#[wasm_bindgen(js_class = IdentityKeyPair)]
impl WasmIdentityKeyPair {
    /// Generates a fresh random identity key pair.
    #[wasm_bindgen(constructor)]
    pub fn generate() -> WasmIdentityKeyPair {
        WasmIdentityKeyPair {
            inner: IdentityKeyPair::generate(),
        }
    }

    /// Reconstructs an identity key pair from 32 secret-key bytes.
    #[wasm_bindgen(js_name = fromSecretKey)]
    pub fn from_secret_key(secret_key: &[u8]) -> Result<WasmIdentityKeyPair, JsError> {
        let bytes = to_key32_js(secret_key)?;
        Ok(WasmIdentityKeyPair {
            inner: IdentityKeyPair::from_secret_key_bytes(bytes),
        })
    }

    /// The 32-byte Ed25519 public identity key (share this with the peer to pin).
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    /// The 32-byte secret identity key. Handle with care.
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.inner.expose_secret_key_bytes().to_vec()
    }
}

enum AuthMode {
    UnauthenticatedForTesting,
    Authenticated {
        local_secret: Zeroizing<[u8; KEY_LEN]>,
        peer_public: [u8; KEY_LEN],
    },
}

/// Handshake authentication policy for a [`FoctetSession`].
///
/// Mirrors the fail-closed native default: prefer [`WasmAuthConfig::authenticated`]
/// with a pinned peer identity for production. [`WasmAuthConfig::unauthenticated_for_testing`]
/// is only for tests or use inside an already-authenticated outer channel.
#[wasm_bindgen(js_name = AuthConfig)]
pub struct WasmAuthConfig {
    mode: AuthMode,
}

#[wasm_bindgen(js_class = AuthConfig)]
impl WasmAuthConfig {
    /// Authenticates the local side with `local_identity` and pins the peer to
    /// `peer_public_key`, requiring the peer to prove that identity.
    pub fn authenticated(
        local_identity: &WasmIdentityKeyPair,
        peer_public_key: &[u8],
    ) -> Result<WasmAuthConfig, JsError> {
        let peer_public = to_key32_js(peer_public_key)?;
        let local_secret = Zeroizing::new(*local_identity.inner.expose_secret_key_bytes());
        Ok(WasmAuthConfig {
            mode: AuthMode::Authenticated {
                local_secret,
                peer_public,
            },
        })
    }

    /// Builds an unauthenticated config. Use only for tests or inside an
    /// already-authenticated outer channel (e.g. mutually authenticated TLS).
    #[wasm_bindgen(js_name = unauthenticatedForTesting)]
    pub fn unauthenticated_for_testing() -> WasmAuthConfig {
        WasmAuthConfig {
            mode: AuthMode::UnauthenticatedForTesting,
        }
    }
}

impl WasmAuthConfig {
    fn build(&self) -> SessionAuthConfig {
        match &self.mode {
            AuthMode::UnauthenticatedForTesting => SessionAuthConfig::unauthenticated_for_testing(),
            AuthMode::Authenticated {
                local_secret,
                peer_public,
            } => SessionAuthConfig::new()
                .with_local_identity(IdentityKeyPair::from_secret_key_bytes(**local_secret))
                .with_peer_identity(PeerIdentity::new(*peer_public))
                .require_peer_authentication(true),
        }
    }
}

/// A decrypted message returned by [`FoctetSession::open_message`].
#[wasm_bindgen(js_name = DecodedMessage)]
pub struct WasmDecodedMessage {
    stream_id: u32,
    flags: u8,
    key_id: u8,
    seq: u64,
    plaintext: Vec<u8>,
}

#[wasm_bindgen(js_class = DecodedMessage)]
impl WasmDecodedMessage {
    /// Logical stream identifier the frame was sealed on.
    #[wasm_bindgen(getter, js_name = streamId)]
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Frame flags bitfield.
    #[wasm_bindgen(getter)]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Traffic-key identifier that opened the frame.
    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// Per-stream sequence number.
    #[wasm_bindgen(getter)]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Decrypted payload bytes.
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }
}

impl From<DecodedMessage> for WasmDecodedMessage {
    fn from(decoded: DecodedMessage) -> Self {
        WasmDecodedMessage {
            stream_id: decoded.header.stream_id,
            flags: decoded.header.flags,
            key_id: decoded.header.key_id,
            seq: decoded.header.seq,
            plaintext: decoded.plaintext,
        }
    }
}

/// A full Foctet session: handshake then ordered, replay-protected messages.
#[wasm_bindgen]
pub struct FoctetSession {
    session: Session,
    endpoint: Option<MessageEndpoint>,
    pending_handshake: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl FoctetSession {
    /// Starts a session as the handshake initiator.
    ///
    /// Call [`Self::initial_handshake_message`] next to obtain the first message
    /// to send to the peer.
    #[wasm_bindgen(js_name = newInitiator)]
    pub fn new_initiator(auth: &WasmAuthConfig) -> FoctetSession {
        FoctetSession::initiator(auth.build())
    }

    /// Starts a session as the handshake responder.
    ///
    /// Feed the initiator's first message to [`Self::handle_handshake_message`].
    #[wasm_bindgen(js_name = newResponder)]
    pub fn new_responder(auth: &WasmAuthConfig) -> FoctetSession {
        FoctetSession::responder(auth.build())
    }

    /// Returns the initiator's first handshake message to send, exactly once.
    ///
    /// Returns `undefined` for a responder or after the message was already taken.
    #[wasm_bindgen(js_name = initialHandshakeMessage)]
    pub fn initial_handshake_message(&mut self) -> Option<Vec<u8>> {
        self.pending_handshake.take()
    }

    /// Feeds a received handshake message, returning an optional reply to send.
    #[wasm_bindgen(js_name = handleHandshakeMessage)]
    pub fn handle_handshake_message(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
        self.handle_handshake_inner(message).map_err(core_to_js)
    }

    /// Whether the handshake has completed and traffic keys are available.
    #[wasm_bindgen(js_name = isEstablished)]
    pub fn is_established(&self) -> bool {
        self.session.state() == SessionState::Active
    }

    /// Whether the peer proved a pinned identity during the handshake.
    #[wasm_bindgen(js_name = peerAuthenticated)]
    pub fn peer_authenticated(&self) -> bool {
        self.session.peer_authenticated()
    }

    /// Seals `plaintext` into one frame to send as a single transport message.
    #[wasm_bindgen(js_name = sealMessage)]
    pub fn seal_message(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.seal_inner(stream_id, flags, plaintext)
            .map_err(core_to_js)
    }

    /// Opens one received transport message into its decrypted payload.
    #[wasm_bindgen(js_name = openMessage)]
    pub fn open_message(&mut self, message: &[u8]) -> Result<WasmDecodedMessage, JsError> {
        self.open_inner(message)
            .map(WasmDecodedMessage::from)
            .map_err(core_to_js)
    }
}

// Inner, native-testable logic (no `JsError`), shared by the wasm wrappers above.
impl FoctetSession {
    fn initiator(auth: SessionAuthConfig) -> Self {
        let (session, hello) = Session::new_initiator_with_auth(RekeyThresholds::default(), auth);
        FoctetSession {
            session,
            endpoint: None,
            pending_handshake: Some(hello.encode()),
        }
    }

    fn responder(auth: SessionAuthConfig) -> Self {
        FoctetSession {
            session: Session::new_responder_with_auth(RekeyThresholds::default(), auth),
            endpoint: None,
            pending_handshake: None,
        }
    }

    fn handle_handshake_inner(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>, CoreError> {
        let control = ControlMessage::decode(message)?;
        let reply = self.session.handle_control(&control)?;
        self.ensure_endpoint();
        Ok(reply.map(|msg| msg.encode()))
    }

    /// Builds the message endpoint once the handshake reaches `Active`.
    fn ensure_endpoint(&mut self) {
        if self.endpoint.is_none()
            && self.session.state() == SessionState::Active
            && let Some(keys) = self.session.active_keys()
        {
            self.endpoint = Some(MessageEndpoint::new(
                keys,
                self.session.inbound_direction(),
                self.session.outbound_direction(),
            ));
        }
    }

    fn seal_inner(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        self.ensure_endpoint();
        self.endpoint
            .as_mut()
            .ok_or(CoreError::InvalidSessionState)?
            .seal(stream_id, flags, plaintext)
    }

    fn open_inner(&mut self, message: &[u8]) -> Result<DecodedMessage, CoreError> {
        self.ensure_endpoint();
        self.endpoint
            .as_mut()
            .ok_or(CoreError::InvalidSessionState)?
            .open(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive_handshake(initiator: &mut FoctetSession, responder: &mut FoctetSession) {
        let client_hello = initiator
            .initial_handshake_message()
            .expect("initiator emits a client hello");
        let server_hello = responder
            .handle_handshake_inner(&client_hello)
            .expect("responder handles client hello")
            .expect("responder replies with a server hello");
        let none = initiator
            .handle_handshake_inner(&server_hello)
            .expect("initiator finalizes");
        assert!(
            none.is_none(),
            "initiator must not reply to the server hello"
        );
    }

    #[test]
    fn unauthenticated_handshake_then_message_roundtrip_and_replay() {
        let mut initiator =
            FoctetSession::initiator(SessionAuthConfig::unauthenticated_for_testing());
        let mut responder =
            FoctetSession::responder(SessionAuthConfig::unauthenticated_for_testing());

        drive_handshake(&mut initiator, &mut responder);
        assert!(initiator.is_established() && responder.is_established());

        let frame = initiator
            .seal_inner(7, 0, b"hello over a wasm session")
            .expect("seal");
        let opened = responder.open_inner(&frame).expect("open");
        assert_eq!(opened.plaintext, b"hello over a wasm session");
        assert_eq!(opened.header.stream_id, 7);

        // A duplicate frame must be rejected as a replay.
        assert!(responder.open_inner(&frame).is_err());

        // Reverse direction works too.
        let back = responder.seal_inner(7, 0, b"reply").expect("seal back");
        assert_eq!(
            initiator.open_inner(&back).expect("open back").plaintext,
            b"reply"
        );
    }

    #[test]
    fn authenticated_handshake_pins_peer_identity() {
        let initiator_id = IdentityKeyPair::generate();
        let responder_id = IdentityKeyPair::generate();

        // Build configs through the WASM-facing builder to exercise `build()`.
        let initiator_auth = WasmAuthConfig::authenticated(
            &WasmIdentityKeyPair {
                inner: IdentityKeyPair::from_secret_key_bytes(
                    *initiator_id.expose_secret_key_bytes(),
                ),
            },
            &responder_id.public_key(),
        )
        .expect("initiator auth");
        let responder_auth = WasmAuthConfig::authenticated(
            &WasmIdentityKeyPair {
                inner: IdentityKeyPair::from_secret_key_bytes(
                    *responder_id.expose_secret_key_bytes(),
                ),
            },
            &initiator_id.public_key(),
        )
        .expect("responder auth");

        let mut initiator = FoctetSession::initiator(initiator_auth.build());
        let mut responder = FoctetSession::responder(responder_auth.build());

        drive_handshake(&mut initiator, &mut responder);
        assert!(initiator.is_established() && responder.is_established());
        assert!(
            initiator.peer_authenticated() && responder.peer_authenticated(),
            "both peers must be authenticated when identities are pinned"
        );

        let frame = initiator
            .seal_inner(0, 0, b"authenticated payload")
            .expect("seal");
        assert_eq!(
            responder.open_inner(&frame).expect("open").plaintext,
            b"authenticated payload"
        );
    }

    #[test]
    fn sealing_before_handshake_fails_closed() {
        let mut initiator =
            FoctetSession::initiator(SessionAuthConfig::unauthenticated_for_testing());
        assert!(
            !initiator.is_established(),
            "session must not be active before the handshake completes"
        );
        assert!(
            initiator.seal_inner(0, 0, b"too early").is_err(),
            "sealing before the session is active must fail"
        );
    }

    #[test]
    fn authenticated_handshake_rejects_unexpected_peer() {
        let initiator_id = IdentityKeyPair::generate();
        let responder_id = IdentityKeyPair::generate();
        let attacker_id = IdentityKeyPair::generate();

        // The initiator pins the attacker's key, but the real responder uses its
        // own identity: the handshake must fail rather than silently accept it.
        let initiator_auth = SessionAuthConfig::new()
            .with_local_identity(IdentityKeyPair::from_secret_key_bytes(
                *initiator_id.expose_secret_key_bytes(),
            ))
            .with_peer_identity(PeerIdentity::new(attacker_id.public_key()))
            .require_peer_authentication(true);
        let responder_auth = SessionAuthConfig::new()
            .with_local_identity(IdentityKeyPair::from_secret_key_bytes(
                *responder_id.expose_secret_key_bytes(),
            ))
            .with_peer_identity(PeerIdentity::new(initiator_id.public_key()))
            .require_peer_authentication(true);

        let mut initiator = FoctetSession::initiator(initiator_auth);
        let mut responder = FoctetSession::responder(responder_auth);

        let client_hello = initiator.initial_handshake_message().expect("client hello");
        let server_hello = responder
            .handle_handshake_inner(&client_hello)
            .expect("responder handles client hello")
            .expect("server hello");
        // The initiator must reject the responder whose identity it did not pin.
        assert!(initiator.handle_handshake_inner(&server_hello).is_err());
    }
}
