//! Framed Foctet session over WebAssembly.
//!
//! This module exposes the native Foctet handshake and framed session API to
//! JavaScript, so a browser or JS runtime can run an authenticated,
//! replay-protected Foctet session instead of only the one-shot body envelope.
//!
//! WebAssembly owns the cryptography and session state; JavaScript owns the
//! transport. Handshake/control messages and sealed payloads cross the boundary
//! as `Uint8Array`.
//!
//! A session is created in one framing mode and stays there:
//!
//! - `newInitiator` / `newResponder` for reliable ordered messages
//! - `newDatagramInitiator` / `newDatagramResponder` for MTU-bounded datagrams
//!
//! Datagram sessions still require a reliable channel for the handshake and
//! rekey control messages. In-session rekey is available through `canRekey`,
//! `prepareRekey`, `commitRekey`, and `handleControlMessage`.

use foctet_core::{
    ChannelBinding, ControlMessage, CoreError, DatagramConfig, DatagramEndpoint, DecodedDatagram,
    DecodedMessage, IdentityKeyPair, MessageEndpoint, PeerIdentity, PreparedRekey, RekeyThresholds,
    Session, SessionAuthConfig, SessionState,
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

#[derive(Clone)]
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
/// with a pinned peer identity for production. [`WasmAuthConfig::bound_to_channel`]
/// substitutes an authenticated outer channel for a Foctet identity, while
/// [`WasmAuthConfig::unauthenticated_for_testing`] is only for tests or use
/// inside an already-authenticated outer channel.
///
/// Any config can additionally carry an outer-channel binding via
/// [`WasmAuthConfig::with_channel_binding`].
#[wasm_bindgen(js_name = AuthConfig)]
pub struct WasmAuthConfig {
    mode: AuthMode,
    channel_binding: Option<Vec<u8>>,
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
            channel_binding: None,
        })
    }

    /// Builds a config whose man-in-the-middle resistance comes from an
    /// authenticated outer channel (e.g. a TLS exporter value) rather than a
    /// Foctet identity.
    ///
    /// Both peers must supply the same `channel_binding`; a relay across a
    /// different outer channel fails closed. This is the production-oriented
    /// alternative to [`WasmAuthConfig::unauthenticated_for_testing`].
    #[wasm_bindgen(js_name = boundToChannel)]
    pub fn bound_to_channel(channel_binding: &[u8]) -> WasmAuthConfig {
        WasmAuthConfig {
            mode: AuthMode::UnauthenticatedForTesting,
            channel_binding: Some(channel_binding.to_vec()),
        }
    }

    /// Builds an unauthenticated config. Use only for tests or inside an
    /// already-authenticated outer channel (e.g. mutually authenticated TLS).
    #[wasm_bindgen(js_name = unauthenticatedForTesting)]
    pub fn unauthenticated_for_testing() -> WasmAuthConfig {
        WasmAuthConfig {
            mode: AuthMode::UnauthenticatedForTesting,
            channel_binding: None,
        }
    }

    /// Returns a copy of this config additionally bound to `channel_binding`.
    ///
    /// Additive to any mode: both peers must supply the same binding or the
    /// handshake fails. An empty binding leaves the transcript unchanged.
    #[wasm_bindgen(js_name = withChannelBinding)]
    pub fn with_channel_binding(&self, channel_binding: &[u8]) -> WasmAuthConfig {
        WasmAuthConfig {
            mode: self.mode.clone(),
            channel_binding: Some(channel_binding.to_vec()),
        }
    }
}

impl WasmAuthConfig {
    fn build(&self) -> SessionAuthConfig {
        let mut config = match &self.mode {
            AuthMode::UnauthenticatedForTesting => SessionAuthConfig::unauthenticated_for_testing(),
            AuthMode::Authenticated {
                local_secret,
                peer_public,
            } => SessionAuthConfig::new()
                .with_local_identity(IdentityKeyPair::from_secret_key_bytes(**local_secret))
                .with_peer_identity(PeerIdentity::new(*peer_public))
                .require_peer_authentication(true),
        };
        if let Some(binding) = &self.channel_binding {
            config = config.with_channel_binding(ChannelBinding::new(binding.clone()));
        }
        config
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

impl From<DecodedDatagram> for WasmDecodedMessage {
    fn from(decoded: DecodedDatagram) -> Self {
        WasmDecodedMessage {
            stream_id: decoded.header.stream_id,
            flags: decoded.header.flags,
            key_id: decoded.header.key_id,
            seq: decoded.header.seq,
            plaintext: decoded.plaintext,
        }
    }
}

/// The data-framing shape a session uses after the handshake. A session commits
/// to exactly one so message and datagram framing can never share a
/// `(key_id, stream_id)` sequence space (which would reuse a nonce).
enum SessionEndpoint {
    Message(MessageEndpoint),
    Datagram(DatagramEndpoint),
}

#[derive(Clone, Copy)]
enum TransportKind {
    /// Reliable, ordered, message-bounded framing (raw WebSocket, WebTransport
    /// stream). Not MTU-capped.
    Message,
    /// MTU-bounded, loss/reorder-tolerant framing (WebTransport datagrams).
    Datagram { max_datagram_size: usize },
}

/// A full Foctet session: an authenticated handshake followed by
/// replay-protected per-message (or per-datagram) seal/open.
///
/// A session is created in one framing mode and stays in it: the `*Message`
/// methods work on a message-mode session (reliable, ordered — raw WebSocket or
/// a WebTransport stream) and the `*Datagram` methods on a datagram-mode session
/// (MTU-bounded, loss-tolerant — WebTransport datagrams). The handshake messages
/// themselves are reliable and must be exchanged over a reliable channel even
/// when data later flows as datagrams.
#[wasm_bindgen]
pub struct FoctetSession {
    session: Session,
    kind: TransportKind,
    endpoint: Option<SessionEndpoint>,
    pending_handshake: Option<Vec<u8>>,
    pending_rekey: Option<PreparedRekey>,
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

    /// Starts a datagram-mode session as the initiator (for WebTransport
    /// datagrams). Exchange the handshake messages over a reliable channel, then
    /// use [`Self::seal_datagram`] / [`Self::open_datagram`] for data.
    ///
    /// `max_datagram_size` caps each sealed datagram; pass `0` for the default
    /// (`foctet_core::DEFAULT_MAX_DATAGRAM_SIZE`).
    #[wasm_bindgen(js_name = newDatagramInitiator)]
    pub fn new_datagram_initiator(
        auth: &WasmAuthConfig,
        max_datagram_size: usize,
    ) -> FoctetSession {
        FoctetSession::initiator_with_kind(auth.build(), datagram_kind(max_datagram_size))
    }

    /// Starts a datagram-mode session as the responder. See
    /// [`Self::new_datagram_initiator`].
    #[wasm_bindgen(js_name = newDatagramResponder)]
    pub fn new_datagram_responder(
        auth: &WasmAuthConfig,
        max_datagram_size: usize,
    ) -> FoctetSession {
        FoctetSession::responder_with_kind(auth.build(), datagram_kind(max_datagram_size))
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

    /// Feeds a received control message (handshake *or* in-session rekey),
    /// returning an optional reply to send. Alias of
    /// [`Self::handle_handshake_message`] with a name that matches its full
    /// role: after the handshake, feed the peer's rekey messages here so this
    /// side rotates to the new traffic keys.
    #[wasm_bindgen(js_name = handleControlMessage)]
    pub fn handle_control_message(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
        self.handle_handshake_inner(message).map_err(core_to_js)
    }

    /// Whether it is this side's turn to initiate the next rekey (the DH
    /// ratchet alternates between peers; the initiator holds the first turn).
    #[wasm_bindgen(js_name = canRekey)]
    pub fn can_rekey(&self) -> bool {
        self.session.can_rekey()
    }

    /// Prepares one DH-ratchet rekey and returns the exact control message to
    /// send over the reliable channel. This side remains on the old key until
    /// [`Self::commit_rekey`] is called after the transport accepts those bytes.
    #[wasm_bindgen(js_name = prepareRekey)]
    pub fn prepare_rekey(&mut self) -> Result<Vec<u8>, JsError> {
        self.prepare_rekey_inner().map_err(core_to_js)
    }

    /// Commits the rekey previously returned by [`Self::prepare_rekey`]. Call
    /// this only after the exact bytes were accepted by the transport. If send
    /// outcome is ambiguous, discard this session instead of committing or
    /// retrying with different bytes.
    #[wasm_bindgen(js_name = commitRekey)]
    pub fn commit_rekey(&mut self) -> Result<(), JsError> {
        self.commit_rekey_inner().map_err(core_to_js)
    }

    /// The identifier of the traffic key currently used for sealing, or
    /// `undefined` before the handshake completes.
    #[wasm_bindgen(getter, js_name = activeKeyId)]
    pub fn active_key_id(&self) -> Option<u8> {
        self.session.active_keys().map(|k| k.key_id)
    }

    /// Whether the handshake has completed and traffic keys are available.
    #[wasm_bindgen(js_name = isEstablished)]
    pub fn is_established(&self) -> bool {
        self.session.state() == SessionState::Active
    }

    /// Whether the message/datagram endpoint is terminal after a protocol
    /// failure. Establish a fresh session instead of reusing it.
    #[wasm_bindgen(js_name = isTerminal)]
    pub fn is_terminal(&self) -> bool {
        if self.session.state() == SessionState::Closed {
            return true;
        }
        match self.endpoint.as_ref() {
            Some(SessionEndpoint::Message(endpoint)) => endpoint.is_terminal(),
            Some(SessionEndpoint::Datagram(endpoint)) => endpoint.is_terminal(),
            None => false,
        }
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
        self.seal_message_inner(stream_id, flags, plaintext)
            .map_err(core_to_js)
    }

    /// Opens one received transport message into its decrypted payload.
    #[wasm_bindgen(js_name = openMessage)]
    pub fn open_message(&mut self, message: &[u8]) -> Result<WasmDecodedMessage, JsError> {
        self.open_message_inner(message)
            .map(WasmDecodedMessage::from)
            .map_err(core_to_js)
    }

    /// Seals `plaintext` into one datagram (datagram-mode sessions only).
    ///
    /// Fails if the sealed datagram would exceed the configured maximum size, or
    /// if this is a message-mode session.
    #[wasm_bindgen(js_name = sealDatagram)]
    pub fn seal_datagram(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.seal_datagram_inner(stream_id, flags, plaintext)
            .map_err(core_to_js)
    }

    /// Opens one received datagram into its decrypted payload (datagram-mode
    /// sessions only).
    #[wasm_bindgen(js_name = openDatagram)]
    pub fn open_datagram(&mut self, datagram: &[u8]) -> Result<WasmDecodedMessage, JsError> {
        self.open_datagram_inner(datagram)
            .map(WasmDecodedMessage::from)
            .map_err(core_to_js)
    }
}

fn datagram_kind(max_datagram_size: usize) -> TransportKind {
    TransportKind::Datagram { max_datagram_size }
}

// Inner, native-testable logic (no `JsError`), shared by the wasm wrappers above.
impl FoctetSession {
    fn initiator(auth: SessionAuthConfig) -> Self {
        Self::initiator_with_kind(auth, TransportKind::Message)
    }

    fn responder(auth: SessionAuthConfig) -> Self {
        Self::responder_with_kind(auth, TransportKind::Message)
    }

    fn initiator_with_kind(auth: SessionAuthConfig, kind: TransportKind) -> Self {
        let (session, hello) = Session::new_initiator_with_auth(RekeyThresholds::default(), auth);
        FoctetSession {
            session,
            kind,
            endpoint: None,
            pending_handshake: Some(hello.encode()),
            pending_rekey: None,
        }
    }

    fn responder_with_kind(auth: SessionAuthConfig, kind: TransportKind) -> Self {
        FoctetSession {
            session: Session::new_responder_with_auth(RekeyThresholds::default(), auth),
            kind,
            endpoint: None,
            pending_handshake: None,
            pending_rekey: None,
        }
    }

    fn handle_handshake_inner(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>, CoreError> {
        let control = ControlMessage::decode(message)?;
        let reply = match self.session.handle_control(&control) {
            Ok(reply) => reply,
            Err(error) => {
                self.pending_rekey = None;
                self.endpoint = None;
                return Err(error);
            }
        };
        self.ensure_endpoint();
        // A rekey control message rotates the session's active key; adopt it
        // on the framing endpoint so subsequent seals use the new key while
        // retained previous keys still open in-flight frames.
        self.sync_endpoint_keys();
        Ok(reply.map(|msg| msg.encode()))
    }

    fn prepare_rekey_inner(&mut self) -> Result<Vec<u8>, CoreError> {
        if self.pending_rekey.is_some() {
            return Err(CoreError::InvalidSessionState);
        }
        let prepared = self.session.prepare_rekey()?;
        let message = prepared.control_message().encode();
        self.pending_rekey = Some(prepared);
        Ok(message)
    }

    fn commit_rekey_inner(&mut self) -> Result<(), CoreError> {
        let prepared = self
            .pending_rekey
            .take()
            .ok_or(CoreError::InvalidSessionState)?;
        self.session.commit_rekey(prepared)?;
        self.sync_endpoint_keys();
        Ok(())
    }

    /// Installs the session's current active key on the framing endpoint
    /// (no-op before the endpoint exists; the endpoint keeps previous key
    /// generations for frames still in flight across the rotation).
    fn sync_endpoint_keys(&mut self) {
        if let (Some(endpoint), Some(keys)) = (self.endpoint.as_mut(), self.session.active_keys()) {
            match endpoint {
                SessionEndpoint::Message(e) => {
                    if e.active_key_id() != keys.key_id {
                        e.install_active_keys(keys);
                    }
                }
                SessionEndpoint::Datagram(e) => {
                    if e.active_key_id() != keys.key_id {
                        e.install_active_keys(keys);
                    }
                }
            }
        }
    }

    /// Builds the framing endpoint (matching the session's mode) once the
    /// handshake reaches `Active`.
    fn ensure_endpoint(&mut self) {
        if self.endpoint.is_none()
            && self.session.state() == SessionState::Active
            && let Some(keys) = self.session.active_keys()
        {
            let inbound = self.session.inbound_direction();
            let outbound = self.session.outbound_direction();
            self.endpoint = Some(match self.kind {
                TransportKind::Message => {
                    SessionEndpoint::Message(MessageEndpoint::new(keys, inbound, outbound))
                }
                TransportKind::Datagram { max_datagram_size } => {
                    let mut config = DatagramConfig::default();
                    if max_datagram_size > 0 {
                        config.max_datagram_size = max_datagram_size;
                    }
                    SessionEndpoint::Datagram(DatagramEndpoint::with_config(
                        keys, inbound, outbound, config,
                    ))
                }
            });
        }
    }

    fn seal_message_inner(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        self.ensure_endpoint();
        match self.endpoint.as_mut() {
            Some(SessionEndpoint::Message(endpoint)) => endpoint.seal(stream_id, flags, plaintext),
            _ => Err(CoreError::InvalidSessionState),
        }
    }

    fn open_message_inner(&mut self, message: &[u8]) -> Result<DecodedMessage, CoreError> {
        self.ensure_endpoint();
        match self.endpoint.as_mut() {
            Some(SessionEndpoint::Message(endpoint)) => endpoint.open(message),
            _ => Err(CoreError::InvalidSessionState),
        }
    }

    fn seal_datagram_inner(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        self.ensure_endpoint();
        match self.endpoint.as_mut() {
            Some(SessionEndpoint::Datagram(endpoint)) => endpoint.seal(stream_id, flags, plaintext),
            _ => Err(CoreError::InvalidSessionState),
        }
    }

    fn open_datagram_inner(&mut self, datagram: &[u8]) -> Result<DecodedDatagram, CoreError> {
        self.ensure_endpoint();
        match self.endpoint.as_mut() {
            Some(SessionEndpoint::Datagram(endpoint)) => endpoint.open(datagram),
            _ => Err(CoreError::InvalidSessionState),
        }
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
            .seal_message_inner(7, 0, b"hello over a wasm session")
            .expect("seal");
        let opened = responder.open_message_inner(&frame).expect("open");
        assert_eq!(opened.plaintext, b"hello over a wasm session");
        assert_eq!(opened.header.stream_id, 7);

        // A duplicate frame must be rejected as a replay.
        assert!(responder.open_message_inner(&frame).is_err());
        assert!(responder.is_terminal());
        assert!(responder.seal_message_inner(7, 0, b"reply").is_err());
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
            .seal_message_inner(0, 0, b"authenticated payload")
            .expect("seal");
        assert_eq!(
            responder
                .open_message_inner(&frame)
                .expect("open")
                .plaintext,
            b"authenticated payload"
        );
    }

    #[test]
    fn channel_bound_auth_config_completes_handshake() {
        // No Foctet identity: MITM resistance comes from a shared channel binding.
        let binding = b"tls-exporter:wasm-channel".to_vec();
        let initiator_auth = WasmAuthConfig::bound_to_channel(&binding);
        let responder_auth = WasmAuthConfig::bound_to_channel(&binding);

        let mut initiator = FoctetSession::initiator(initiator_auth.build());
        let mut responder = FoctetSession::responder(responder_auth.build());

        drive_handshake(&mut initiator, &mut responder);
        assert!(initiator.is_established() && responder.is_established());

        let frame = initiator.seal_message_inner(0, 0, b"hi").expect("seal");
        assert_eq!(
            responder
                .open_message_inner(&frame)
                .expect("open")
                .plaintext,
            b"hi"
        );
    }

    #[test]
    fn mismatched_channel_binding_fails_wasm_handshake() {
        let initiator_auth = WasmAuthConfig::bound_to_channel(b"channel-A");
        let responder_auth = WasmAuthConfig::bound_to_channel(b"channel-B");
        let mut initiator = FoctetSession::initiator(initiator_auth.build());
        let mut responder = FoctetSession::responder(responder_auth.build());

        let client_hello = initiator.initial_handshake_message().expect("client hello");
        assert!(responder.handle_handshake_inner(&client_hello).is_err());
    }

    #[test]
    fn with_channel_binding_strengthens_authenticated_config() {
        // Identity auth plus a channel binding: both must match.
        let client_id = IdentityKeyPair::generate();
        let server_id = IdentityKeyPair::generate();
        let binding = b"bound".to_vec();

        let client_auth = WasmAuthConfig::authenticated(
            &WasmIdentityKeyPair {
                inner: IdentityKeyPair::from_secret_key_bytes(*client_id.expose_secret_key_bytes()),
            },
            &server_id.public_key(),
        )
        .expect("client auth")
        .with_channel_binding(&binding);
        let server_auth = WasmAuthConfig::authenticated(
            &WasmIdentityKeyPair {
                inner: IdentityKeyPair::from_secret_key_bytes(*server_id.expose_secret_key_bytes()),
            },
            &client_id.public_key(),
        )
        .expect("server auth")
        .with_channel_binding(&binding);

        let mut initiator = FoctetSession::initiator(client_auth.build());
        let mut responder = FoctetSession::responder(server_auth.build());
        drive_handshake(&mut initiator, &mut responder);
        assert!(initiator.peer_authenticated() && responder.peer_authenticated());
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
            initiator.seal_message_inner(0, 0, b"too early").is_err(),
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
        assert!(initiator.is_terminal());
    }

    #[test]
    fn in_session_rekey_rotates_keys_and_traffic_continues() {
        let mut initiator =
            FoctetSession::initiator(SessionAuthConfig::unauthenticated_for_testing());
        let mut responder =
            FoctetSession::responder(SessionAuthConfig::unauthenticated_for_testing());
        drive_handshake(&mut initiator, &mut responder);

        let key_before = initiator.session.active_keys().expect("key").key_id;

        // The initiator holds the first ratchet turn; the responder does not.
        assert!(initiator.session.can_rekey());
        assert!(!responder.session.can_rekey());
        assert!(responder.prepare_rekey_inner().is_err());

        // A frame sealed under the old key, delivered after the rekey below,
        // must still open (previous key generations are retained).
        let old_key_frame = initiator
            .seal_message_inner(1, 0, b"sealed before rekey")
            .expect("seal under old key");

        let rekey = initiator
            .prepare_rekey_inner()
            .expect("initiator prepares rekey");
        assert!(initiator.session.can_rekey(), "prepare must not rotate yet");
        initiator
            .commit_rekey_inner()
            .expect("initiator commits rekey");
        assert!(
            !initiator.session.can_rekey(),
            "after rekeying, the turn passes to the peer"
        );
        responder
            .handle_handshake_inner(&rekey)
            .expect("responder applies rekey");
        assert!(responder.session.can_rekey(), "turn handed to responder");

        let key_after = initiator.session.active_keys().expect("key").key_id;
        assert_eq!(key_after, key_before + 1, "active key must rotate");

        // Traffic continues under the new key in both directions.
        let frame = initiator
            .seal_message_inner(1, 0, b"after rekey")
            .expect("seal under new key");
        let opened = responder.open_message_inner(&frame).expect("open");
        assert_eq!(opened.plaintext, b"after rekey");
        assert_eq!(opened.header.key_id, key_after);

        let back = responder.seal_message_inner(1, 0, b"reply").expect("seal");
        assert_eq!(
            initiator.open_message_inner(&back).expect("open").plaintext,
            b"reply"
        );

        // The pre-rekey frame still opens under the retained previous key.
        assert_eq!(
            responder
                .open_message_inner(&old_key_frame)
                .expect("old-key frame still opens")
                .plaintext,
            b"sealed before rekey"
        );

        // And the responder can now take its turn.
        let rekey_back = responder
            .prepare_rekey_inner()
            .expect("responder prepares rekey");
        responder
            .commit_rekey_inner()
            .expect("responder commits rekey");
        initiator
            .handle_handshake_inner(&rekey_back)
            .expect("initiator applies the responder's rekey");
        assert_eq!(
            initiator.session.active_keys().expect("key").key_id,
            key_after + 1
        );
        let frame = initiator
            .seal_message_inner(1, 0, b"third key")
            .expect("seal");
        assert_eq!(
            responder
                .open_message_inner(&frame)
                .expect("open")
                .plaintext,
            b"third key"
        );
    }

    #[test]
    fn in_session_rekey_works_in_datagram_mode() {
        let mut initiator = FoctetSession::initiator_with_kind(
            SessionAuthConfig::unauthenticated_for_testing(),
            TransportKind::Datagram {
                max_datagram_size: 0,
            },
        );
        let mut responder = FoctetSession::responder_with_kind(
            SessionAuthConfig::unauthenticated_for_testing(),
            TransportKind::Datagram {
                max_datagram_size: 0,
            },
        );
        drive_handshake(&mut initiator, &mut responder);

        // Seal a datagram under the old key, deliver it *after* the rekey —
        // the loss/reorder-tolerant shape must still open it.
        let old_key_datagram = initiator
            .seal_datagram_inner(2, 0, b"reordered across rekey")
            .expect("seal under old key");

        // The rekey control message itself travels over the reliable channel.
        let rekey = initiator
            .prepare_rekey_inner()
            .expect("initiator prepares rekey");
        initiator
            .commit_rekey_inner()
            .expect("initiator commits rekey");
        responder
            .handle_handshake_inner(&rekey)
            .expect("responder applies rekey");

        let fresh = initiator
            .seal_datagram_inner(2, 0, b"after rekey")
            .expect("seal under new key");
        assert_eq!(
            responder
                .open_datagram_inner(&fresh)
                .expect("open new-key datagram")
                .plaintext,
            b"after rekey"
        );
        assert_eq!(
            responder
                .open_datagram_inner(&old_key_datagram)
                .expect("open reordered old-key datagram")
                .plaintext,
            b"reordered across rekey"
        );
    }

    #[test]
    fn datagram_mode_handshake_then_datagram_roundtrip_and_replay() {
        let mut initiator = FoctetSession::initiator_with_kind(
            SessionAuthConfig::unauthenticated_for_testing(),
            TransportKind::Datagram {
                max_datagram_size: 0,
            },
        );
        let mut responder = FoctetSession::responder_with_kind(
            SessionAuthConfig::unauthenticated_for_testing(),
            TransportKind::Datagram {
                max_datagram_size: 0,
            },
        );

        drive_handshake(&mut initiator, &mut responder);
        assert!(initiator.is_established() && responder.is_established());

        let datagram = initiator
            .seal_datagram_inner(3, 0, b"hello over a wasm datagram")
            .expect("seal datagram");
        let opened = responder
            .open_datagram_inner(&datagram)
            .expect("open datagram");
        assert_eq!(opened.plaintext, b"hello over a wasm datagram");
        assert_eq!(opened.header.stream_id, 3);

        // A duplicate datagram must be rejected as a replay.
        assert!(responder.open_datagram_inner(&datagram).is_err());

        // Message-framing methods must fail on a datagram-mode session.
        assert!(initiator.seal_message_inner(3, 0, b"wrong shape").is_err());
    }
}
