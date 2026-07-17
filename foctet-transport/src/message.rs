//! Generic, backend-agnostic message transport abstraction.
//!
//! [`MessageTransport`] is the message counterpart to [`crate::DatagramTransport`]
//! and the byte-stream builders in this crate. It moves whole, reliable,
//! ordered, message-bounded units — most importantly **raw WebSocket messages**,
//! where each message is a discrete frame and the application wants to keep those
//! boundaries instead of treating the connection as an opaque byte stream.
//!
//! [`SecureMessageChannel`] layers Foctet's [`MessageEndpoint`] on top of any
//! `MessageTransport`, so a single secure-message implementation works over raw
//! WebSocket, an in-process message queue, or any other discrete-message backend
//! that implements the trait.
//!
//! Each `send` seals exactly one Foctet frame into one message; each `recv`
//! opens exactly one. Because the transport is reliable and ordered, the default
//! maximum message size is large (see [`foctet_core::DEFAULT_MAX_MESSAGE_SIZE`]),
//! unlike the MTU-bounded datagram shape. Replay state is committed only after
//! AEAD authentication, so a forged message cannot advance the window.

use foctet_core::{
    ControlMessage, CoreError, DecodedMessage, KeyHandle, MessageConfig, MessageEndpoint, Session,
    frame::flags,
};
use thiserror::Error;

use crate::error::TransportErrorDisposition;

/// A message-oriented transport that sends and receives whole, discrete messages.
///
/// The futures intentionally do **not** require `Send`, so the trait is usable
/// from `!Send` runtimes such as browser WebSocket bindings. Implementations
/// must preserve message boundaries: the bytes passed to one `send_message`
/// arrive as exactly one `recv_message` on the peer.
#[allow(async_fn_in_trait)]
pub trait MessageTransport {
    /// Transport-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Sends one message.
    async fn send_message(&self, message: Vec<u8>) -> Result<(), Self::Error>;

    /// Receives one message.
    async fn recv_message(&self) -> Result<Vec<u8>, Self::Error>;

    /// Returns the maximum message payload size the transport accepts, if known.
    fn max_message_size(&self) -> Option<usize>;
}

/// Error returned by [`SecureMessageChannel`] operations.
#[derive(Debug, Error)]
pub enum MessageChannelError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Foctet message seal/open failed.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// The underlying message transport failed.
    #[error("message transport error: {0}")]
    Transport(E),
}

impl<E> MessageChannelError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Classifies whether this channel may safely continue after the error.
    pub const fn disposition(&self) -> TransportErrorDisposition {
        match self {
            Self::Transport(_) => TransportErrorDisposition::Terminal,
            Self::Core(error) => match error.disposition() {
                foctet_core::CoreErrorDisposition::Recoverable => {
                    TransportErrorDisposition::Recoverable
                }
                foctet_core::CoreErrorDisposition::Terminal => TransportErrorDisposition::Terminal,
            },
        }
    }
}

/// A secure Foctet message channel over any [`MessageTransport`].
///
/// Negotiate keys with a normal Foctet handshake (for example over a control
/// stream) first, then build this channel from the resulting [`Session`].
#[derive(Debug)]
pub struct SecureMessageChannel<T> {
    transport: T,
    endpoint: MessageEndpoint,
    terminal: bool,
}

impl<T> SecureMessageChannel<T>
where
    T: MessageTransport,
{
    /// Builds a channel from a transport and an active [`Session`], clamping the
    /// message size to the transport's reported maximum when available.
    pub fn from_active_session(transport: T, session: &Session) -> Result<Self, CoreError> {
        let mut config = MessageConfig::default();
        if let Some(max) = transport.max_message_size() {
            config.max_message_size = config.max_message_size.min(max);
        }
        Self::from_active_session_with_config(transport, session, config)
    }

    /// Builds a channel from a transport, an active [`Session`], and an explicit
    /// message configuration.
    pub fn from_active_session_with_config(
        transport: T,
        session: &Session,
        config: MessageConfig,
    ) -> Result<Self, CoreError> {
        let keys = session
            .active_keys()
            .ok_or(CoreError::InvalidSessionState)?;
        let endpoint = MessageEndpoint::with_config(
            keys,
            session.inbound_direction(),
            session.outbound_direction(),
            config,
        );
        Ok(Self {
            transport,
            endpoint,
            terminal: false,
        })
    }

    /// Returns the maximum plaintext bytes that fit in one message.
    pub fn max_plaintext_len(&self) -> usize {
        self.endpoint.max_plaintext_len()
    }

    /// Returns whether a terminal protocol or transport error closed this
    /// channel. A terminal channel must be discarded with its session.
    pub fn is_terminal(&self) -> bool {
        self.terminal || self.endpoint.is_terminal()
    }

    /// Installs a freshly rotated set of traffic keys (after a rekey).
    pub fn install_active_keys(&mut self, keys: KeyHandle) {
        self.endpoint.install_active_keys(keys);
    }

    /// Adopts the session's current active traffic keys after it has rekeyed.
    ///
    /// Drive the DH-ratchet rekey on the [`Session`] (over a reliable control
    /// channel), then call this on both peers to install the rotated key. The
    /// previous key is retained, so a message sealed under the old key that is
    /// still in flight opens correctly.
    pub fn rekey_from_session(&mut self, session: &Session) -> Result<(), CoreError> {
        if self.is_terminal() {
            return Err(CoreError::TransportTerminal);
        }
        let keys = session
            .active_keys()
            .ok_or(CoreError::InvalidSessionState)?;
        self.endpoint.install_active_keys(keys);
        Ok(())
    }

    /// Returns a reference to the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Seals `plaintext` into one frame and sends it as a single message.
    pub async fn send_message(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<(), MessageChannelError<T::Error>> {
        if self.is_terminal() {
            return Err(MessageChannelError::Core(CoreError::TransportTerminal));
        }
        let bytes = match self.endpoint.seal(stream_id, flags, plaintext) {
            Ok(bytes) => bytes,
            Err(error) => {
                if error.disposition() == foctet_core::CoreErrorDisposition::Terminal {
                    self.terminal = true;
                }
                return Err(MessageChannelError::Core(error));
            }
        };
        match self.transport.send_message(bytes).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.terminal = true;
                Err(MessageChannelError::Transport(error))
            }
        }
    }

    /// Prepares, sends, and commits one rekey over this reliable channel.
    ///
    /// The control message is sealed under the old traffic key. A backend
    /// failure is ambiguous and closes both this channel and `session`; a seal
    /// rejection before transport delivery cancels the prepared transaction.
    pub async fn send_rekey(
        &mut self,
        session: &mut Session,
    ) -> Result<(), MessageChannelError<T::Error>> {
        if self.is_terminal() {
            return Err(MessageChannelError::Core(CoreError::TransportTerminal));
        }
        let prepared = session.prepare_rekey()?;
        let bytes =
            match self
                .endpoint
                .seal(0, flags::IS_CONTROL, &prepared.control_message().encode())
            {
                Ok(bytes) => bytes,
                Err(error) => {
                    if self.endpoint.is_terminal() {
                        self.terminal = true;
                        session.terminate();
                    } else if let Err(cancel_error) = session.cancel_prepared_rekey(prepared) {
                        self.terminal = true;
                        return Err(MessageChannelError::Core(cancel_error));
                    }
                    return Err(MessageChannelError::Core(error));
                }
            };
        if let Err(error) = self.transport.send_message(bytes).await {
            self.terminal = true;
            session.terminate();
            return Err(MessageChannelError::Transport(error));
        }
        if let Err(error) = session.commit_rekey(prepared) {
            self.terminal = true;
            session.terminate();
            return Err(MessageChannelError::Core(error));
        }
        let keys = match session.active_keys() {
            Some(keys) => keys,
            None => {
                self.terminal = true;
                session.terminate();
                return Err(MessageChannelError::Core(CoreError::InvalidSessionState));
            }
        };
        self.endpoint.install_active_keys(keys);
        Ok(())
    }

    /// Receives one message and opens it into a decrypted payload.
    pub async fn recv_message(&mut self) -> Result<DecodedMessage, MessageChannelError<T::Error>> {
        if self.is_terminal() {
            return Err(MessageChannelError::Core(CoreError::TransportTerminal));
        }
        let bytes = match self.transport.recv_message().await {
            Ok(bytes) => bytes,
            Err(error) => {
                self.terminal = true;
                return Err(MessageChannelError::Transport(error));
            }
        };
        match self.endpoint.open(&bytes) {
            Ok(message) => Ok(message),
            Err(error) => {
                if error.disposition() == foctet_core::CoreErrorDisposition::Terminal {
                    self.terminal = true;
                }
                Err(MessageChannelError::Core(error))
            }
        }
    }

    /// Receives and applies one rekey from this reliable control channel.
    pub async fn recv_rekey(
        &mut self,
        session: &mut Session,
    ) -> Result<(), MessageChannelError<T::Error>> {
        let decoded = match self.recv_message().await {
            Ok(decoded) => decoded,
            Err(error) => {
                session.terminate();
                return Err(error);
            }
        };
        if decoded.header.flags & flags::IS_CONTROL == 0 {
            self.terminal = true;
            session.terminate();
            return Err(MessageChannelError::Core(
                CoreError::UnexpectedControlMessage,
            ));
        }
        let control = match ControlMessage::decode(&decoded.plaintext) {
            Ok(control @ ControlMessage::Rekey { .. }) => control,
            Ok(_) | Err(_) => {
                self.terminal = true;
                session.terminate();
                return Err(MessageChannelError::Core(
                    CoreError::UnexpectedControlMessage,
                ));
            }
        };
        if let Err(error) = session.handle_control(&control) {
            self.terminal = true;
            return Err(MessageChannelError::Core(error));
        }
        let keys = match session.active_keys() {
            Some(keys) => keys,
            None => {
                self.terminal = true;
                session.terminate();
                return Err(MessageChannelError::Core(CoreError::InvalidSessionState));
            }
        };
        self.endpoint.install_active_keys(keys);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use foctet_core::{
        Direction, EphemeralKeyPair, KeyHandle, RekeyThresholds, Session, SessionAuthConfig,
        derive_traffic_keys, random_session_salt,
    };

    /// In-memory, reliable, ordered message transport for one direction.
    #[derive(Default)]
    struct MemoryMessageTransport {
        // Messages this side will read (its inbox) and write (peer's inbox).
        inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
        outbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("memory message transport closed")]
    struct MemoryError;

    impl MessageTransport for MemoryMessageTransport {
        type Error = MemoryError;

        async fn send_message(&self, message: Vec<u8>) -> Result<(), Self::Error> {
            self.outbox.borrow_mut().push_back(message);
            Ok(())
        }

        async fn recv_message(&self) -> Result<Vec<u8>, Self::Error> {
            self.inbox.borrow_mut().pop_front().ok_or(MemoryError)
        }

        fn max_message_size(&self) -> Option<usize> {
            None
        }
    }

    fn linked_pair() -> (MemoryMessageTransport, MemoryMessageTransport) {
        let a_to_b: Rc<RefCell<VecDeque<Vec<u8>>>> = Rc::default();
        let b_to_a: Rc<RefCell<VecDeque<Vec<u8>>>> = Rc::default();
        let client = MemoryMessageTransport {
            inbox: b_to_a.clone(),
            outbox: a_to_b.clone(),
        };
        let server = MemoryMessageTransport {
            inbox: a_to_b,
            outbox: b_to_a,
        };
        (client, server)
    }

    fn shared_session_keys() -> (Session, Session) {
        // Drive a real native handshake so both sides share traffic keys and the
        // channel exercises `from_active_session`.
        let (mut initiator, client_hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut responder = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let server_hello = responder
            .handle_control(&client_hello)
            .expect("responder handles client hello")
            .expect("responder returns a server hello");
        let none = initiator
            .handle_control(&server_hello)
            .expect("initiator finalizes");
        assert!(none.is_none(), "initiator must not reply to server hello");
        (initiator, responder)
    }

    #[tokio::test]
    async fn secure_message_channel_roundtrip_and_replay() {
        let (initiator, responder) = shared_session_keys();
        let (client_io, server_io) = linked_pair();

        let mut client = SecureMessageChannel::from_active_session(client_io, &initiator)
            .expect("client channel");
        let mut server = SecureMessageChannel::from_active_session(server_io, &responder)
            .expect("server channel");

        client
            .send_message(0, 0, b"hello over messages")
            .await
            .expect("send");

        // Capture the on-wire bytes before the server consumes them, so we can
        // re-deliver the exact same message afterwards.
        let on_wire = server
            .transport()
            .inbox
            .borrow()
            .front()
            .expect("one message queued")
            .clone();

        let opened = server.recv_message().await.expect("recv");
        assert_eq!(opened.plaintext, b"hello over messages");

        // Re-deliver the same bytes: a duplicate must be rejected as a replay.
        server.transport().inbox.borrow_mut().push_back(on_wire);
        let err = server
            .recv_message()
            .await
            .expect_err("duplicate must be replay-rejected");
        assert!(matches!(err, MessageChannelError::Core(CoreError::Replay)));
        assert!(server.is_terminal());
        assert!(matches!(
            server
                .send_message(0, 0, b"must not send after replay")
                .await,
            Err(MessageChannelError::Core(CoreError::TransportTerminal))
        ));
    }

    #[tokio::test]
    async fn secure_message_channel_after_key_rotation() {
        // Build channels directly from raw keys so we can rotate them in lockstep.
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let ss = a.shared_secret(b.public).expect("shared secret");
        let salt = random_session_salt();
        let k1 = KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("keys gen 1"));
        let k2 = KeyHandle::new(derive_traffic_keys(&ss, &salt, 2).expect("keys gen 2"));

        let (client_io, server_io) = linked_pair();
        let mut client = SecureMessageChannel {
            transport: client_io,
            endpoint: MessageEndpoint::new(k1.clone(), Direction::S2C, Direction::C2S),
            terminal: false,
        };
        let mut server = SecureMessageChannel {
            transport: server_io,
            endpoint: MessageEndpoint::new(k1, Direction::C2S, Direction::S2C),
            terminal: false,
        };

        client.send_message(0, 0, b"before").await.expect("send 1");
        assert_eq!(
            server.recv_message().await.expect("recv 1").plaintext,
            b"before"
        );

        client.install_active_keys(k2.clone());
        server.install_active_keys(k2);

        client.send_message(0, 0, b"after").await.expect("send 2");
        let opened = server.recv_message().await.expect("recv 2");
        assert_eq!(opened.plaintext, b"after");
        assert_eq!(opened.header.key_id, 2);
    }

    #[tokio::test]
    async fn transport_error_makes_message_channel_terminal() {
        let (initiator, _responder) = shared_session_keys();
        let (transport, _peer) = linked_pair();
        let mut channel =
            SecureMessageChannel::from_active_session(transport, &initiator).expect("channel");

        assert!(matches!(
            channel.recv_message().await,
            Err(MessageChannelError::Transport(_))
        ));
        assert!(channel.is_terminal());
        assert!(matches!(
            channel
                .send_message(0, 0, b"must not send after failure")
                .await,
            Err(MessageChannelError::Core(CoreError::TransportTerminal))
        ));
    }
}
