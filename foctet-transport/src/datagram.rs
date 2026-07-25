//! Generic, backend-agnostic datagram transport abstraction.
//!
//! [`DatagramTransport`] is the datagram counterpart to the byte-stream
//! integrations in this crate: it moves whole, message-bounded datagrams.
//! [`SecureDatagramChannel`] layers Foctet's [`DatagramEndpoint`] on top of any
//! `DatagramTransport`, so a single secure-datagram implementation works over
//! QUIC datagrams, WebTransport datagrams, raw UDP, or any other datagram
//! backend that implements the trait.
//!
//! Each `send` seals exactly one Foctet frame into one datagram; each `recv`
//! opens exactly one. Loss and reordering are tolerated by the replay window,
//! and replay state is committed only after AEAD authentication.
//!
//! # Rekey over datagrams
//!
//! Foctet's rekey is a DH ratchet driven by [`Session`] control messages, and
//! those control messages MUST travel over a **reliable, ordered** channel (a
//! control stream) — the datagram path itself is lossy and reordering, so a lost
//! ratchet message would desynchronize the peers. This mirrors QUIC, where the
//! handshake and key updates ride reliable streams while application data rides
//! datagrams under the negotiated keys.
//!
//! The recommended flow uses [`SecureDatagramChannel::send_rekey`] and
//! [`SecureDatagramChannel::recv_rekey`] with a [`SecureMessageChannel`] as the
//! reliable encrypted control path. These methods bind control delivery,
//! session commit, and datagram-key adoption into one fail-closed operation.
//! Each new key gets a new `key_id`, and the endpoint retains the previous
//! key(s) ([`DatagramConfig::max_retained_keys`]), so datagrams sealed under the
//! **old** key that arrive (reordered or delayed) after the rekey still decrypt
//! — datagrams carry their `key_id`, and the receiver selects the matching
//! retained key.

use foctet_core::{
    CoreError, DatagramConfig, DatagramEndpoint, DecodedDatagram, KeyHandle, Session,
};
use thiserror::Error;

use crate::error::TransportErrorDisposition;
use crate::message::{MessageChannelError, MessageTransport, SecureMessageChannel};

/// A message-oriented datagram transport that sends and receives whole datagrams.
///
/// The futures intentionally do **not** require `Send`, so the trait is usable
/// from `!Send` runtimes such as browser WebTransport. Implementations should
/// move exactly the bytes they are given per datagram, preserving message
/// boundaries.
#[allow(async_fn_in_trait)]
pub trait DatagramTransport {
    /// Transport-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Sends one datagram.
    async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Self::Error>;

    /// Receives one datagram.
    async fn recv_datagram(&self) -> Result<Vec<u8>, Self::Error>;

    /// Returns the maximum datagram payload size the transport accepts, if known.
    fn max_datagram_size(&self) -> Option<usize>;
}

/// Error returned by [`SecureDatagramChannel`] operations.
#[derive(Debug, Error)]
pub enum DatagramChannelError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Foctet datagram seal/open failed.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// The underlying datagram transport failed.
    #[error("datagram transport error: {0}")]
    Transport(E),
}

impl<E> DatagramChannelError<E>
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

/// A secure Foctet datagram channel over any [`DatagramTransport`].
///
/// Negotiate keys with a normal Foctet handshake (for example over a control
/// stream) first, then build this channel from the resulting [`Session`].
#[derive(Debug)]
pub struct SecureDatagramChannel<T> {
    transport: T,
    endpoint: DatagramEndpoint,
    terminal: bool,
}

impl<T> SecureDatagramChannel<T>
where
    T: DatagramTransport,
{
    /// Builds a channel from a transport and an active [`Session`], clamping the
    /// datagram size to the transport's reported maximum when available.
    pub fn from_active_session(transport: T, session: &Session) -> Result<Self, CoreError> {
        let mut config = DatagramConfig::default();
        if let Some(max) = transport.max_datagram_size() {
            config.max_datagram_size = config.max_datagram_size.min(max);
        }
        Self::from_active_session_with_config(transport, session, config)
    }

    /// Builds a channel from a transport, an active [`Session`], and an explicit
    /// datagram configuration.
    pub fn from_active_session_with_config(
        transport: T,
        session: &Session,
        config: DatagramConfig,
    ) -> Result<Self, CoreError> {
        let lease = session.claim_datagram_endpoint()?;
        let endpoint = DatagramEndpoint::from_session_lease_with_config(lease, config);
        Ok(Self {
            transport,
            endpoint,
            terminal: false,
        })
    }

    /// Returns the maximum plaintext bytes that fit in one datagram.
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

    /// Adopts the session's current active traffic keys after it has rekeyed
    /// over its (reliable) control channel.
    ///
    /// This is a low-level adoption primitive. Prefer [`Self::send_rekey`] and
    /// [`Self::recv_rekey`], which integrate the reliable control transaction.
    /// The previous key is retained, so datagrams sealed under the old key that
    /// arrive after the rekey still decrypt.
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

    /// Initiates a transactional rekey over a reliable secure message channel,
    /// then adopts the committed key for datagrams.
    pub async fn send_rekey<C>(
        &mut self,
        control: &mut SecureMessageChannel<C>,
        session: &mut Session,
    ) -> Result<(), MessageChannelError<C::Error>>
    where
        C: MessageTransport,
    {
        if self.is_terminal() {
            return Err(MessageChannelError::Core(CoreError::TransportTerminal));
        }
        if let Err(error) = control.send_rekey(session).await {
            self.terminal = true;
            return Err(error);
        }
        if let Err(error) = self.rekey_from_session(session) {
            self.terminal = true;
            session.terminate();
            return Err(MessageChannelError::Core(error));
        }
        Ok(())
    }

    /// Receives a transactional rekey over a reliable secure message channel,
    /// then adopts the applied key for datagrams.
    pub async fn recv_rekey<C>(
        &mut self,
        control: &mut SecureMessageChannel<C>,
        session: &mut Session,
    ) -> Result<(), MessageChannelError<C::Error>>
    where
        C: MessageTransport,
    {
        if self.is_terminal() {
            return Err(MessageChannelError::Core(CoreError::TransportTerminal));
        }
        if let Err(error) = control.recv_rekey(session).await {
            self.terminal = true;
            return Err(error);
        }
        if let Err(error) = self.rekey_from_session(session) {
            self.terminal = true;
            session.terminate();
            return Err(MessageChannelError::Core(error));
        }
        Ok(())
    }

    /// Returns a reference to the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Seals `plaintext` into one frame and sends it as a single datagram.
    pub async fn send_datagram(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<(), DatagramChannelError<T::Error>> {
        if self.is_terminal() {
            return Err(DatagramChannelError::Core(CoreError::TransportTerminal));
        }
        let bytes = match self.endpoint.seal(stream_id, flags, plaintext) {
            Ok(bytes) => bytes,
            Err(error) => {
                if error.disposition() == foctet_core::CoreErrorDisposition::Terminal {
                    self.terminal = true;
                }
                return Err(DatagramChannelError::Core(error));
            }
        };
        match self.transport.send_datagram(bytes).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.terminal = true;
                Err(DatagramChannelError::Transport(error))
            }
        }
    }

    /// Receives one datagram and opens it into a decrypted payload.
    pub async fn recv_datagram(
        &mut self,
    ) -> Result<DecodedDatagram, DatagramChannelError<T::Error>> {
        if self.is_terminal() {
            return Err(DatagramChannelError::Core(CoreError::TransportTerminal));
        }
        let bytes = match self.transport.recv_datagram().await {
            Ok(bytes) => bytes,
            Err(error) => {
                self.terminal = true;
                return Err(DatagramChannelError::Transport(error));
            }
        };
        match self.endpoint.open(&bytes) {
            Ok(datagram) => Ok(datagram),
            Err(error) => {
                if error.disposition() == foctet_core::CoreErrorDisposition::Terminal {
                    self.terminal = true;
                }
                Err(DatagramChannelError::Core(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use foctet_core::{RekeyThresholds, Session, SessionAuthConfig};

    /// In-memory, lossy/reorderable datagram transport for one direction.
    #[derive(Default)]
    struct MemoryDatagramTransport {
        inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
        outbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("memory datagram transport closed")]
    struct MemoryError;

    #[derive(Debug)]
    struct FailingControlTransport;

    impl MessageTransport for FailingControlTransport {
        type Error = MemoryError;

        async fn send_message(&self, _message: Vec<u8>) -> Result<(), Self::Error> {
            Err(MemoryError)
        }

        async fn recv_message(&self) -> Result<Vec<u8>, Self::Error> {
            Err(MemoryError)
        }

        fn max_message_size(&self) -> Option<usize> {
            None
        }
    }

    impl DatagramTransport for MemoryDatagramTransport {
        type Error = MemoryError;

        async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Self::Error> {
            self.outbox.borrow_mut().push_back(datagram);
            Ok(())
        }

        async fn recv_datagram(&self) -> Result<Vec<u8>, Self::Error> {
            self.inbox.borrow_mut().pop_front().ok_or(MemoryError)
        }

        fn max_datagram_size(&self) -> Option<usize> {
            None
        }
    }

    impl MessageTransport for MemoryDatagramTransport {
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

    fn linked_pair() -> (MemoryDatagramTransport, MemoryDatagramTransport) {
        let a_to_b: Rc<RefCell<VecDeque<Vec<u8>>>> = Rc::default();
        let b_to_a: Rc<RefCell<VecDeque<Vec<u8>>>> = Rc::default();
        let a = MemoryDatagramTransport {
            inbox: b_to_a.clone(),
            outbox: a_to_b.clone(),
        };
        let b = MemoryDatagramTransport {
            inbox: a_to_b,
            outbox: b_to_a,
        };
        (a, b)
    }

    fn session_pair() -> (Session, Session) {
        let (mut initiator, hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut responder = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let server_hello = responder
            .handle_control(&hello)
            .expect("responder handles hello")
            .expect("server hello");
        initiator
            .handle_control(&server_hello)
            .expect("initiator finalizes");
        (initiator, responder)
    }

    #[tokio::test]
    async fn datagrams_decrypt_across_a_rekey_including_a_reordered_old_key_datagram() {
        let (mut session_init, mut session_resp) = session_pair();
        let (transport_a, transport_b) = linked_pair();
        let mut a =
            SecureDatagramChannel::from_active_session(transport_a, &session_init).expect("a");
        let mut b =
            SecureDatagramChannel::from_active_session(transport_b, &session_resp).expect("b");
        let (control_transport_a, control_transport_b) = linked_pair();
        let mut control_a =
            SecureMessageChannel::from_active_session(control_transport_a, &session_init)
                .expect("a control");
        let mut control_b =
            SecureMessageChannel::from_active_session(control_transport_b, &session_resp)
                .expect("b control");

        // A sends a datagram under the original key (key_id 0); capture it off
        // the wire and withhold it so it arrives *after* the rekey.
        a.send_datagram(0, 0, b"sealed before rekey")
            .await
            .expect("send old");
        let old_key_datagram = b
            .transport()
            .inbox
            .borrow_mut()
            .pop_front()
            .expect("one datagram queued");

        // Rekey over a real reliable, encrypted control channel. The sender
        // commits only after the backend accepts the old-key control message;
        // each datagram endpoint adopts the session key in the same operation.
        a.send_rekey(&mut control_a, &mut session_init)
            .await
            .expect("a sends rekey");
        b.recv_rekey(&mut control_b, &mut session_resp)
            .await
            .expect("b receives rekey");

        // A sends a datagram under the new key (key_id 1).
        a.send_datagram(0, 0, b"sealed after rekey")
            .await
            .expect("send new");

        // Deliver the OLD-key datagram first (reordered across the rekey): the
        // retained previous key must still open it.
        b.transport()
            .inbox
            .borrow_mut()
            .push_front(old_key_datagram);
        let old = b.recv_datagram().await.expect("recv old");
        assert_eq!(old.header.key_id, 0);
        assert_eq!(old.plaintext, b"sealed before rekey");

        // Then the new-key datagram opens under the rotated key.
        let new = b.recv_datagram().await.expect("recv new");
        assert_eq!(new.header.key_id, 1);
        assert_eq!(new.plaintext, b"sealed after rekey");
    }

    #[tokio::test]
    async fn transport_error_makes_datagram_channel_terminal() {
        let (initiator, _responder) = session_pair();
        let (transport, _peer) = linked_pair();
        let mut channel =
            SecureDatagramChannel::from_active_session(transport, &initiator).expect("channel");

        assert!(matches!(
            channel.recv_datagram().await,
            Err(DatagramChannelError::Transport(_))
        ));
        assert!(channel.is_terminal());
        assert!(matches!(
            channel
                .send_datagram(0, 0, b"must not send after failure")
                .await,
            Err(DatagramChannelError::Core(CoreError::TransportTerminal))
        ));
    }

    #[tokio::test]
    async fn control_send_failure_closes_datagram_channel_and_session() {
        let (mut initiator, _responder) = session_pair();
        let (transport, _peer) = linked_pair();
        let mut datagrams =
            SecureDatagramChannel::from_active_session(transport, &initiator).expect("datagrams");
        let mut control =
            SecureMessageChannel::from_active_session(FailingControlTransport, &initiator)
                .expect("control");

        assert!(matches!(
            datagrams.send_rekey(&mut control, &mut initiator).await,
            Err(MessageChannelError::Transport(_))
        ));
        assert!(datagrams.is_terminal());
        assert!(control.is_terminal());
        assert_eq!(initiator.state(), foctet_core::SessionState::Closed);
        assert!(initiator.active_keys().is_none());
    }

    #[tokio::test]
    async fn dropped_rekey_control_fails_closed_on_receive() {
        let (mut initiator, mut responder) = session_pair();
        let (data_a, data_b) = linked_pair();
        let mut datagrams_a =
            SecureDatagramChannel::from_active_session(data_a, &initiator).expect("a datagrams");
        let mut datagrams_b =
            SecureDatagramChannel::from_active_session(data_b, &responder).expect("b datagrams");
        let (control_a, control_b) = linked_pair();
        let mut control_a =
            SecureMessageChannel::from_active_session(control_a, &initiator).expect("a control");
        let mut control_b =
            SecureMessageChannel::from_active_session(control_b, &responder).expect("b control");

        datagrams_a
            .send_rekey(&mut control_a, &mut initiator)
            .await
            .expect("sender commits accepted control");
        control_b
            .transport()
            .inbox
            .borrow_mut()
            .pop_front()
            .expect("drop queued rekey control");

        assert!(matches!(
            datagrams_b.recv_rekey(&mut control_b, &mut responder).await,
            Err(MessageChannelError::Transport(_))
        ));
        assert!(datagrams_b.is_terminal());
        assert!(control_b.is_terminal());
        assert_eq!(responder.state(), foctet_core::SessionState::Closed);
        assert_eq!(
            initiator.active_keys().expect("sender key").key_id,
            1,
            "sender committed only the accepted generation"
        );
    }

    #[tokio::test]
    async fn duplicate_rekey_control_closes_receiver_without_advancing_twice() {
        let (mut initiator, mut responder) = session_pair();
        let (data_a, data_b) = linked_pair();
        let mut datagrams_a =
            SecureDatagramChannel::from_active_session(data_a, &initiator).expect("a datagrams");
        let mut datagrams_b =
            SecureDatagramChannel::from_active_session(data_b, &responder).expect("b datagrams");
        let (control_a, control_b) = linked_pair();
        let mut control_a =
            SecureMessageChannel::from_active_session(control_a, &initiator).expect("a control");
        let mut control_b =
            SecureMessageChannel::from_active_session(control_b, &responder).expect("b control");

        datagrams_a
            .send_rekey(&mut control_a, &mut initiator)
            .await
            .expect("send rekey");
        let duplicate = control_b
            .transport()
            .inbox
            .borrow()
            .front()
            .expect("queued rekey")
            .clone();
        datagrams_b
            .recv_rekey(&mut control_b, &mut responder)
            .await
            .expect("apply first rekey");
        assert_eq!(responder.active_keys().expect("receiver key").key_id, 1);

        control_b
            .transport()
            .inbox
            .borrow_mut()
            .push_back(duplicate);
        assert!(matches!(
            datagrams_b.recv_rekey(&mut control_b, &mut responder).await,
            Err(MessageChannelError::Core(CoreError::Replay))
        ));
        assert!(datagrams_b.is_terminal());
        assert!(control_b.is_terminal());
        assert_eq!(responder.state(), foctet_core::SessionState::Closed);
        assert!(responder.active_keys().is_none());
    }
}
