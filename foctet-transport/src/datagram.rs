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
//! The flow is therefore: rekey the [`Session`] over its control channel on both
//! peers, then call [`SecureDatagramChannel::rekey_from_session`] on each side to
//! adopt the rotated key. Each new key gets a new `key_id`, and the endpoint
//! retains the previous key(s) ([`DatagramConfig::max_retained_keys`]), so
//! datagrams sealed under the **old** key that arrive (reordered or delayed)
//! after the rekey still decrypt — datagrams carry their `key_id`, and the
//! receiver selects the matching retained key.

use foctet_core::{
    CoreError, DatagramConfig, DatagramEndpoint, DecodedDatagram, KeyHandle, Session,
};
use thiserror::Error;

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

/// A secure Foctet datagram channel over any [`DatagramTransport`].
///
/// Negotiate keys with a normal Foctet handshake (for example over a control
/// stream) first, then build this channel from the resulting [`Session`].
#[derive(Debug)]
pub struct SecureDatagramChannel<T> {
    transport: T,
    endpoint: DatagramEndpoint,
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
        let keys = session
            .active_keys()
            .ok_or(CoreError::InvalidSessionState)?;
        let endpoint = DatagramEndpoint::with_config(
            keys,
            session.inbound_direction(),
            session.outbound_direction(),
            config,
        );
        Ok(Self {
            transport,
            endpoint,
        })
    }

    /// Returns the maximum plaintext bytes that fit in one datagram.
    pub fn max_plaintext_len(&self) -> usize {
        self.endpoint.max_plaintext_len()
    }

    /// Installs a freshly rotated set of traffic keys (after a rekey).
    pub fn install_active_keys(&mut self, keys: KeyHandle) {
        self.endpoint.install_active_keys(keys);
    }

    /// Adopts the session's current active traffic keys after it has rekeyed
    /// over its (reliable) control channel.
    ///
    /// See the module-level "Rekey over datagrams" section: drive the rekey on
    /// the [`Session`] over a reliable control channel, then call this on both
    /// peers. The previous key is retained, so datagrams sealed under the old
    /// key that arrive after the rekey still decrypt.
    pub fn rekey_from_session(&mut self, session: &Session) -> Result<(), CoreError> {
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

    /// Seals `plaintext` into one frame and sends it as a single datagram.
    pub async fn send_datagram(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<(), DatagramChannelError<T::Error>> {
        let bytes = self.endpoint.seal(stream_id, flags, plaintext)?;
        self.transport
            .send_datagram(bytes)
            .await
            .map_err(DatagramChannelError::Transport)?;
        Ok(())
    }

    /// Receives one datagram and opens it into a decrypted payload.
    pub async fn recv_datagram(
        &mut self,
    ) -> Result<DecodedDatagram, DatagramChannelError<T::Error>> {
        let bytes = self
            .transport
            .recv_datagram()
            .await
            .map_err(DatagramChannelError::Transport)?;
        Ok(self.endpoint.open(&bytes)?)
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

        // Rekey the sessions over the (reliable) control channel, then adopt the
        // rotated key into both datagram channels.
        let rekey = session_init.force_rekey().expect("initiator rekeys");
        session_resp
            .handle_control(&rekey)
            .expect("responder applies rekey");
        a.rekey_from_session(&session_init).expect("a rekey");
        b.rekey_from_session(&session_resp).expect("b rekey");

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
}
