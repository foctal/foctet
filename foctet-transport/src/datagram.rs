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

use foctet_core::{
    CoreError, DatagramConfig, DatagramEndpoint, DecodedDatagram, Session, TrafficKeys,
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
        let keys = session.active_keys().ok_or(CoreError::InvalidSessionState)?;
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
    pub fn install_active_keys(&mut self, keys: TrafficKeys) {
        self.endpoint.install_active_keys(keys);
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
