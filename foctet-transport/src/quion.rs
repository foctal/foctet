//! High-level Foctet integration helpers for `quion`.
//!
//! Enable Quion's `rustls-ring` or `rustls-aws-lc-rs` feature in the application
//! to select the TLS provider. Streams use Tokio I/O; datagrams use the shared
//! fail-closed [`crate::SecureDatagramChannel`] implementation.

#[cfg(feature = "dangerous-unauthenticated")]
use foctet_core::Session;
use foctet_core::{RekeyThresholds, SessionAuthConfig};
use thiserror::Error;

use crate::{
    TokioTransportBuilder, TokioTransportChannel, TransportChannelError, TransportConfig,
    TransportErrorDisposition, adapter::SplitIo,
};

/// Error returned by the datagram transport view of a Quion connection.
#[derive(Debug, Error)]
pub enum QuionDatagramTransportError {
    /// Quion refused to send the datagram.
    #[error("quion send datagram error: {0}")]
    Send(#[from] quion::SendDatagramError),
    /// The connection failed while receiving a datagram.
    #[error("quion connection error: {0}")]
    Connection(#[from] quion::ConnectionError),
}

impl QuionDatagramTransportError {
    /// Transport failures terminate the secure datagram channel.
    pub const fn disposition(&self) -> TransportErrorDisposition {
        TransportErrorDisposition::Terminal
    }
}

/// Secure datagrams over Quion, including MTU checks and terminal-error handling.
pub type QuionDatagramChannel = crate::SecureDatagramChannel<quion::Connection>;

impl crate::DatagramTransport for quion::Connection {
    type Error = QuionDatagramTransportError;

    async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Self::Error> {
        quion::Connection::send_datagram(self, datagram)?;
        Ok(())
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(quion::Connection::read_datagram(self).await?)
    }

    fn max_datagram_size(&self) -> Option<usize> {
        quion::Connection::max_datagram_size(self)
    }
}

/// Opens a bidirectional Quion stream and wraps it as a Foctet secure channel.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel(
    connection: &quion::Connection,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    open_secure_channel_with(connection, session, TransportConfig::default()).await
}

/// Opens a bidirectional Quion stream and applies a custom transport config.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel_with(
    connection: &quion::Connection,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .build_from_split(recv, send, session)
        .map_err(TransportChannelError::core)
}

/// Opens a bidirectional Quion stream, runs the native Foctet handshake, and wraps it as a secure channel.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel_with_handshake(
    connection: &quion::Connection,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Opens a bidirectional Quion stream, runs the native Foctet handshake, and applies a custom transport config.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel_with_handshake_and_config(
    connection: &quion::Connection,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Opens a bidirectional Quion stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
pub async fn open_secure_channel_with_handshake_and_auth_config(
    connection: &quion::Connection,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .establish_initiator_with_auth(SplitIo::from_split(recv, send), thresholds, auth)
        .await
        .map_err(TransportChannelError::core)
}

/// Accepts a bidirectional Quion stream and wraps it as a Foctet secure channel.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel(
    connection: &quion::Connection,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    accept_secure_channel_with(connection, session, TransportConfig::default()).await
}

/// Accepts a bidirectional Quion stream and applies a custom transport config.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel_with(
    connection: &quion::Connection,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .build_from_split(recv, send, session)
        .map_err(TransportChannelError::core)
}

/// Accepts a bidirectional Quion stream, runs the native Foctet handshake, and wraps it as a secure channel.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel_with_handshake(
    connection: &quion::Connection,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Accepts a bidirectional Quion stream, runs the native Foctet handshake, and applies a custom transport config.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel_with_handshake_and_config(
    connection: &quion::Connection,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Accepts a bidirectional Quion stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
pub async fn accept_secure_channel_with_handshake_and_auth_config(
    connection: &quion::Connection,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quion::RecvStream, quion::SendStream>>,
    TransportChannelError<quion::ConnectionError>,
> {
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .establish_responder_with_auth(SplitIo::from_split(recv, send), thresholds, auth)
        .await
        .map_err(TransportChannelError::core)
}
