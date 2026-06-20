//! High-level Foctet integration helpers for `quinn`.

use foctet_core::{RekeyThresholds, Session, SessionAuthConfig};

use crate::{
    TokioTransportBuilder, TokioTransportChannel, TransportChannelError, TransportConfig,
    adapter::SplitIo,
};

/// Opens a bidirectional Quinn stream and wraps it as a Foctet secure channel.
pub async fn open_secure_channel(
    connection: &quinn::Connection,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    open_secure_channel_with(connection, session, TransportConfig::default()).await
}

/// Opens a bidirectional Quinn stream and applies a custom transport config.
pub async fn open_secure_channel_with(
    connection: &quinn::Connection,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
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

/// Opens a bidirectional Quinn stream, runs the native Foctet handshake, and wraps it as a secure channel.
pub async fn open_secure_channel_with_handshake(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Opens a bidirectional Quinn stream, runs the native Foctet handshake, and applies a custom transport config.
pub async fn open_secure_channel_with_handshake_and_config(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Opens a bidirectional Quinn stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
pub async fn open_secure_channel_with_handshake_and_auth_config(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
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

/// Accepts a bidirectional Quinn stream and wraps it as a Foctet secure channel.
pub async fn accept_secure_channel(
    connection: &quinn::Connection,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    accept_secure_channel_with(connection, session, TransportConfig::default()).await
}

/// Accepts a bidirectional Quinn stream and applies a custom transport config.
pub async fn accept_secure_channel_with(
    connection: &quinn::Connection,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
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

/// Accepts a bidirectional Quinn stream, runs the native Foctet handshake, and wraps it as a secure channel.
pub async fn accept_secure_channel_with_handshake(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Accepts a bidirectional Quinn stream, runs the native Foctet handshake, and applies a custom transport config.
pub async fn accept_secure_channel_with_handshake_and_config(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Accepts a bidirectional Quinn stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
pub async fn accept_secure_channel_with_handshake_and_auth_config(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
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
