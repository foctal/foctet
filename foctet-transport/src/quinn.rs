//! High-level Foctet integration helpers for `quinn`.

use foctet_core::Session;

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
