//! High-level Foctet integration helpers for `muxtls`.

use foctet_core::Session;

use crate::{
    TokioTransportBuilder, TokioTransportChannel, TransportChannelError, TransportConfig,
    adapter::SplitIo,
};

/// Opens a bidirectional muxtls stream and wraps it as a Foctet secure channel.
pub async fn open_secure_channel(
    connection: &muxtls::Connection,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<muxtls::RecvStream, muxtls::SendStream>>,
    TransportChannelError<muxtls::Error>,
> {
    open_secure_channel_with(connection, session, TransportConfig::default()).await
}

/// Opens a bidirectional muxtls stream and applies a custom transport config.
pub async fn open_secure_channel_with(
    connection: &muxtls::Connection,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<muxtls::RecvStream, muxtls::SendStream>>,
    TransportChannelError<muxtls::Error>,
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

/// Accepts a bidirectional muxtls stream and wraps it as a Foctet secure channel.
pub async fn accept_secure_channel(
    connection: &muxtls::Connection,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<muxtls::RecvStream, muxtls::SendStream>>,
    TransportChannelError<muxtls::Error>,
> {
    accept_secure_channel_with(connection, session, TransportConfig::default()).await
}

/// Accepts a bidirectional muxtls stream and applies a custom transport config.
pub async fn accept_secure_channel_with(
    connection: &muxtls::Connection,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<muxtls::RecvStream, muxtls::SendStream>>,
    TransportChannelError<muxtls::Error>,
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
