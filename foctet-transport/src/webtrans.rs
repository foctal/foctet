//! High-level Foctet integration helpers for `webtrans`.

use foctet_core::Session;

use crate::{
    TokioTransportBuilder, TokioTransportChannel, TransportChannelError, TransportConfig,
    adapter::SplitIo,
};

/// Opens a bidirectional WebTransport stream and wraps it as a Foctet secure channel.
pub async fn open_secure_channel(
    session_handle: &webtrans::Session,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<webtrans::RecvStream, webtrans::SendStream>>,
    TransportChannelError<webtrans::quinn::SessionError>,
> {
    open_secure_channel_with(session_handle, session, TransportConfig::default()).await
}

/// Opens a bidirectional WebTransport stream and applies a custom transport config.
pub async fn open_secure_channel_with(
    session_handle: &webtrans::Session,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<webtrans::RecvStream, webtrans::SendStream>>,
    TransportChannelError<webtrans::quinn::SessionError>,
> {
    let (send, recv) = session_handle
        .open_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .build_from_split(recv, send, session)
        .map_err(TransportChannelError::core)
}

/// Accepts a bidirectional WebTransport stream and wraps it as a Foctet secure channel.
pub async fn accept_secure_channel(
    session_handle: &webtrans::Session,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<webtrans::RecvStream, webtrans::SendStream>>,
    TransportChannelError<webtrans::quinn::SessionError>,
> {
    accept_secure_channel_with(session_handle, session, TransportConfig::default()).await
}

/// Accepts a bidirectional WebTransport stream and applies a custom transport config.
pub async fn accept_secure_channel_with(
    session_handle: &webtrans::Session,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<webtrans::RecvStream, webtrans::SendStream>>,
    TransportChannelError<webtrans::quinn::SessionError>,
> {
    let (send, recv) = session_handle
        .accept_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .build_from_split(recv, send, session)
        .map_err(TransportChannelError::core)
}
