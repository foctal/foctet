//! High-level Foctet integration helpers for multiplexed WebSocket transports.

use foctet_core::Session;
use websock_tungstenite_mux as websock_mux;

use crate::{
    TokioTransportBuilder, TokioTransportChannel, TransportChannelError, TransportConfig,
    adapter::SplitIo,
};

/// Opens a bidirectional WebSocket-mux stream and wraps it as a Foctet secure channel.
pub async fn open_secure_channel(
    session_handle: &websock_mux::Session,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    open_secure_channel_with(session_handle, session, TransportConfig::default()).await
}

/// Opens a bidirectional WebSocket-mux stream and applies a custom transport config.
pub async fn open_secure_channel_with(
    session_handle: &websock_mux::Session,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
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

/// Accepts a bidirectional WebSocket-mux stream and wraps it as a Foctet secure channel.
pub async fn accept_secure_channel(
    session_handle: &websock_mux::Session,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    accept_secure_channel_with(session_handle, session, TransportConfig::default()).await
}

/// Accepts a bidirectional WebSocket-mux stream and applies a custom transport config.
pub async fn accept_secure_channel_with(
    session_handle: &websock_mux::Session,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
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
