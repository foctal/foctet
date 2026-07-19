//! High-level Foctet integration helpers for `webtrans`.

#[cfg(feature = "dangerous-unauthenticated")]
use foctet_core::Session;
use foctet_core::{RekeyThresholds, SessionAuthConfig};

use crate::{
    TokioTransportBuilder, TokioTransportChannel, TransportChannelError, TransportConfig,
    adapter::SplitIo,
};

/// Opens a bidirectional WebTransport stream and wraps it as a Foctet secure channel.
#[cfg(feature = "dangerous-unauthenticated")]
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
#[cfg(feature = "dangerous-unauthenticated")]
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

/// Opens a bidirectional WebTransport stream, runs the native Foctet handshake, and wraps it as a secure channel.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel_with_handshake(
    session_handle: &webtrans::Session,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<webtrans::RecvStream, webtrans::SendStream>>,
    TransportChannelError<webtrans::quinn::SessionError>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        session_handle,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Opens a bidirectional WebTransport stream, runs the native Foctet handshake, and applies a custom transport config.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel_with_handshake_and_config(
    session_handle: &webtrans::Session,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<webtrans::RecvStream, webtrans::SendStream>>,
    TransportChannelError<webtrans::quinn::SessionError>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        session_handle,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Opens a bidirectional WebTransport stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
pub async fn open_secure_channel_with_handshake_and_auth_config(
    session_handle: &webtrans::Session,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
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
        .establish_initiator_with_auth(SplitIo::from_split(recv, send), thresholds, auth)
        .await
        .map_err(TransportChannelError::core)
}

/// Accepts a bidirectional WebTransport stream and wraps it as a Foctet secure channel.
#[cfg(feature = "dangerous-unauthenticated")]
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
#[cfg(feature = "dangerous-unauthenticated")]
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

/// Accepts a bidirectional WebTransport stream, runs the native Foctet handshake, and wraps it as a secure channel.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel_with_handshake(
    session_handle: &webtrans::Session,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<webtrans::RecvStream, webtrans::SendStream>>,
    TransportChannelError<webtrans::quinn::SessionError>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        session_handle,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Accepts a bidirectional WebTransport stream, runs the native Foctet handshake, and applies a custom transport config.
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel_with_handshake_and_config(
    session_handle: &webtrans::Session,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<webtrans::RecvStream, webtrans::SendStream>>,
    TransportChannelError<webtrans::quinn::SessionError>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        session_handle,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Accepts a bidirectional WebTransport stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
pub async fn accept_secure_channel_with_handshake_and_auth_config(
    session_handle: &webtrans::Session,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
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
        .establish_responder_with_auth(SplitIo::from_split(recv, send), thresholds, auth)
        .await
        .map_err(TransportChannelError::core)
}
