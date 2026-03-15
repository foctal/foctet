use std::{future::poll_fn, pin::Pin};

use foctet_core::{AsyncSecureChannel, CoreError, FoctetFramed, Session, io::TokioIo};
use futures_sink::Sink;

use crate::{TransportConfig, adapter::SplitIo};

/// Builder for the recommended Tokio-based transport integration path.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioTransportBuilder {
    config: TransportConfig,
}

impl TokioTransportBuilder {
    /// Creates a builder with default transport configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the transport configuration.
    pub fn with_config(mut self, config: TransportConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the default application stream ID.
    pub fn with_app_stream_id(mut self, stream_id: u32) -> Self {
        self.config = self.config.with_app_stream_id(stream_id);
        self
    }

    /// Sets the default plaintext frame flags.
    pub fn with_app_flags(mut self, flags: u8) -> Self {
        self.config = self.config.with_app_flags(flags);
        self
    }

    /// Returns the current transport configuration.
    pub fn config(&self) -> TransportConfig {
        self.config
    }

    /// Builds a secure Foctet transport channel from a combined Tokio I/O object.
    pub fn build<T>(self, io: T, session: Session) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let inner = AsyncSecureChannel::from_tokio(io, session)?
            .with_app_stream_id(self.config.app_stream_id())
            .with_app_flags(self.config.app_flags());

        Ok(TokioTransportChannel {
            inner,
            config: self.config,
        })
    }

    /// Builds a secure Foctet transport channel from split Tokio halves.
    pub fn build_from_split<R, W>(
        self,
        recv: R,
        send: W,
        session: Session,
    ) -> Result<TokioTransportChannel<SplitIo<R, W>>, CoreError>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        self.build(SplitIo::from_split(recv, send), session)
    }
}

/// High-level Tokio secure transport wrapper.
#[derive(Debug)]
pub struct TokioTransportChannel<T> {
    inner: AsyncSecureChannel<TokioIo<T>>,
    config: TransportConfig,
}

impl<T> TokioTransportChannel<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Sends application bytes using the configured Foctet defaults.
    pub async fn send_application(&mut self, plaintext: &[u8]) -> Result<(), CoreError> {
        self.inner.send_data(plaintext).await
    }

    /// Receives the next application payload.
    pub async fn recv_application(&mut self) -> Result<Vec<u8>, CoreError> {
        self.inner.recv_application().await
    }

    /// Flushes and closes the secured transport channel.
    pub async fn close(&mut self) -> Result<(), CoreError> {
        poll_fn(|cx| Pin::new(self.inner.framed_mut()).poll_close(cx)).await
    }

    /// Returns the builder-driven transport configuration.
    pub fn config(&self) -> TransportConfig {
        self.config
    }

    /// Returns an immutable reference to the inner Foctet secure channel.
    pub fn core_channel(&self) -> &AsyncSecureChannel<TokioIo<T>> {
        &self.inner
    }

    /// Returns a mutable reference to the inner Foctet secure channel.
    pub fn core_channel_mut(&mut self) -> &mut AsyncSecureChannel<TokioIo<T>> {
        &mut self.inner
    }

    /// Returns an immutable reference to the framed Foctet transport.
    pub fn framed(&self) -> &FoctetFramed<TokioIo<T>> {
        self.inner.framed_ref()
    }

    /// Returns a mutable reference to the framed Foctet transport.
    pub fn framed_mut(&mut self) -> &mut FoctetFramed<TokioIo<T>> {
        self.inner.framed_mut()
    }

    /// Returns an immutable reference to the underlying Foctet session.
    pub fn session(&self) -> &Session {
        self.inner.session()
    }

    /// Returns a mutable reference to the underlying Foctet session.
    pub fn session_mut(&mut self) -> &mut Session {
        self.inner.session_mut()
    }

    /// Consumes the wrapper and returns the inner Foctet secure channel.
    pub fn into_core_channel(self) -> AsyncSecureChannel<TokioIo<T>> {
        self.inner
    }

    /// Consumes the wrapper and returns `(transport, session)`.
    pub fn into_transport_and_session(self) -> (T, Session) {
        let (framed, session) = self.inner.into_parts();
        let io = framed.into_inner();
        (io.into_inner(), session)
    }
}

#[cfg(all(test, feature = "runtime-tokio"))]
mod tests {
    use foctet_core::{RekeyThresholds, Session};

    use super::TokioTransportBuilder;
    use crate::TransportConfig;

    fn make_session_pair() -> Result<(Session, Session), foctet_core::CoreError> {
        let thresholds = RekeyThresholds::default();
        let (mut initiator, hello) = Session::new_initiator(thresholds.clone());
        let mut responder = Session::new_responder(thresholds);
        let server_hello = responder
            .handle_control(&hello)?
            .expect("responder returns server hello");
        initiator.handle_control(&server_hello)?;
        Ok((initiator, responder))
    }

    #[tokio::test]
    async fn builder_roundtrip_over_split_io() {
        let (client_session, server_session) = make_session_pair().expect("session pair");
        let (client_recv, server_send) = tokio::io::duplex(1024);
        let (server_recv, client_send) = tokio::io::duplex(1024);

        let config = TransportConfig::default().with_app_stream_id(7);
        let mut client = TokioTransportBuilder::new()
            .with_config(config)
            .build_from_split(client_recv, client_send, client_session)
            .expect("client channel");
        let mut server = TokioTransportBuilder::new()
            .with_config(config)
            .build_from_split(server_recv, server_send, server_session)
            .expect("server channel");

        client.send_application(b"ping").await.expect("client send");
        let msg = server.recv_application().await.expect("server recv");
        assert_eq!(msg, b"ping");
        assert_eq!(server.config().app_stream_id(), 7);
    }
}
