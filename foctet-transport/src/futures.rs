use std::{future::poll_fn, pin::Pin};

use foctet_core::{
    AsyncSecureChannel, ControlMessage, CoreError, FoctetFramed, RekeyThresholds, Session,
    SessionAuthConfig, io::FuturesIo,
};
use futures_io::{AsyncRead, AsyncWrite};
use futures_sink::Sink;
use futures_util::{AsyncReadExt, AsyncWriteExt};

use crate::{TransportConfig, adapter::SplitIo};

const HANDSHAKE_CONTROL_MAX_LEN: usize = 1024;

/// Builder for the futures-io integration path.
#[derive(Clone, Copy, Debug, Default)]
pub struct FuturesTransportBuilder {
    config: TransportConfig,
}

impl FuturesTransportBuilder {
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

    /// Builds a secure Foctet transport channel from a combined futures-io object.
    pub fn build<T>(self, io: T, session: Session) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let inner = AsyncSecureChannel::from_futures(io, session)?
            .with_app_stream_id(self.config.app_stream_id())
            .with_app_flags(self.config.app_flags());

        Ok(FuturesTransportChannel {
            inner,
            config: self.config,
        })
    }

    /// Builds a secure Foctet transport channel from split futures-io halves.
    pub fn build_from_split<R, W>(
        self,
        recv: R,
        send: W,
        session: Session,
    ) -> Result<FuturesTransportChannel<SplitIo<R, W>>, CoreError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        self.build(SplitIo::from_split(recv, send), session)
    }

    /// Runs the native Foctet handshake as initiator on the transport, then builds a secure channel.
    pub async fn establish_initiator<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session =
            run_initiator_handshake(&mut io, thresholds, SessionAuthConfig::default()).await?;
        self.build(io, session)
    }

    /// Runs the native Foctet handshake as initiator with explicit authentication config.
    pub async fn establish_initiator_with_auth<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = run_initiator_handshake(&mut io, thresholds, auth).await?;
        self.build(io, session)
    }

    /// Runs the native Foctet handshake as responder on the transport, then builds a secure channel.
    pub async fn establish_responder<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session =
            run_responder_handshake(&mut io, thresholds, SessionAuthConfig::default()).await?;
        self.build(io, session)
    }

    /// Runs the native Foctet handshake as responder with explicit authentication config.
    pub async fn establish_responder_with_auth<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = run_responder_handshake(&mut io, thresholds, auth).await?;
        self.build(io, session)
    }

    /// Runs the native Foctet handshake as initiator on split transport halves, then builds a secure channel.
    pub async fn establish_initiator_from_split<R, W>(
        self,
        recv: R,
        send: W,
        thresholds: RekeyThresholds,
    ) -> Result<FuturesTransportChannel<SplitIo<R, W>>, CoreError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        self.establish_initiator(SplitIo::from_split(recv, send), thresholds)
            .await
    }

    /// Runs the native Foctet handshake as responder on split transport halves, then builds a secure channel.
    pub async fn establish_responder_from_split<R, W>(
        self,
        recv: R,
        send: W,
        thresholds: RekeyThresholds,
    ) -> Result<FuturesTransportChannel<SplitIo<R, W>>, CoreError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        self.establish_responder(SplitIo::from_split(recv, send), thresholds)
            .await
    }
}

async fn write_control<T>(io: &mut T, msg: &ControlMessage) -> Result<(), CoreError>
where
    T: AsyncWrite + Unpin,
{
    let encoded = msg.encode();
    let len = u16::try_from(encoded.len()).map_err(|_| CoreError::InvalidControlMessage)?;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(&encoded).await?;
    io.flush().await?;
    Ok(())
}

async fn read_control<T>(io: &mut T) -> Result<ControlMessage, CoreError>
where
    T: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 2];
    io.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > HANDSHAKE_CONTROL_MAX_LEN {
        return Err(CoreError::InvalidControlMessage);
    }

    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    ControlMessage::decode(&buf)
}

async fn run_initiator_handshake<T>(
    io: &mut T,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
) -> Result<Session, CoreError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut session, hello) = Session::new_initiator_with_auth(thresholds, auth);
    write_control(io, &hello).await?;
    let server_hello = read_control(io).await?;
    session.handle_control(&server_hello)?;
    Ok(session)
}

async fn run_responder_handshake<T>(
    io: &mut T,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
) -> Result<Session, CoreError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = Session::new_responder_with_auth(thresholds, auth);
    let hello = read_control(io).await?;
    let server_hello = session
        .handle_control(&hello)?
        .ok_or(CoreError::UnexpectedControlMessage)?;
    write_control(io, &server_hello).await?;
    Ok(session)
}

/// High-level futures-io secure transport wrapper.
#[derive(Debug)]
pub struct FuturesTransportChannel<T> {
    inner: AsyncSecureChannel<FuturesIo<T>>,
    config: TransportConfig,
}

impl<T> FuturesTransportChannel<T>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
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
    pub fn core_channel(&self) -> &AsyncSecureChannel<FuturesIo<T>> {
        &self.inner
    }

    /// Returns a mutable reference to the inner Foctet secure channel.
    pub fn core_channel_mut(&mut self) -> &mut AsyncSecureChannel<FuturesIo<T>> {
        &mut self.inner
    }

    /// Returns an immutable reference to the framed Foctet transport.
    pub fn framed(&self) -> &FoctetFramed<FuturesIo<T>> {
        self.inner.framed_ref()
    }

    /// Returns a mutable reference to the framed Foctet transport.
    pub fn framed_mut(&mut self) -> &mut FoctetFramed<FuturesIo<T>> {
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
    pub fn into_core_channel(self) -> AsyncSecureChannel<FuturesIo<T>> {
        self.inner
    }

    /// Consumes the wrapper and returns `(transport, session)`.
    pub fn into_transport_and_session(self) -> (T, Session) {
        let (framed, session) = self.inner.into_parts();
        let io = framed.into_inner();
        (io.into_inner(), session)
    }
}
