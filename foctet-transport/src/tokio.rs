use std::{future::poll_fn, pin::Pin, time::Duration};

use foctet_core::{
    AsyncSecureChannel, ControlMessage, CoreError, FoctetFramed, RekeyThresholds, Session,
    SessionAuthConfig, io::TokioIo,
};
use futures_sink::Sink;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{TransportConfig, adapter::SplitIo};

const HANDSHAKE_CONTROL_MAX_LEN: usize = 1024;

/// Default deadline for [`TokioTransportBuilder::establish_initiator_with_timeout`]
/// and the responder/auth variants: enough for a two-message round trip over a
/// slow network, short enough to bound a stalled or hostile peer's hold on
/// server resources. This is the same value as
/// [`foctet_core::ProtocolLimits::handshake_timeout`]'s default, so the
/// centralized limits struct remains the single documented source.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = foctet_core::DEFAULT_HANDSHAKE_TIMEOUT;

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
        T: AsyncRead + AsyncWrite + Unpin,
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
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = run_initiator_handshake(
            &mut io,
            thresholds,
            SessionAuthConfig::unauthenticated_for_testing(),
        )
        .await?;
        self.build(io, session)
    }

    /// Runs the native Foctet handshake as initiator with explicit authentication config.
    pub async fn establish_initiator_with_auth<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
    ) -> Result<TokioTransportChannel<T>, CoreError>
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
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = run_responder_handshake(
            &mut io,
            thresholds,
            SessionAuthConfig::unauthenticated_for_testing(),
        )
        .await?;
        self.build(io, session)
    }

    /// Runs the native Foctet handshake as responder with explicit authentication config.
    pub async fn establish_responder_with_auth<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = run_responder_handshake(&mut io, thresholds, auth).await?;
        self.build(io, session)
    }

    /// Runs the native Foctet handshake as initiator with an explicit deadline,
    /// failing with [`CoreError::HandshakeTimeout`] if the peer does not
    /// complete it in time. Bounds how long a stalled or hostile peer can hold
    /// a connection open before authentication completes.
    pub async fn establish_initiator_with_auth_and_timeout<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
        timeout: Duration,
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session =
            tokio::time::timeout(timeout, run_initiator_handshake(&mut io, thresholds, auth))
                .await
                .map_err(|_| CoreError::HandshakeTimeout)??;
        self.build(io, session)
    }

    /// Convenience wrapper using [`DEFAULT_HANDSHAKE_TIMEOUT`] and the
    /// unauthenticated-for-testing auth config; see
    /// [`Self::establish_initiator_with_auth_and_timeout`].
    pub async fn establish_initiator_with_timeout<T>(
        self,
        io: T,
        thresholds: RekeyThresholds,
        timeout: Duration,
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        self.establish_initiator_with_auth_and_timeout(
            io,
            thresholds,
            SessionAuthConfig::unauthenticated_for_testing(),
            timeout,
        )
        .await
    }

    /// Runs the native Foctet handshake as responder with an explicit
    /// deadline; see [`Self::establish_initiator_with_auth_and_timeout`].
    pub async fn establish_responder_with_auth_and_timeout<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
        timeout: Duration,
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session =
            tokio::time::timeout(timeout, run_responder_handshake(&mut io, thresholds, auth))
                .await
                .map_err(|_| CoreError::HandshakeTimeout)??;
        self.build(io, session)
    }

    /// Rate-limited responder handshake: consults `limiter` **before** doing
    /// any handshake work, failing fast with
    /// [`CoreError::HandshakeRateLimited`] when admission control is
    /// saturated, then runs
    /// [`Self::establish_responder_with_auth_and_timeout`]. Intended for
    /// accept loops that share one [`crate::HandshakeRateLimiter`] across all
    /// inbound connections.
    pub async fn establish_responder_with_auth_timeout_and_limiter<T>(
        self,
        io: T,
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
        timeout: Duration,
        limiter: &crate::HandshakeRateLimiter,
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        limiter.admit()?;
        self.establish_responder_with_auth_and_timeout(io, thresholds, auth, timeout)
            .await
    }

    /// Convenience wrapper using [`DEFAULT_HANDSHAKE_TIMEOUT`] and the
    /// unauthenticated-for-testing auth config; see
    /// [`Self::establish_responder_with_auth_and_timeout`].
    pub async fn establish_responder_with_timeout<T>(
        self,
        io: T,
        thresholds: RekeyThresholds,
        timeout: Duration,
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        self.establish_responder_with_auth_and_timeout(
            io,
            thresholds,
            SessionAuthConfig::unauthenticated_for_testing(),
            timeout,
        )
        .await
    }

    /// Convenience wrapper using [`DEFAULT_HANDSHAKE_TIMEOUT`]; see
    /// [`Self::establish_initiator_with_timeout`].
    pub async fn establish_initiator_with_default_timeout<T>(
        self,
        io: T,
        thresholds: RekeyThresholds,
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        self.establish_initiator_with_timeout(io, thresholds, DEFAULT_HANDSHAKE_TIMEOUT)
            .await
    }

    /// Convenience wrapper using [`DEFAULT_HANDSHAKE_TIMEOUT`]; see
    /// [`Self::establish_responder_with_timeout`].
    pub async fn establish_responder_with_default_timeout<T>(
        self,
        io: T,
        thresholds: RekeyThresholds,
    ) -> Result<TokioTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        self.establish_responder_with_timeout(io, thresholds, DEFAULT_HANDSHAKE_TIMEOUT)
            .await
    }

    /// Runs the native Foctet handshake as initiator on split transport halves, then builds a secure channel.
    pub async fn establish_initiator_from_split<R, W>(
        self,
        recv: R,
        send: W,
        thresholds: RekeyThresholds,
    ) -> Result<TokioTransportChannel<SplitIo<R, W>>, CoreError>
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
    ) -> Result<TokioTransportChannel<SplitIo<R, W>>, CoreError>
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
    let mut serialized = Vec::with_capacity(2 + encoded.len());
    serialized.extend_from_slice(&len.to_be_bytes());
    serialized.extend_from_slice(&encoded);
    // Keep one immutable serialization alive until the complete handshake
    // control has been written. The builder owns `io`, so any write or flush
    // error drops the connection and the uncommitted session together.
    io.write_all(&serialized).await?;
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
    use std::{
        io,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };

    use foctet_core::{RekeyThresholds, Session, SessionAuthConfig};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::TokioTransportBuilder;
    use crate::TransportConfig;

    #[derive(Clone, Copy, Debug)]
    enum HandshakeWriteFailure {
        ErrorAfter(usize),
        WriteZero,
        Flush,
        PeerClosed,
    }

    #[derive(Debug, Default)]
    struct HandshakeWriteState {
        outbound: Vec<u8>,
    }

    #[derive(Debug)]
    struct FailingHandshakeIo {
        failure: HandshakeWriteFailure,
        state: Arc<Mutex<HandshakeWriteState>>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for FailingHandshakeIo {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncRead for FailingHandshakeIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.failure {
                HandshakeWriteFailure::PeerClosed => Poll::Ready(Ok(())),
                _ => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for FailingHandshakeIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.state.lock().expect("handshake state lock");
            match self.failure {
                HandshakeWriteFailure::ErrorAfter(limit) => {
                    let remaining = limit.saturating_sub(state.outbound.len());
                    if remaining == 0 {
                        return Poll::Ready(Err(io::Error::other(
                            "injected handshake write failure",
                        )));
                    }
                    let written = remaining.min(buf.len());
                    state.outbound.extend_from_slice(&buf[..written]);
                    Poll::Ready(Ok(written))
                }
                HandshakeWriteFailure::WriteZero => Poll::Ready(Ok(0)),
                HandshakeWriteFailure::Flush | HandshakeWriteFailure::PeerClosed => {
                    state.outbound.extend_from_slice(buf);
                    Poll::Ready(Ok(buf.len()))
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.failure {
                HandshakeWriteFailure::Flush => {
                    Poll::Ready(Err(io::Error::other("injected handshake flush failure")))
                }
                _ => Poll::Ready(Ok(())),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn assert_handshake_write_failure(
        failure: HandshakeWriteFailure,
        expected_emitted: Option<usize>,
    ) {
        let state = Arc::new(Mutex::new(HandshakeWriteState::default()));
        let dropped = Arc::new(AtomicBool::new(false));
        let io = FailingHandshakeIo {
            failure,
            state: state.clone(),
            dropped: dropped.clone(),
        };

        let result = TokioTransportBuilder::new()
            .establish_initiator(io, RekeyThresholds::default())
            .await;
        assert!(matches!(result, Err(foctet_core::CoreError::Io(_))));
        assert!(
            dropped.load(Ordering::SeqCst),
            "failed handshake must discard its owned connection"
        );

        let emitted = state.lock().expect("handshake state lock").outbound.len();
        match expected_emitted {
            Some(expected) => assert_eq!(emitted, expected),
            None => assert!(emitted > 2, "complete handshake frame must be emitted"),
        }
    }

    fn make_session_pair() -> Result<(Session, Session), foctet_core::CoreError> {
        let thresholds = RekeyThresholds::default();
        let (mut initiator, hello) = Session::new_initiator_with_auth(
            thresholds.clone(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut responder = Session::new_responder_with_auth(
            thresholds,
            SessionAuthConfig::unauthenticated_for_testing(),
        );
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

    #[tokio::test]
    async fn builder_establishes_handshake_over_split_io() {
        let thresholds = RekeyThresholds::default();
        let (client_recv, server_send) = tokio::io::duplex(1024);
        let (server_recv, client_send) = tokio::io::duplex(1024);

        let config = TransportConfig::default().with_app_stream_id(9);
        let builder = TokioTransportBuilder::new().with_config(config);
        let client_builder = builder;

        let client_task = tokio::spawn({
            async move {
                client_builder
                    .establish_initiator_from_split(client_recv, client_send, thresholds)
                    .await
            }
        });

        let mut server = builder
            .establish_responder_from_split(server_recv, server_send, RekeyThresholds::default())
            .await
            .expect("server channel");
        let mut client = client_task
            .await
            .expect("client join")
            .expect("client channel");

        client
            .send_application(b"hello")
            .await
            .expect("client send");
        let msg = server.recv_application().await.expect("server recv");
        assert_eq!(msg, b"hello");
        assert_eq!(client.config().app_stream_id(), 9);
    }

    #[tokio::test]
    async fn establish_with_timeout_succeeds_when_peer_responds_in_time() {
        let thresholds = RekeyThresholds::default();
        let (client_recv, server_send) = tokio::io::duplex(1024);
        let (server_recv, client_send) = tokio::io::duplex(1024);

        let builder = TokioTransportBuilder::new();
        let client_task = tokio::spawn({
            let thresholds = thresholds.clone();
            async move {
                builder
                    .establish_initiator_with_timeout(
                        crate::adapter::SplitIo::from_split(client_recv, client_send),
                        thresholds,
                        std::time::Duration::from_secs(5),
                    )
                    .await
            }
        });

        let server = builder
            .establish_responder_with_timeout(
                crate::adapter::SplitIo::from_split(server_recv, server_send),
                thresholds,
                std::time::Duration::from_secs(5),
            )
            .await;
        assert!(server.is_ok());
        let client = client_task.await.expect("client join");
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn establish_with_timeout_fails_closed_when_peer_never_responds() {
        let thresholds = RekeyThresholds::default();
        // The responder side is never driven, so the initiator's "wait for
        // server hello" read never resolves; the handshake must time out
        // rather than hang forever.
        let (client_recv, _server_send) = tokio::io::duplex(1024);
        let (_server_recv, client_send) = tokio::io::duplex(1024);

        let builder = TokioTransportBuilder::new();
        let result = builder
            .establish_initiator_with_timeout(
                crate::adapter::SplitIo::from_split(client_recv, client_send),
                thresholds,
                std::time::Duration::from_millis(50),
            )
            .await;
        assert!(matches!(
            result,
            Err(foctet_core::CoreError::HandshakeTimeout)
                | Err(foctet_core::CoreError::Io(_))
                | Err(foctet_core::CoreError::UnexpectedEof)
        ));
    }

    #[tokio::test]
    async fn handshake_write_failures_discard_the_connection() {
        assert_handshake_write_failure(HandshakeWriteFailure::ErrorAfter(0), Some(0)).await;
        assert_handshake_write_failure(HandshakeWriteFailure::ErrorAfter(7), Some(7)).await;
        assert_handshake_write_failure(HandshakeWriteFailure::WriteZero, Some(0)).await;
        assert_handshake_write_failure(HandshakeWriteFailure::Flush, None).await;
        assert_handshake_write_failure(HandshakeWriteFailure::PeerClosed, None).await;
    }
}
