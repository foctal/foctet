use std::{
    future::{Future, poll_fn},
    pin::{Pin, pin},
    task::Poll,
};

use foctet_core::{
    AsyncSecureChannel, ControlMessage, CoreError, FoctetFramed, RekeyThresholds, Session,
    SessionAuthConfig, io::FuturesIo,
};
use futures_io::{AsyncRead, AsyncWrite};
use futures_sink::Sink;
use futures_util::{AsyncReadExt, AsyncWriteExt};

use crate::{TransportConfig, adapter::SplitIo};

const HANDSHAKE_CONTROL_MAX_LEN: usize = foctet_core::MAX_CONTROL_MESSAGE_LEN;

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
    #[cfg(feature = "dangerous-unauthenticated")]
    pub async fn establish_initiator<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
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
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = run_initiator_handshake(&mut io, thresholds, auth).await?;
        self.build(io, session)
    }

    /// Runs a production initiator handshake with typed authenticated config.
    pub async fn establish_production_initiator<T>(
        self,
        io: T,
        thresholds: RekeyThresholds,
        auth: foctet_core::ProductionSessionAuth,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        self.establish_initiator_with_auth(io, thresholds, auth.into_session_auth())
            .await
    }

    /// Runs the native Foctet handshake as responder on the transport, then builds a secure channel.
    #[cfg(feature = "dangerous-unauthenticated")]
    pub async fn establish_responder<T>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
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
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = run_responder_handshake(&mut io, thresholds, auth).await?;
        self.build(io, session)
    }

    /// Runs a production responder handshake with typed authenticated config.
    pub async fn establish_production_responder<T>(
        self,
        io: T,
        thresholds: RekeyThresholds,
        auth: foctet_core::ProductionSessionAuth,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        self.establish_responder_with_auth(io, thresholds, auth.into_session_auth())
            .await
    }

    /// Runs the native Foctet handshake as initiator with explicit authentication
    /// config, bounded by a caller-supplied `timeout` future.
    ///
    /// Because this builder is runtime-agnostic, the deadline is provided as a
    /// future rather than a `Duration`: pass `tokio::time::sleep(dur)`,
    /// `async_io::Timer::after(dur)`, a browser timer, or any future that
    /// resolves when the handshake should be abandoned. If `timeout` resolves
    /// before the handshake completes, this fails with
    /// [`CoreError::HandshakeTimeout`] and the transport is dropped.
    pub async fn establish_initiator_with_auth_and_timeout<T, F>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
        timeout: F,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        F: Future<Output = ()>,
    {
        let session =
            run_with_timeout(run_initiator_handshake(&mut io, thresholds, auth), timeout).await?;
        self.build(io, session)
    }

    /// Runs the native Foctet handshake as responder with explicit authentication
    /// config, bounded by a caller-supplied `timeout` future.
    ///
    /// See [`Self::establish_initiator_with_auth_and_timeout`] for how the
    /// runtime-agnostic timeout future is supplied.
    pub async fn establish_responder_with_auth_and_timeout<T, F>(
        self,
        mut io: T,
        thresholds: RekeyThresholds,
        auth: SessionAuthConfig,
        timeout: F,
    ) -> Result<FuturesTransportChannel<T>, CoreError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        F: Future<Output = ()>,
    {
        let session =
            run_with_timeout(run_responder_handshake(&mut io, thresholds, auth), timeout).await?;
        self.build(io, session)
    }

    /// Runs the native Foctet handshake as initiator on split transport halves, then builds a secure channel.
    #[cfg(feature = "dangerous-unauthenticated")]
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
    #[cfg(feature = "dangerous-unauthenticated")]
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

/// Drives `work` to completion, but resolves to [`CoreError::HandshakeTimeout`]
/// if `timer` completes first. Runtime-agnostic: `timer` is any future, so the
/// caller supplies the deadline source.
async fn run_with_timeout<W, F>(work: W, timer: F) -> Result<Session, CoreError>
where
    W: Future<Output = Result<Session, CoreError>>,
    F: Future<Output = ()>,
{
    let mut work = pin!(work);
    let mut timer = pin!(timer);
    poll_fn(move |cx| {
        // Poll the handshake first so a handshake that is already complete wins
        // even if the timer is also ready in the same poll.
        if let Poll::Ready(result) = work.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(CoreError::HandshakeTimeout));
        }
        Poll::Pending
    })
    .await
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

    /// Immediately performs one fail-closed transactional rekey.
    pub async fn rekey_now(&mut self) -> Result<(), CoreError> {
        self.inner.rekey_now().await
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use std::task::Context;

    /// A futures-io transport whose writes succeed instantly but whose reads
    /// never produce data, so any handshake stalls waiting for the peer's reply.
    #[derive(Debug)]
    struct StalledIo;

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

    impl AsyncRead for StalledIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for StalledIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for FailingHandshakeIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            match self.failure {
                HandshakeWriteFailure::PeerClosed => Poll::Ready(Ok(0)),
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

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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

        let result = FuturesTransportBuilder::new()
            .establish_initiator_with_auth(
                io,
                RekeyThresholds::default(),
                SessionAuthConfig::unauthenticated_for_testing(),
            )
            .await;
        assert!(matches!(result, Err(CoreError::Io(_))));
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

    #[tokio::test]
    async fn initiator_handshake_times_out_when_timer_fires_first() {
        // An already-ready timer must abort the stalled handshake.
        let err = FuturesTransportBuilder::new()
            .establish_initiator_with_auth_and_timeout(
                StalledIo,
                RekeyThresholds::default(),
                SessionAuthConfig::unauthenticated_for_testing(),
                std::future::ready(()),
            )
            .await
            .expect_err("stalled handshake must time out");
        assert!(matches!(err, CoreError::HandshakeTimeout));
    }

    #[tokio::test]
    async fn responder_handshake_times_out_when_timer_fires_first() {
        let err = FuturesTransportBuilder::new()
            .establish_responder_with_auth_and_timeout(
                StalledIo,
                RekeyThresholds::default(),
                SessionAuthConfig::unauthenticated_for_testing(),
                std::future::ready(()),
            )
            .await
            .expect_err("stalled handshake must time out");
        assert!(matches!(err, CoreError::HandshakeTimeout));
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
