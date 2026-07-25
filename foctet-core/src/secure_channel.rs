use std::{
    future::poll_fn,
    io::{Read, Write},
    pin::Pin,
};

use futures_core::Stream;
use futures_sink::Sink;

use crate::{
    CoreError, FoctetFramed, PreparedRekey, Session,
    io::SyncIo,
    payload::{self, Tlv, tlv_type},
};

/// High-level blocking facade that combines `Session`, `SyncIo`, and TLV helpers.
///
/// This wrapper is intended for the common case where callers want:
/// - automatic session-aware control/rekey handling
/// - application-data TLV framing by default
/// - a simple send/receive application-data API
#[derive(Debug)]
pub struct SecureChannel<T> {
    io: SyncIo<T>,
    session: Session,
    app_stream_id: u32,
    app_flags: u8,
}

/// High-level async facade that combines `Session`, `FoctetFramed`, and TLV helpers.
///
/// This wrapper is intended for async runtimes where callers want:
/// - automatic session-aware control/rekey handling
/// - application-data TLV framing by default
/// - an async send/receive application-data API
#[derive(Debug)]
pub struct AsyncSecureChannel<T> {
    framed: FoctetFramed<T>,
    session: Session,
    pending_rekey: Option<PreparedRekey>,
    pending_rekey_enqueued: bool,
    app_stream_id: u32,
    app_flags: u8,
}

impl<T: Read + Write> SecureChannel<T> {
    /// Constructs a secure channel from an active session.
    ///
    /// The session must already be in `Active` state with derived traffic keys.
    pub fn from_active_session(io: T, session: Session) -> Result<Self, CoreError> {
        let active_keys = session
            .active_keys()
            .ok_or(CoreError::InvalidSessionState)?;
        let inbound = session.inbound_direction();
        let outbound = session.outbound_direction();

        Ok(Self {
            io: SyncIo::new(io, active_keys, inbound, outbound),
            session,
            app_stream_id: 0,
            app_flags: 0,
        })
    }

    /// Sets the default stream ID for application-data frames.
    pub fn with_app_stream_id(mut self, stream_id: u32) -> Self {
        self.app_stream_id = stream_id;
        self
    }

    /// Sets the default plaintext frame flags for application-data frames.
    pub fn with_app_flags(mut self, flags: u8) -> Self {
        self.app_flags = flags;
        self
    }

    /// Returns immutable reference to the underlying `Session`.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Returns mutable reference to the underlying `Session`.
    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    /// Sends application data in an `APPLICATION_DATA` TLV with session-aware rekey handling.
    pub fn send_data(&mut self, plaintext: &[u8]) -> Result<(), CoreError> {
        self.io.send_data_with_session(
            &mut self.session,
            self.app_flags,
            self.app_stream_id,
            plaintext,
        )
    }

    /// Sends explicit TLVs with session-aware rekey handling.
    ///
    /// This bypasses `APPLICATION_DATA` convenience framing.
    pub fn send_tlvs(&mut self, tlvs: &[Tlv]) -> Result<(), CoreError> {
        let payload = payload::encode_tlvs(tlvs)?;
        self.io.send_data_with_session(
            &mut self.session,
            self.app_flags,
            self.app_stream_id,
            &payload,
        )
    }

    /// Immediately performs one transactional DH-ratchet rekey.
    ///
    /// The control frame is written and flushed under the old traffic key
    /// before the session commits the new key. An ambiguous I/O failure closes
    /// both the transport and session.
    pub fn rekey_now(&mut self) -> Result<(), CoreError> {
        let prepared = self.session.prepare_rekey()?;
        if let Err(error) =
            self.io
                .send_control_with_key_id(0, prepared.old_key_id(), prepared.control_message())
        {
            if self.io.is_terminal() {
                self.session.terminate();
            } else if let Err(cancel_error) = self.session.cancel_prepared_rekey(prepared) {
                self.io.terminate();
                return Err(cancel_error);
            }
            return Err(error);
        }
        if let Err(error) = self.session.commit_rekey(prepared) {
            self.io.terminate();
            self.session.terminate();
            return Err(error);
        }
        let keys = match self.session.active_keys() {
            Some(keys) => keys,
            None => {
                self.io.terminate();
                self.session.terminate();
                return Err(CoreError::InvalidSessionState);
            }
        };
        self.io.install_active_keys(keys);
        Ok(())
    }

    /// Receives the next application-data payload.
    ///
    /// Control frames are handled automatically. The method loops internally until
    /// it receives a non-control frame, then decodes TLVs and returns the first
    /// `APPLICATION_DATA` value.
    pub fn recv_application(&mut self) -> Result<Vec<u8>, CoreError> {
        loop {
            let Some(plaintext) = self.io.recv_application_with_session(&mut self.session)? else {
                continue;
            };

            let tlvs = payload::decode_tlvs(&plaintext)?;
            let app = tlvs
                .iter()
                .find(|t| t.typ == tlv_type::APPLICATION_DATA)
                .ok_or(CoreError::InvalidTlv)?;
            return Ok(app.value.clone());
        }
    }

    /// Receives the next non-control frame and returns decoded TLVs.
    pub fn recv_tlvs(&mut self) -> Result<Vec<Tlv>, CoreError> {
        loop {
            let Some(plaintext) = self.io.recv_application_with_session(&mut self.session)? else {
                continue;
            };
            return payload::decode_tlvs(&plaintext);
        }
    }

    /// Consumes the wrapper and returns `(io, session)`.
    pub fn into_parts(self) -> (T, Session) {
        (self.io.into_inner(), self.session)
    }
}

impl<T> AsyncSecureChannel<T> {
    /// Sets the default stream ID for application-data frames.
    pub fn with_app_stream_id(mut self, stream_id: u32) -> Self {
        self.app_stream_id = stream_id;
        self
    }

    /// Sets the default plaintext frame flags for application-data frames.
    pub fn with_app_flags(mut self, flags: u8) -> Self {
        self.app_flags = flags;
        self
    }

    /// Returns immutable reference to the underlying `Session`.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Returns mutable reference to the underlying `Session`.
    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    /// Returns immutable reference to inner framed transport.
    pub fn framed_ref(&self) -> &FoctetFramed<T> {
        &self.framed
    }

    /// Returns mutable reference to inner framed transport.
    pub fn framed_mut(&mut self) -> &mut FoctetFramed<T> {
        &mut self.framed
    }

    /// Consumes the wrapper and returns `(framed, session)`.
    pub fn into_parts(self) -> (FoctetFramed<T>, Session) {
        let mut this = self;
        if this.pending_rekey.is_some() {
            this.framed.terminate();
            this.session.terminate();
        }
        (this.framed, this.session)
    }
}

impl<T: crate::io::PollIo + Unpin> AsyncSecureChannel<T> {
    /// Constructs an async secure channel from an active session.
    ///
    /// The session must already be in `Active` state with derived traffic keys.
    pub fn from_active_session(io: T, session: Session) -> Result<Self, CoreError> {
        let active_keys = session
            .active_keys()
            .ok_or(CoreError::InvalidSessionState)?;
        let inbound = session.inbound_direction();
        let outbound = session.outbound_direction();
        let framed = FoctetFramed::new(io, active_keys, inbound, outbound);

        Ok(Self {
            framed,
            session,
            pending_rekey: None,
            pending_rekey_enqueued: false,
            app_stream_id: 0,
            app_flags: 0,
        })
    }

    /// Sends application data in an `APPLICATION_DATA` TLV with session-aware rekey handling.
    pub async fn send_data(&mut self, plaintext: &[u8]) -> Result<(), CoreError> {
        if self.pending_rekey.is_some() {
            return Err(CoreError::RekeyInProgress);
        }
        // The frame must be encrypted and enqueued exactly once. This closure
        // is re-polled from the top whenever the flush below returns
        // `Pending`, so without the `queued` latch the same plaintext would be
        // re-encrypted under the next sequence number and sent again — a
        // silent duplicate delivery on any transport whose flush can suspend.
        let mut queued = false;
        let result = poll_fn(|cx| {
            let mut framed = Pin::new(&mut self.framed);
            if !queued {
                match framed.as_mut().poll_ready(cx) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(())) => {}
                }

                framed.as_mut().start_send_data_with_session(
                    &mut self.session,
                    self.app_flags,
                    self.app_stream_id,
                    plaintext,
                )?;
                queued = true;
            }

            framed.poll_flush(cx)
        })
        .await;
        if result.is_err() && self.framed.is_terminal() {
            self.session.terminate();
        }
        result
    }

    /// Sends explicit TLVs with session-aware rekey handling.
    ///
    /// This bypasses `APPLICATION_DATA` convenience framing.
    pub async fn send_tlvs(&mut self, tlvs: &[Tlv]) -> Result<(), CoreError> {
        let payload = payload::encode_tlvs(tlvs)?;
        self.send_data(&payload).await
    }

    /// Immediately performs one transactional DH-ratchet rekey.
    ///
    /// The exact old-key control frame is flushed before the session commits
    /// the new key. A rejected enqueue leaves the session unchanged; an
    /// ambiguous write or flush failure closes both objects.
    pub async fn rekey_now(&mut self) -> Result<(), CoreError> {
        if self.pending_rekey.is_none() {
            self.pending_rekey = Some(self.session.prepare_rekey()?);
            self.pending_rekey_enqueued = false;
        }

        if !self.pending_rekey_enqueued {
            let prepared = self
                .pending_rekey
                .as_ref()
                .ok_or(CoreError::InvalidSessionState)?;
            let old_key_id = prepared.old_key_id();
            let control = prepared.control_message().clone();
            let enqueue_result = poll_fn(|cx| {
                let mut framed = Pin::new(&mut self.framed);
                match framed.as_mut().poll_ready(cx) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(error)) => {
                        return std::task::Poll::Ready(Err(error));
                    }
                    std::task::Poll::Ready(Ok(())) => {}
                }
                std::task::Poll::Ready(
                    framed.start_send_control_with_key_id(0, old_key_id, &control),
                )
            })
            .await;
            if let Err(error) = enqueue_result {
                let prepared = self
                    .pending_rekey
                    .take()
                    .ok_or(CoreError::InvalidSessionState)?;
                if self.framed.is_terminal() {
                    self.session.terminate();
                } else if let Err(cancel_error) = self.session.cancel_prepared_rekey(prepared) {
                    self.framed.terminate();
                    return Err(cancel_error);
                }
                return Err(error);
            }
            self.pending_rekey_enqueued = true;
        }

        if let Err(error) = poll_fn(|cx| Pin::new(&mut self.framed).poll_flush(cx)).await {
            self.pending_rekey = None;
            self.pending_rekey_enqueued = false;
            self.session.terminate();
            return Err(error);
        }
        let prepared = self
            .pending_rekey
            .take()
            .ok_or(CoreError::InvalidSessionState)?;
        self.pending_rekey_enqueued = false;
        if let Err(error) = self.session.commit_rekey(prepared) {
            self.framed.terminate();
            self.session.terminate();
            return Err(error);
        }
        let keys = match self.session.active_keys() {
            Some(keys) => keys,
            None => {
                self.framed.terminate();
                self.session.terminate();
                return Err(CoreError::InvalidSessionState);
            }
        };
        self.framed.install_active_keys(keys);
        Ok(())
    }

    /// Receives the next application-data payload.
    ///
    /// Control frames are handled automatically. The method loops internally until
    /// it receives a non-control frame, then decodes TLVs and returns the first
    /// `APPLICATION_DATA` value.
    pub async fn recv_application(&mut self) -> Result<Vec<u8>, CoreError> {
        if self.pending_rekey.is_some() {
            return Err(CoreError::RekeyInProgress);
        }
        loop {
            let item = poll_fn(|cx| Pin::new(&mut self.framed).poll_next(cx)).await;
            let decoded = match item {
                Some(Ok(frame)) => frame,
                Some(Err(e)) => return Err(e),
                None => return Err(CoreError::UnexpectedEof),
            };

            if let Some(plaintext) = Pin::new(&mut self.framed)
                .handle_incoming_with_session(&mut self.session, decoded)?
            {
                let tlvs = payload::decode_tlvs(&plaintext)?;
                let app = tlvs
                    .iter()
                    .find(|t| t.typ == tlv_type::APPLICATION_DATA)
                    .ok_or(CoreError::InvalidTlv)?;
                return Ok(app.value.clone());
            }
        }
    }

    /// Receives the next non-control frame and returns decoded TLVs.
    pub async fn recv_tlvs(&mut self) -> Result<Vec<Tlv>, CoreError> {
        if self.pending_rekey.is_some() {
            return Err(CoreError::RekeyInProgress);
        }
        loop {
            let item = poll_fn(|cx| Pin::new(&mut self.framed).poll_next(cx)).await;
            let decoded = match item {
                Some(Ok(frame)) => frame,
                Some(Err(e)) => return Err(e),
                None => return Err(CoreError::UnexpectedEof),
            };

            if let Some(plaintext) = Pin::new(&mut self.framed)
                .handle_incoming_with_session(&mut self.session, decoded)?
            {
                return payload::decode_tlvs(&plaintext);
            }
        }
    }
}

#[cfg(feature = "runtime-tokio")]
impl<T> AsyncSecureChannel<crate::io::TokioIo<T>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Constructs async secure channel from a Tokio I/O object and an active session.
    pub fn from_tokio(io: T, session: Session) -> Result<Self, CoreError> {
        Self::from_active_session(crate::io::TokioIo::new(io), session)
    }
}

#[cfg(feature = "runtime-futures")]
impl<T> AsyncSecureChannel<crate::io::FuturesIo<T>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    /// Constructs async secure channel from a futures-io object and an active session.
    pub fn from_futures(io: T, session: Session) -> Result<Self, CoreError> {
        Self::from_active_session(crate::io::FuturesIo::new(io), session)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::{Read, Write},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use crate::{ControlMessage, RekeyThresholds, Session, SessionAuthConfig};

    use super::SecureChannel;

    #[derive(Clone, Debug)]
    struct MemPipe {
        rx: Arc<Mutex<VecDeque<u8>>>,
        tx: Arc<Mutex<VecDeque<u8>>>,
    }

    impl MemPipe {
        fn pair() -> (Self, Self) {
            let a_rx = Arc::new(Mutex::new(VecDeque::new()));
            let b_rx = Arc::new(Mutex::new(VecDeque::new()));
            (
                Self {
                    rx: Arc::clone(&a_rx),
                    tx: Arc::clone(&b_rx),
                },
                Self { rx: b_rx, tx: a_rx },
            )
        }
    }

    impl Read for MemPipe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut rx = self.rx.lock().expect("lock rx");
            let n = buf.len().min(rx.len());
            for slot in buf.iter_mut().take(n) {
                *slot = rx.pop_front().expect("rx byte");
            }
            Ok(n)
        }
    }

    impl Write for MemPipe {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut tx = self.tx.lock().expect("lock tx");
            tx.extend(buf.iter().copied());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn make_session_pair() -> (Session, Session) {
        let thresholds = RekeyThresholds {
            max_frames: 1,
            max_bytes: 1 << 30,
            max_age: Duration::from_secs(3600),
            max_previous_keys: 2,
        };

        let (mut initiator, hello) = Session::new_initiator_with_auth(
            thresholds.clone(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut responder = Session::new_responder_with_auth(
            thresholds,
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let server_hello = responder
            .handle_control(&hello)
            .expect("responder handle client hello")
            .expect("server hello");
        let none = initiator
            .handle_control(&server_hello)
            .expect("initiator handle server hello");
        assert!(none.is_none());
        (initiator, responder)
    }

    #[test]
    fn secure_channel_roundtrip_and_rekey() {
        let (a_io, b_io) = MemPipe::pair();
        let (a_session, b_session) = make_session_pair();

        let mut client = SecureChannel::from_active_session(a_io, a_session)
            .expect("client channel")
            .with_app_stream_id(7);
        let mut server = SecureChannel::from_active_session(b_io, b_session)
            .expect("server channel")
            .with_app_stream_id(7);

        client.send_data(b"hello-1").expect("send 1");
        let m1 = server.recv_application().expect("recv 1");
        assert_eq!(m1, b"hello-1");

        // max_frames=1 triggers rekey after first app payload.
        client.send_data(b"hello-2").expect("send 2");
        let m2 = server.recv_application().expect("recv 2");
        assert_eq!(m2, b"hello-2");
    }

    #[test]
    fn explicit_rekey_is_delivered_before_the_new_key_is_used() {
        let (a_io, b_io) = MemPipe::pair();
        let (a_session, b_session) = make_session_pair();
        let mut client =
            SecureChannel::from_active_session(a_io, a_session).expect("client channel");
        let mut server =
            SecureChannel::from_active_session(b_io, b_session).expect("server channel");

        client.rekey_now().expect("transactional rekey");
        assert_eq!(
            client.session().active_keys().expect("client key").key_id,
            1
        );

        client
            .send_data(b"new-key payload")
            .expect("send after rekey");
        assert_eq!(
            server.recv_application().expect("receive after rekey"),
            b"new-key payload"
        );
        assert_eq!(
            server.session().active_keys().expect("server key").key_id,
            1
        );
    }

    #[test]
    fn secure_channel_rejects_non_active_session() {
        let (io, _peer) = MemPipe::pair();
        let thresholds = RekeyThresholds::default();
        let responder = Session::new_responder(thresholds);
        let err = SecureChannel::from_active_session(io, responder)
            .expect_err("must reject non-active session");
        assert!(matches!(err, crate::CoreError::InvalidSessionState));
    }

    #[test]
    fn handshake_exchange_is_control_messages() {
        let thresholds = RekeyThresholds::default();
        let (_initiator, hello) = Session::new_initiator_with_auth(
            thresholds.clone(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut responder = Session::new_responder_with_auth(
            thresholds,
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let response = responder
            .handle_control(&hello)
            .expect("valid client hello")
            .expect("server hello");
        assert!(matches!(hello, ControlMessage::ClientHello { .. }));
        assert!(matches!(response, ControlMessage::ServerHello { .. }));
    }

    mod async_send {
        use std::{
            collections::VecDeque,
            future::Future,
            pin::{Pin, pin},
            task::{Context, Poll, Waker},
        };

        use crate::io::{PollRead, PollWrite};
        use crate::{RekeyThresholds, Session, SessionAuthConfig};

        use super::super::AsyncSecureChannel;

        /// Session pair with default thresholds so no rekey control frames
        /// interleave with the single application payload under test.
        fn quiet_session_pair() -> (Session, Session) {
            let (mut initiator, hello) = Session::new_initiator_with_auth(
                RekeyThresholds::default(),
                SessionAuthConfig::unauthenticated_for_testing(),
            );
            let mut responder = Session::new_responder_with_auth(
                RekeyThresholds::default(),
                SessionAuthConfig::unauthenticated_for_testing(),
            );
            let server_hello = responder
                .handle_control(&hello)
                .expect("responder handles hello")
                .expect("server hello");
            initiator
                .handle_control(&server_hello)
                .expect("initiator finalizes");
            (initiator, responder)
        }

        /// In-memory `PollIo` whose flush suspends a configurable number of
        /// times before completing, like a transport that waits for a flush
        /// acknowledgement (e.g. a multiplexed WebSocket stream).
        #[derive(Default, Debug)]
        struct SlowFlushIo {
            inbound: VecDeque<u8>,
            outbound: Vec<u8>,
            pending_flushes: usize,
            fail_flush: bool,
        }

        impl PollRead for SlowFlushIo {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                let n = buf.len().min(self.inbound.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = self.inbound.pop_front().expect("inbound byte");
                }
                Poll::Ready(Ok(n))
            }
        }

        impl PollWrite for SlowFlushIo {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.outbound.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                if self.pending_flushes > 0 {
                    self.pending_flushes -= 1;
                    return Poll::Pending;
                }
                if self.fail_flush {
                    return Poll::Ready(Err(std::io::Error::other("injected flush failure")));
                }
                Poll::Ready(Ok(()))
            }

            fn poll_close(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        /// Regression test: `send_data` must encrypt and enqueue the payload
        /// exactly once even when the transport flush suspends, forcing the
        /// send future to be polled multiple times. A latch bug here once
        /// re-encrypted the plaintext under the next sequence number on every
        /// re-poll, silently delivering duplicates (caught by the websock-mux
        /// byte-stream conformance test).
        #[test]
        fn send_data_is_not_duplicated_when_flush_suspends() {
            let (initiator, responder) = quiet_session_pair();

            let sender_io = SlowFlushIo {
                pending_flushes: 3,
                ..SlowFlushIo::default()
            };
            let mut sender = AsyncSecureChannel::from_active_session(sender_io, initiator)
                .expect("sender channel");

            let waker = Waker::noop().clone();
            let mut cx = Context::from_waker(&waker);

            {
                let mut fut = pin!(sender.send_data(b"ping"));
                // The first polls suspend in flush; the payload must stay queued,
                // not be re-encrypted.
                for _ in 0..3 {
                    assert!(fut.as_mut().poll(&mut cx).is_pending());
                }
                match fut.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(())) => {}
                    other => panic!("expected send completion, got {other:?}"),
                }
            }
            let wire = sender.framed_ref().get_ref().outbound.clone();

            let receiver_io = SlowFlushIo::default();
            let mut receiver = AsyncSecureChannel::from_active_session(receiver_io, responder)
                .expect("receiver channel");
            receiver
                .framed_mut()
                .get_mut()
                .inbound
                .extend(wire.iter().copied());

            {
                let mut recv = pin!(receiver.recv_application());
                match recv.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(payload)) => assert_eq!(payload, b"ping"),
                    other => panic!("expected one payload, got {other:?}"),
                }
            }

            // Exactly one frame must have been sent: the next read hits EOF
            // instead of a duplicate "ping" under a fresh sequence number.
            {
                let mut next = pin!(receiver.recv_application());
                match next.as_mut().poll(&mut cx) {
                    Poll::Ready(Err(crate::CoreError::UnexpectedEof)) => {}
                    other => panic!("expected EOF after the single frame, got {other:?}"),
                }
            }
        }

        #[test]
        fn automatic_rekey_flush_failure_closes_the_paired_session() {
            let thresholds = RekeyThresholds {
                max_frames: 1,
                max_bytes: u64::MAX,
                max_age: std::time::Duration::MAX,
                max_previous_keys: 2,
            };
            let (mut initiator, hello) = Session::new_initiator_with_auth(
                thresholds.clone(),
                SessionAuthConfig::unauthenticated_for_testing(),
            );
            let mut responder = Session::new_responder_with_auth(
                thresholds,
                SessionAuthConfig::unauthenticated_for_testing(),
            );
            let server_hello = responder
                .handle_control(&hello)
                .expect("responder handles hello")
                .expect("server hello");
            initiator
                .handle_control(&server_hello)
                .expect("initiator finalizes");

            let io = SlowFlushIo {
                fail_flush: true,
                ..SlowFlushIo::default()
            };
            let mut sender =
                AsyncSecureChannel::from_active_session(io, initiator).expect("sender channel");
            let waker = Waker::noop().clone();
            let mut cx = Context::from_waker(&waker);

            {
                let mut send = pin!(sender.send_data(b"triggers rekey"));
                assert!(matches!(
                    send.as_mut().poll(&mut cx),
                    Poll::Ready(Err(crate::CoreError::Io(_)))
                ));
            }

            assert!(sender.framed_ref().is_terminal());
            assert_eq!(sender.session().state(), crate::SessionState::Closed);
            assert!(sender.session().active_keys().is_none());
        }

        #[test]
        fn explicit_async_rekey_commits_only_after_flush() {
            let (initiator, responder) = quiet_session_pair();
            let sender_io = SlowFlushIo {
                pending_flushes: 1,
                ..SlowFlushIo::default()
            };
            let mut sender = AsyncSecureChannel::from_active_session(sender_io, initiator)
                .expect("sender channel");
            let waker = Waker::noop().clone();
            let mut cx = Context::from_waker(&waker);

            {
                let mut rekey = pin!(sender.rekey_now());
                assert!(rekey.as_mut().poll(&mut cx).is_pending());
                match rekey.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(())) => {}
                    other => panic!("expected rekey completion, got {other:?}"),
                }
            }
            assert_eq!(
                sender.session().active_keys().expect("sender key").key_id,
                1
            );

            let wire = sender.framed_ref().get_ref().outbound.clone();
            let mut receiver = AsyncSecureChannel::from_active_session(
                SlowFlushIo {
                    inbound: wire.into_iter().collect(),
                    ..SlowFlushIo::default()
                },
                responder,
            )
            .expect("receiver channel");
            {
                let mut receive = pin!(receiver.recv_application());
                assert!(matches!(
                    receive.as_mut().poll(&mut cx),
                    Poll::Ready(Err(crate::CoreError::UnexpectedEof))
                ));
            }
            assert_eq!(
                receiver
                    .session()
                    .active_keys()
                    .expect("receiver key")
                    .key_id,
                1
            );
        }

        #[test]
        fn cancelled_async_rekey_resumes_the_same_transaction() {
            let (initiator, _responder) = quiet_session_pair();
            let sender_io = SlowFlushIo {
                pending_flushes: 1,
                ..SlowFlushIo::default()
            };
            let mut sender = AsyncSecureChannel::from_active_session(sender_io, initiator)
                .expect("sender channel");
            let waker = Waker::noop().clone();
            let mut cx = Context::from_waker(&waker);

            {
                let mut rekey = pin!(sender.rekey_now());
                assert!(rekey.as_mut().poll(&mut cx).is_pending());
            }
            assert_eq!(
                sender.session().active_keys().expect("old key").key_id,
                0,
                "cancelled future must not commit before flush"
            );

            {
                let mut send = pin!(sender.send_data(b"must wait for rekey"));
                assert!(matches!(
                    send.as_mut().poll(&mut cx),
                    Poll::Ready(Err(crate::CoreError::RekeyInProgress))
                ));
            }

            {
                let mut resumed = pin!(sender.rekey_now());
                assert!(matches!(
                    resumed.as_mut().poll(&mut cx),
                    Poll::Ready(Ok(()))
                ));
            }
            assert_eq!(sender.session().active_keys().expect("new key").key_id, 1);
        }

        #[test]
        fn explicit_async_rekey_flush_failure_closes_the_session() {
            let (initiator, _responder) = quiet_session_pair();
            let io = SlowFlushIo {
                fail_flush: true,
                ..SlowFlushIo::default()
            };
            let mut sender =
                AsyncSecureChannel::from_active_session(io, initiator).expect("sender channel");
            let waker = Waker::noop().clone();
            let mut cx = Context::from_waker(&waker);

            {
                let mut rekey = pin!(sender.rekey_now());
                assert!(matches!(
                    rekey.as_mut().poll(&mut cx),
                    Poll::Ready(Err(crate::CoreError::Io(_)))
                ));
            }

            assert!(sender.framed_ref().is_terminal());
            assert_eq!(sender.session().state(), crate::SessionState::Closed);
            assert!(sender.session().active_keys().is_none());
        }
    }
}
