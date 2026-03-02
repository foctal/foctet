use std::{
    future::poll_fn,
    io::{Read, Write},
    pin::Pin,
};

use futures_core::Stream;
use futures_sink::Sink;

use crate::{
    CoreError, FoctetFramed, Session,
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
        (self.framed, self.session)
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
            app_stream_id: 0,
            app_flags: 0,
        })
    }

    /// Sends application data in an `APPLICATION_DATA` TLV with session-aware rekey handling.
    pub async fn send_data(&mut self, plaintext: &[u8]) -> Result<(), CoreError> {
        poll_fn(|cx| {
            let mut framed = Pin::new(&mut self.framed);
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

            framed.poll_flush(cx)
        })
        .await
    }

    /// Sends explicit TLVs with session-aware rekey handling.
    ///
    /// This bypasses `APPLICATION_DATA` convenience framing.
    pub async fn send_tlvs(&mut self, tlvs: &[Tlv]) -> Result<(), CoreError> {
        let payload = payload::encode_tlvs(tlvs)?;
        self.send_data(&payload).await
    }

    /// Receives the next application-data payload.
    ///
    /// Control frames are handled automatically. The method loops internally until
    /// it receives a non-control frame, then decodes TLVs and returns the first
    /// `APPLICATION_DATA` value.
    pub async fn recv_application(&mut self) -> Result<Vec<u8>, CoreError> {
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

    use crate::{ControlMessage, RekeyThresholds, Session};

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

        let (mut initiator, hello) = Session::new_initiator(thresholds.clone());
        let mut responder = Session::new_responder(thresholds);
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
        let (_initiator, hello) = Session::new_initiator(thresholds.clone());
        let mut responder = Session::new_responder(thresholds);
        let response = responder
            .handle_control(&hello)
            .expect("valid client hello")
            .expect("server hello");
        assert!(matches!(hello, ControlMessage::ClientHello { .. }));
        assert!(matches!(response, ControlMessage::ServerHello { .. }));
    }
}
