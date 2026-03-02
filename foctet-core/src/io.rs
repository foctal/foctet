use std::{
    io::{Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    CoreError,
    control::ControlMessage,
    crypto::{Direction, TrafficKeys, decrypt_frame_with_key, encrypt_frame},
    frame::{FRAME_HEADER_LEN, Frame, FrameHeader},
    payload::{self, Tlv},
    replay::{DEFAULT_REPLAY_WINDOW, ReplayProtector},
    session::Session,
};

#[cfg(any(feature = "runtime-tokio", feature = "runtime-futures"))]
use crate::frame::{FoctetFramed, FoctetStream};

/// Minimal poll-based read trait used by Foctet runtime adapters.
pub trait PollRead {
    /// Attempts to read bytes into `buf`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>>;
}

/// Minimal poll-based write trait used by Foctet runtime adapters.
pub trait PollWrite {
    /// Attempts to write bytes from `buf`.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>>;
    /// Flushes pending writes.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>;
    /// Closes the writer side.
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>;
}

/// Combined poll-based I/O trait.
pub trait PollIo: PollRead + PollWrite {}

impl<T: PollRead + PollWrite> PollIo for T {}

/// Tokio adapter implementing [`PollRead`] and [`PollWrite`].
#[cfg(feature = "runtime-tokio")]
#[derive(Debug, Clone)]
pub struct TokioIo<T> {
    inner: T,
}

#[cfg(feature = "runtime-tokio")]
impl<T> TokioIo<T> {
    /// Wraps a Tokio I/O object.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Unwraps and returns the inner Tokio I/O object.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[cfg(feature = "runtime-tokio")]
impl<T> PollRead for TokioIo<T>
where
    T: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut read_buf = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(feature = "runtime-tokio")]
impl<T> PollWrite for TokioIo<T>
where
    T: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Futures-io adapter implementing [`PollRead`] and [`PollWrite`].
#[cfg(feature = "runtime-futures")]
#[derive(Debug, Clone)]
pub struct FuturesIo<T> {
    inner: T,
}

#[cfg(feature = "runtime-futures")]
impl<T> FuturesIo<T> {
    /// Wraps a futures-io object.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Unwraps and returns the inner futures-io object.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[cfg(feature = "runtime-futures")]
impl<T> PollRead for FuturesIo<T>
where
    T: futures_io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "runtime-futures")]
impl<T> PollWrite for FuturesIo<T>
where
    T: futures_io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(feature = "runtime-tokio")]
impl<T> FoctetFramed<TokioIo<T>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Constructs [`FoctetFramed`] from Tokio async I/O.
    pub fn from_tokio(
        io: T,
        keys: TrafficKeys,
        inbound_direction: Direction,
        outbound_direction: Direction,
    ) -> Self {
        Self::new(
            TokioIo::new(io),
            keys,
            inbound_direction,
            outbound_direction,
        )
    }
}

#[cfg(feature = "runtime-futures")]
impl<T> FoctetFramed<FuturesIo<T>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    /// Constructs [`FoctetFramed`] from futures-io async I/O.
    pub fn from_futures(
        io: T,
        keys: TrafficKeys,
        inbound_direction: Direction,
        outbound_direction: Direction,
    ) -> Self {
        Self::new(
            FuturesIo::new(io),
            keys,
            inbound_direction,
            outbound_direction,
        )
    }
}

#[cfg(feature = "runtime-tokio")]
impl<T> FoctetStream<TokioIo<T>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Constructs [`FoctetStream`] from Tokio async I/O.
    pub fn from_tokio(
        io: T,
        keys: TrafficKeys,
        inbound_direction: Direction,
        outbound_direction: Direction,
    ) -> Self {
        let framed = FoctetFramed::from_tokio(io, keys, inbound_direction, outbound_direction);
        Self::new(framed)
    }
}

#[cfg(feature = "runtime-futures")]
impl<T> FoctetStream<FuturesIo<T>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    /// Constructs [`FoctetStream`] from futures-io async I/O.
    pub fn from_futures(
        io: T,
        keys: TrafficKeys,
        inbound_direction: Direction,
        outbound_direction: Direction,
    ) -> Self {
        let framed = FoctetFramed::from_futures(io, keys, inbound_direction, outbound_direction);
        Self::new(framed)
    }
}

#[cfg(feature = "runtime-tokio")]
impl<T> tokio::io::AsyncRead for FoctetStream<T>
where
    T: PollRead + PollWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let dst = buf.initialize_unfilled();
        match Pin::new(&mut *self).poll_read_plain(cx, dst) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }
}

#[cfg(feature = "runtime-tokio")]
impl<T> tokio::io::AsyncWrite for FoctetStream<T>
where
    T: PollRead + PollWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut *self).poll_write_plain(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut *self).poll_flush_plain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut *self).poll_close_plain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }
}

#[cfg(feature = "runtime-futures")]
impl<T> futures_io::AsyncRead for FoctetStream<T>
where
    T: PollRead + PollWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut *self).poll_read_plain(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }
}

#[cfg(feature = "runtime-futures")]
impl<T> futures_io::AsyncWrite for FoctetStream<T>
where
    T: PollRead + PollWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut *self).poll_write_plain(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut *self).poll_flush_plain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut *self).poll_close_plain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }
}

/// Blocking `Read + Write` adapter for Foctet framed transport.
#[derive(Debug)]
pub struct SyncIo<T> {
    io: T,
    keys: Vec<TrafficKeys>,
    active_key_id: u8,
    max_retained_keys: usize,
    inbound_direction: Direction,
    outbound_direction: Direction,
    default_stream_id: u32,
    default_flags: u8,
    next_seq: u64,
    max_ciphertext_len: usize,
    replay: ReplayProtector,
}

impl<T> SyncIo<T> {
    /// Creates a blocking Foctet transport wrapper.
    pub fn new(
        io: T,
        keys: TrafficKeys,
        inbound_direction: Direction,
        outbound_direction: Direction,
    ) -> Self {
        Self {
            io,
            active_key_id: keys.key_id,
            keys: vec![keys],
            max_retained_keys: 2,
            inbound_direction,
            outbound_direction,
            default_stream_id: 0,
            default_flags: 0,
            next_seq: 0,
            max_ciphertext_len: 16 * 1024 * 1024,
            replay: ReplayProtector::new(DEFAULT_REPLAY_WINDOW),
        }
    }

    /// Sets default stream ID for [`SyncIo::send`].
    pub fn with_stream_id(mut self, stream_id: u32) -> Self {
        self.default_stream_id = stream_id;
        self
    }

    /// Sets default frame flags for [`SyncIo::send`].
    pub fn with_default_flags(mut self, flags: u8) -> Self {
        self.default_flags = flags;
        self
    }

    /// Sets inbound ciphertext size limit.
    pub fn with_max_ciphertext_len(mut self, max_len: usize) -> Self {
        self.max_ciphertext_len = max_len;
        self
    }

    /// Sets number of retained previous keys.
    pub fn with_max_retained_keys(mut self, max: usize) -> Self {
        self.max_retained_keys = max.max(1);
        self
    }

    /// Returns current active key ID.
    pub fn active_key_id(&self) -> u8 {
        self.active_key_id
    }

    /// Returns known key IDs, active first.
    pub fn known_key_ids(&self) -> Vec<u8> {
        self.keys.iter().map(|k| k.key_id).collect()
    }

    /// Installs new active keys and retains previous keys.
    pub fn install_active_keys(&mut self, keys: TrafficKeys) {
        self.keys.retain(|k| k.key_id != keys.key_id);
        self.keys.insert(0, keys.clone());
        self.active_key_id = keys.key_id;
        let keep = self.max_retained_keys + 1;
        if self.keys.len() > keep {
            self.keys.truncate(keep);
        }
    }

    /// Consumes wrapper and returns underlying I/O object.
    pub fn into_inner(self) -> T {
        self.io
    }

    fn active_keys(&self) -> Result<&TrafficKeys, CoreError> {
        self.keys
            .iter()
            .find(|k| k.key_id == self.active_key_id)
            .ok_or(CoreError::MissingSessionSecret)
    }

    fn key_for_id(&self, key_id: u8) -> Option<&TrafficKeys> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }

    fn set_key_ring_from_session(&mut self, session: &Session) -> Result<(), CoreError> {
        let ring = session.key_ring()?;
        self.keys = ring;
        self.active_key_id = self
            .keys
            .first()
            .map(|k| k.key_id)
            .ok_or(CoreError::InvalidSessionState)?;
        let keep = self.max_retained_keys + 1;
        if self.keys.len() > keep {
            self.keys.truncate(keep);
        }
        Ok(())
    }
}

impl<T: Read + Write> SyncIo<T> {
    fn send_with_key(
        &mut self,
        keys: &TrafficKeys,
        flags: u8,
        stream_id: u32,
        plaintext: &[u8],
    ) -> Result<(), CoreError> {
        let frame = encrypt_frame(
            keys,
            self.outbound_direction,
            flags,
            stream_id,
            self.next_seq,
            plaintext,
        )?;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.io.write_all(&frame.to_bytes())?;
        self.io.flush()?;
        Ok(())
    }

    /// Sends plaintext using default flags and stream ID.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), CoreError> {
        self.send_with(self.default_flags, self.default_stream_id, plaintext)
    }

    /// Sends plaintext with explicit frame flags and stream ID.
    pub fn send_with(
        &mut self,
        flags: u8,
        stream_id: u32,
        plaintext: &[u8],
    ) -> Result<(), CoreError> {
        let active = self.active_keys()?.clone();
        self.send_with_key(&active, flags, stream_id, plaintext)
    }

    /// Sends TLV payload records as a single encrypted frame payload.
    pub fn send_tlvs_with(
        &mut self,
        flags: u8,
        stream_id: u32,
        tlvs: &[Tlv],
    ) -> Result<(), CoreError> {
        let payload = payload::encode_tlvs(tlvs)?;
        self.send_with(flags, stream_id, &payload)
    }

    /// Receives and decrypts one frame payload.
    pub fn recv(&mut self) -> Result<Vec<u8>, CoreError> {
        let mut header_buf = [0u8; FRAME_HEADER_LEN];
        self.io.read_exact(&mut header_buf)?;
        let header = FrameHeader::decode(&header_buf)?;
        header.validate_v0()?;

        let ct_len = header.ct_len as usize;
        if ct_len > self.max_ciphertext_len {
            return Err(CoreError::FrameTooLarge);
        }

        let mut ciphertext = vec![0u8; ct_len];
        self.io.read_exact(&mut ciphertext)?;

        self.replay
            .check_and_record(header.key_id, header.stream_id, header.seq)?;

        let keys = self
            .key_for_id(header.key_id)
            .ok_or(CoreError::UnexpectedKeyId {
                expected: self.active_key_id,
                actual: header.key_id,
            })?;

        let frame = Frame { header, ciphertext };
        decrypt_frame_with_key(keys, self.inbound_direction, &frame)
    }

    /// Sends one control message.
    pub fn send_control(&mut self, stream_id: u32, msg: &ControlMessage) -> Result<(), CoreError> {
        self.send_with(crate::frame::flags::IS_CONTROL, stream_id, &msg.encode())
    }

    /// Sends one control message using an explicit key ID.
    pub fn send_control_with_key_id(
        &mut self,
        stream_id: u32,
        key_id: u8,
        msg: &ControlMessage,
    ) -> Result<(), CoreError> {
        let key = self
            .key_for_id(key_id)
            .ok_or(CoreError::UnexpectedKeyId {
                expected: self.active_key_id,
                actual: key_id,
            })?
            .clone();
        self.send_with_key(
            &key,
            crate::frame::flags::IS_CONTROL,
            stream_id,
            &msg.encode(),
        )
    }

    /// Receives and decodes one control message.
    pub fn recv_control(&mut self) -> Result<ControlMessage, CoreError> {
        let plaintext = self.recv()?;
        ControlMessage::decode(&plaintext)
    }

    /// Receives and decodes TLV payload records.
    pub fn recv_tlvs(&mut self) -> Result<Vec<Tlv>, CoreError> {
        let plaintext = self.recv()?;
        payload::decode_tlvs(&plaintext)
    }

    /// Sends application payload and auto-handles session rekey controls.
    pub fn send_data_with_session(
        &mut self,
        session: &mut Session,
        flags: u8,
        stream_id: u32,
        plaintext: &[u8],
    ) -> Result<(), CoreError> {
        self.set_key_ring_from_session(session)?;
        let app_tlv = Tlv::application_data(plaintext)?;
        self.send_tlvs_with(flags, stream_id, &[app_tlv])?;

        if let Some(ctrl) = session.on_outbound_payload(plaintext.len())? {
            let rekey_old = match &ctrl {
                ControlMessage::Rekey { old_key_id, .. } => Some(*old_key_id),
                _ => None,
            };
            if let Some(old_key_id) = rekey_old {
                self.send_control_with_key_id(0, old_key_id, &ctrl)?;
                self.set_key_ring_from_session(session)?;
            } else {
                self.send_control(0, &ctrl)?;
            }
        }
        Ok(())
    }

    /// Receives next frame and applies session-aware control handling.
    pub fn recv_application_with_session(
        &mut self,
        session: &mut Session,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let mut header_buf = [0u8; FRAME_HEADER_LEN];
        self.io.read_exact(&mut header_buf)?;
        let header = FrameHeader::decode(&header_buf)?;
        header.validate_v0()?;

        let ct_len = header.ct_len as usize;
        if ct_len > self.max_ciphertext_len {
            return Err(CoreError::FrameTooLarge);
        }

        let mut ciphertext = vec![0u8; ct_len];
        self.io.read_exact(&mut ciphertext)?;

        self.replay
            .check_and_record(header.key_id, header.stream_id, header.seq)?;

        let keys = self
            .key_for_id(header.key_id)
            .ok_or(CoreError::UnexpectedKeyId {
                expected: self.active_key_id,
                actual: header.key_id,
            })?;

        let frame = Frame { header, ciphertext };
        let plaintext = decrypt_frame_with_key(keys, self.inbound_direction, &frame)?;

        if frame.header.flags & crate::frame::flags::IS_CONTROL != 0 {
            let msg = ControlMessage::decode(&plaintext)?;
            let response = session.handle_control(&msg)?;
            self.set_key_ring_from_session(session)?;
            if let Some(resp) = response {
                self.send_control(0, &resp)?;
            }
            return Ok(None);
        }

        Ok(Some(plaintext))
    }
}

impl From<CoreError> for std::io::Error {
    fn from(value: CoreError) -> Self {
        std::io::Error::other(value)
    }
}
