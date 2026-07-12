use std::{
    io::{Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    CoreError,
    control::ControlMessage,
    crypto::{Direction, KeyHandle, TrafficKeys, decrypt_frame_with_key, encrypt_frame},
    frame::{FRAME_HEADER_LEN, Frame, FrameHeader},
    limits::ProtocolLimits,
    payload::{self, Tlv},
    replay::ReplayProtector,
    sequence::OutboundSequence,
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
        keys: KeyHandle,
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
        keys: KeyHandle,
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
        keys: KeyHandle,
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
        keys: KeyHandle,
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
    keys: Vec<KeyHandle>,
    active_key_id: u8,
    limits: ProtocolLimits,
    inbound_direction: Direction,
    outbound_direction: Direction,
    default_stream_id: u32,
    default_flags: u8,
    next_seq: OutboundSequence,
    replay: ReplayProtector,
    terminal: bool,
}

impl<T> SyncIo<T> {
    /// Creates a blocking Foctet transport wrapper.
    pub fn new(
        io: T,
        keys: KeyHandle,
        inbound_direction: Direction,
        outbound_direction: Direction,
    ) -> Self {
        let limits = ProtocolLimits::default();
        Self {
            io,
            active_key_id: keys.key_id,
            keys: vec![keys],
            inbound_direction,
            outbound_direction,
            default_stream_id: 0,
            default_flags: 0,
            next_seq: OutboundSequence::default(),
            replay: limits.replay_protector(),
            terminal: false,
            limits,
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

    /// Applies a complete set of [`ProtocolLimits`], rebuilding the replay
    /// protector from the new replay-window size and window cap.
    ///
    /// Intended to be called immediately after [`SyncIo::new`], before any
    /// frames are processed; it resets replay-window state.
    pub fn with_limits(mut self, limits: ProtocolLimits) -> Self {
        self.replay = limits.replay_protector();
        self.limits = limits;
        self
    }

    /// Returns the active protocol limits.
    pub fn limits(&self) -> ProtocolLimits {
        self.limits
    }

    /// Sets inbound ciphertext size limit.
    pub fn with_max_ciphertext_len(mut self, max_len: usize) -> Self {
        self.limits.max_ciphertext_len = max_len;
        self
    }

    /// Sets number of retained previous keys.
    pub fn with_max_retained_keys(mut self, max: usize) -> Self {
        self.limits.max_retained_keys = max.max(1);
        self
    }

    /// Returns current active key ID.
    pub fn active_key_id(&self) -> u8 {
        self.active_key_id
    }

    /// Returns how many inbound frames this transport's replay protection has
    /// rejected since creation (see [`crate::ReplayProtector::rejections`]);
    /// an observability counter that carries no key material.
    pub fn replay_rejections(&self) -> u64 {
        self.replay.rejections()
    }

    /// Returns whether an ambiguous outbound I/O failure permanently closed
    /// this wrapper. A closed wrapper must be discarded along with its session;
    /// it cannot safely retry or emit another encrypted frame.
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Returns known key IDs, active first.
    pub fn known_key_ids(&self) -> Vec<u8> {
        self.keys.iter().map(|k| k.key_id).collect()
    }

    /// Installs new active keys and retains previous keys.
    pub fn install_active_keys(&mut self, keys: KeyHandle) {
        self.keys.retain(|k| k.key_id != keys.key_id);
        self.keys.insert(0, keys.clone());
        self.active_key_id = keys.key_id;
        let keep = self.limits.max_retained_keys + 1;
        if self.keys.len() > keep {
            self.keys.truncate(keep);
        }
    }

    /// Consumes wrapper and returns underlying I/O object.
    pub fn into_inner(self) -> T {
        self.io
    }

    fn active_keys(&self) -> Result<&KeyHandle, CoreError> {
        self.keys
            .iter()
            .find(|k| k.key_id == self.active_key_id)
            .ok_or(CoreError::MissingSessionSecret)
    }

    fn key_for_id(&self, key_id: u8) -> Option<&KeyHandle> {
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
        let keep = self.limits.max_retained_keys + 1;
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
        if self.terminal {
            return Err(CoreError::TransportTerminal);
        }
        if plaintext.len() > self.limits.max_plaintext_len {
            return Err(CoreError::FrameTooLarge);
        }
        let frame = encrypt_frame(
            keys,
            self.outbound_direction,
            flags,
            stream_id,
            self.next_seq.current(),
            plaintext,
        )?;
        // Reserve before the first byte reaches the transport. `write_all` may
        // fail after emitting a prefix (or all bytes), and `flush` may fail
        // after peer delivery. Consuming the sequence first prevents a retry
        // from ever encrypting different plaintext under the same nonce.
        let next_seq = self.next_seq.prepared_next()?;
        self.next_seq.commit(next_seq);

        // Keep the exact serialized frame alive for the complete write. There
        // is intentionally no resume API: any write/flush error has ambiguous
        // delivery semantics, so the only safe default is terminal closure.
        let serialized = frame.to_bytes();
        if let Err(error) = self.io.write_all(&serialized) {
            self.terminal = true;
            return Err(CoreError::Io(error));
        }
        if let Err(error) = self.io.flush() {
            self.terminal = true;
            return Err(CoreError::Io(error));
        }
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
        if self.terminal {
            return Err(CoreError::TransportTerminal);
        }
        let result = self.recv_inner();
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    fn recv_inner(&mut self) -> Result<Vec<u8>, CoreError> {
        let mut header_buf = [0u8; FRAME_HEADER_LEN];
        self.io.read_exact(&mut header_buf)?;
        let header = FrameHeader::decode(&header_buf)?;
        header.validate_v0()?;

        let ct_len = header.ct_len as usize;
        if ct_len > self.limits.max_ciphertext_len {
            return Err(CoreError::FrameTooLarge);
        }

        let mut ciphertext = vec![0u8; ct_len];
        self.io.read_exact(&mut ciphertext)?;

        let keys = self
            .key_for_id(header.key_id)
            .ok_or(CoreError::UnexpectedKeyId {
                expected: self.active_key_id,
                actual: header.key_id,
            })?;

        // Authenticate the ciphertext *before* committing replay-window state.
        // Recording an attacker-chosen sequence number prior to AEAD
        // verification would let a forged frame permanently advance the window
        // and desynchronize/DoS the receiver. See replay.rs and SPEC.md.
        let frame = Frame { header, ciphertext };
        let plaintext = decrypt_frame_with_key(keys, self.inbound_direction, &frame)?;
        self.replay.check_and_record(
            frame.header.key_id,
            frame.header.stream_id,
            frame.header.seq,
        )?;
        Ok(plaintext)
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

        if let Some(prepared) = session.on_outbound_payload(plaintext.len())? {
            self.send_control_with_key_id(0, prepared.old_key_id(), prepared.control_message())?;
            session.commit_rekey(prepared)?;
            self.set_key_ring_from_session(session)?;
        }
        Ok(())
    }

    /// Receives next frame and applies session-aware control handling.
    pub fn recv_application_with_session(
        &mut self,
        session: &mut Session,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        if self.terminal {
            return Err(CoreError::TransportTerminal);
        }
        let result = self.recv_application_with_session_inner(session);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    fn recv_application_with_session_inner(
        &mut self,
        session: &mut Session,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let mut header_buf = [0u8; FRAME_HEADER_LEN];
        self.io.read_exact(&mut header_buf)?;
        let header = FrameHeader::decode(&header_buf)?;
        header.validate_v0()?;

        let ct_len = header.ct_len as usize;
        if ct_len > self.limits.max_ciphertext_len {
            return Err(CoreError::FrameTooLarge);
        }

        let mut ciphertext = vec![0u8; ct_len];
        self.io.read_exact(&mut ciphertext)?;

        let keys = self
            .key_for_id(header.key_id)
            .ok_or(CoreError::UnexpectedKeyId {
                expected: self.active_key_id,
                actual: header.key_id,
            })?;

        // Authenticate before committing replay state (see `recv`).
        let frame = Frame { header, ciphertext };
        let plaintext = decrypt_frame_with_key(keys, self.inbound_direction, &frame)?;
        self.replay.check_and_record(
            frame.header.key_id,
            frame.header.stream_id,
            frame.header.seq,
        )?;

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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{Read, Write};

    use super::SyncIo;
    use crate::CoreError;
    use crate::crypto::{
        Direction, EphemeralKeyPair, KeyHandle, derive_traffic_keys, encrypt_frame,
        random_session_salt,
    };

    #[derive(Default)]
    struct MockIo {
        inbound: VecDeque<u8>,
        outbound: Vec<u8>,
    }

    struct FailingWriteIo {
        outbound: Vec<u8>,
        fail_after: usize,
        fail_flush: bool,
    }

    impl Read for FailingWriteIo {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for FailingWriteIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let remaining = self.fail_after.saturating_sub(self.outbound.len());
            if remaining == 0 {
                return Err(std::io::Error::other("injected write failure"));
            }
            let written = remaining.min(buf.len());
            self.outbound.extend_from_slice(&buf[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                Err(std::io::Error::other("injected flush failure"))
            } else {
                Ok(())
            }
        }
    }

    impl Read for MockIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.inbound.is_empty() {
                return Ok(0);
            }
            let n = buf.len().min(self.inbound.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.inbound.pop_front().expect("inbound byte");
            }
            Ok(n)
        }
    }

    impl Write for MockIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn test_keys() -> KeyHandle {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let ss = a.shared_secret(b.public).expect("shared secret");
        let salt = random_session_salt();
        KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("traffic keys"))
    }

    #[test]
    fn sync_send_fails_closed_on_sequence_exhaustion() {
        let keys = test_keys();
        let mut io = SyncIo::new(MockIo::default(), keys, Direction::S2C, Direction::C2S);

        // Drive the outbound counter to the last representable sequence.
        io.next_seq.set_for_test(u64::MAX - 1);
        io.send(b"last").expect("final valid frame must be emitted");
        assert_eq!(io.next_seq.current(), u64::MAX);
        let emitted = io.io.outbound.len();
        assert!(emitted > 0);

        // The next send would have to reuse a nonce; it must fail closed and
        // must NOT emit any wrapped frame.
        let err = io
            .send(b"overflow")
            .expect_err("must refuse to wrap the nonce");
        assert!(matches!(err, CoreError::SequenceExhausted));
        assert_eq!(
            io.io.outbound.len(),
            emitted,
            "no wrapped frame may be written"
        );
        assert_eq!(io.next_seq.current(), u64::MAX);
    }

    #[test]
    fn partial_write_failure_consumes_sequence_and_is_terminal() {
        let keys = test_keys();
        let transport = FailingWriteIo {
            outbound: Vec::new(),
            fail_after: 7,
            fail_flush: false,
        };
        let mut io = SyncIo::new(transport, keys, Direction::S2C, Direction::C2S);

        assert!(matches!(io.send(b"first"), Err(CoreError::Io(_))));
        assert!(io.is_terminal());
        assert_eq!(
            io.next_seq.current(),
            1,
            "reserved sequence is never reused"
        );
        let emitted = io.io.outbound.clone();

        assert!(matches!(
            io.send(b"different retry"),
            Err(CoreError::TransportTerminal)
        ));
        assert_eq!(io.io.outbound, emitted, "terminal retry emits no bytes");
    }

    #[test]
    fn flush_failure_after_complete_frame_is_terminal() {
        let keys = test_keys();
        let transport = FailingWriteIo {
            outbound: Vec::new(),
            fail_after: usize::MAX,
            fail_flush: true,
        };
        let mut io = SyncIo::new(transport, keys, Direction::S2C, Direction::C2S);

        assert!(matches!(
            io.send(b"complete but ambiguous"),
            Err(CoreError::Io(_))
        ));
        assert!(io.is_terminal());
        assert_eq!(io.next_seq.current(), 1);
        let emitted = io.io.outbound.clone();

        assert!(matches!(
            io.send(b"retry"),
            Err(CoreError::TransportTerminal)
        ));
        assert_eq!(io.io.outbound, emitted);
    }

    #[test]
    fn authentication_failure_makes_sync_io_terminal() {
        let keys = test_keys();

        // Receiver treats inbound traffic as the C2S direction, so the peer
        // encrypts with C2S keys.
        let valid = encrypt_frame(&keys, Direction::C2S, 0, 0, 0, b"hello").expect("valid frame");
        let forged =
            encrypt_frame(&keys, Direction::C2S, 0, 0, 1_000_000, b"forged").expect("forged frame");
        let mut forged_bytes = forged.to_bytes();
        let last = forged_bytes.len() - 1;
        forged_bytes[last] ^= 0xff; // corrupt the AEAD tag -> authentication failure

        let mut mock = MockIo::default();
        mock.inbound.extend(forged_bytes.iter().copied());
        mock.inbound.extend(valid.to_bytes().iter().copied());

        let mut io = SyncIo::new(mock, keys, Direction::C2S, Direction::S2C);

        // The forged high-sequence frame must fail authentication.
        let err = io
            .recv()
            .expect_err("forged frame must fail authentication");
        assert!(matches!(err, CoreError::Aead));
        assert!(io.is_terminal());

        assert!(matches!(io.recv(), Err(CoreError::TransportTerminal)));
    }

    #[test]
    fn with_limits_enforces_max_ciphertext_len_on_receive() {
        use crate::limits::ProtocolLimits;

        let keys = test_keys();
        let frame = encrypt_frame(&keys, Direction::C2S, 0, 0, 0, b"a slightly longer payload")
            .expect("frame");

        let mut mock = MockIo::default();
        mock.inbound.extend(frame.to_bytes().iter().copied());

        // Configure an inbound ciphertext ceiling far below this frame's length.
        let mut io = SyncIo::new(mock, keys, Direction::C2S, Direction::S2C)
            .with_limits(ProtocolLimits::default().with_max_ciphertext_len(4));
        assert_eq!(io.limits().max_ciphertext_len, 4);

        let err = io
            .recv()
            .expect_err("frame exceeding the configured ciphertext limit must be rejected");
        assert!(matches!(err, CoreError::FrameTooLarge));
    }

    #[test]
    fn send_rejects_plaintext_over_the_configured_limit() {
        use crate::limits::ProtocolLimits;

        let keys = test_keys();
        let mut io = SyncIo::new(MockIo::default(), keys, Direction::S2C, Direction::C2S)
            .with_limits(ProtocolLimits::default().with_max_plaintext_len(4));

        let err = io
            .send(b"way past the limit")
            .expect_err("oversized plaintext must be rejected before encryption");
        assert!(matches!(err, CoreError::FrameTooLarge));
        assert!(io.io.outbound.is_empty(), "nothing may be written");

        io.send(b"ok").expect("small payload still sends");
    }

    #[test]
    fn with_limits_configures_replay_window_size() {
        use crate::limits::ProtocolLimits;

        let keys = test_keys();
        // seq=0, then seq=8: with a window of 4, the older seq=0 falls outside
        // the window once seq=8 advances it.
        let first = encrypt_frame(&keys, Direction::C2S, 0, 0, 8, b"newer").expect("first");
        let stale = encrypt_frame(&keys, Direction::C2S, 0, 0, 0, b"older").expect("stale");

        let mut mock = MockIo::default();
        mock.inbound.extend(first.to_bytes().iter().copied());
        mock.inbound.extend(stale.to_bytes().iter().copied());

        let mut io = SyncIo::new(mock, keys, Direction::C2S, Direction::S2C)
            .with_limits(ProtocolLimits::default().with_replay_window(4));
        assert_eq!(io.limits().replay_window, 4);

        assert_eq!(io.recv().expect("newer seq accepted"), b"newer");
        let err = io
            .recv()
            .expect_err("seq outside the small replay window must be rejected");
        assert!(matches!(err, CoreError::ReplayWindowExceeded));
    }
}
