use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, BytesMut};
use futures_core::Stream;
use futures_sink::Sink;

use crate::{
    CoreError,
    control::ControlMessage,
    crypto::{Direction, KeyHandle, decrypt_frame_with_key, encrypt_frame},
    io::PollIo,
    limits::ProtocolLimits,
    payload::{self, Tlv},
    replay::ReplayProtector,
    sequence::OutboundSequence,
    session::Session,
};

/// Draft v0 wire version identifier.
pub const WIRE_VERSION_V0: u8 = 0x00;
/// Mandatory profile identifier for Draft v0.
pub const PROFILE_X25519_HKDF_XCHACHA20POLY1305: u8 = 0x01;
/// Serialized frame-header length in bytes.
pub const FRAME_HEADER_LEN: usize = 22;

/// Draft v0 frame magic marker (`0xF0 0xC7`).
pub const DRAFT_MAGIC: [u8; 2] = [0xF0, 0xC7];

/// Bit flags carried in [`FrameHeader::flags`].
pub mod flags {
    /// Routing information exists at an outer layer.
    pub const HAS_ROUTING: u8 = 1 << 0;
    /// Frame carries a control payload.
    pub const IS_CONTROL: u8 = 1 << 1;
    /// Delivery acknowledgement hint.
    pub const ACK_REQUIRED: u8 = 1 << 2;
    /// Ciphertext includes semantic padding.
    pub const PADDING: u8 = 1 << 3;
    /// Bitmask of all known flags for Draft v0.
    pub const ALL_KNOWN_BITS: u8 = HAS_ROUTING | IS_CONTROL | ACK_REQUIRED | PADDING;
}

/// Plaintext wire header authenticated as AEAD AAD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    /// Draft magic marker.
    pub magic: [u8; 2],
    /// Protocol version.
    pub version: u8,
    /// Frame flags bitfield.
    pub flags: u8,
    /// Cryptographic profile identifier.
    pub profile_id: u8,
    /// Active traffic-key identifier.
    pub key_id: u8,
    /// Logical stream identifier.
    pub stream_id: u32,
    /// Sequence number per stream/direction/key.
    pub seq: u64,
    /// Ciphertext length in bytes.
    pub ct_len: u32,
}

impl FrameHeader {
    /// Creates a header value for a frame.
    pub fn new(
        flags: u8,
        profile_id: u8,
        key_id: u8,
        stream_id: u32,
        seq: u64,
        ct_len: u32,
    ) -> Self {
        Self {
            magic: DRAFT_MAGIC,
            version: WIRE_VERSION_V0,
            flags,
            profile_id,
            key_id,
            stream_id,
            seq,
            ct_len,
        }
    }

    /// Serializes header into fixed-width wire bytes.
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[0..2].copy_from_slice(&self.magic);
        out[2] = self.version;
        out[3] = self.flags;
        out[4] = self.profile_id;
        out[5] = self.key_id;
        out[6..10].copy_from_slice(&self.stream_id.to_be_bytes());
        out[10..18].copy_from_slice(&self.seq.to_be_bytes());
        out[18..22].copy_from_slice(&self.ct_len.to_be_bytes());
        out
    }

    /// Parses a fixed-width frame header from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, CoreError> {
        if buf.len() != FRAME_HEADER_LEN {
            return Err(CoreError::InvalidHeaderLength(buf.len()));
        }

        let mut magic = [0u8; 2];
        magic.copy_from_slice(&buf[0..2]);
        let version = buf[2];
        let flags = buf[3];
        let profile_id = buf[4];
        let key_id = buf[5];

        let mut stream_id_bytes = [0u8; 4];
        stream_id_bytes.copy_from_slice(&buf[6..10]);
        let stream_id = u32::from_be_bytes(stream_id_bytes);

        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&buf[10..18]);
        let seq = u64::from_be_bytes(seq_bytes);

        let mut ct_len_bytes = [0u8; 4];
        ct_len_bytes.copy_from_slice(&buf[18..22]);
        let ct_len = u32::from_be_bytes(ct_len_bytes);

        Ok(Self {
            magic,
            version,
            flags,
            profile_id,
            key_id,
            stream_id,
            seq,
            ct_len,
        })
    }

    /// Validates version/profile/flags according to Draft v0.
    pub fn validate_v0(&self) -> Result<(), CoreError> {
        if self.magic != DRAFT_MAGIC {
            return Err(CoreError::InvalidMagic);
        }
        if self.version != WIRE_VERSION_V0 {
            return Err(CoreError::UnsupportedVersion(self.version));
        }
        if self.profile_id != PROFILE_X25519_HKDF_XCHACHA20POLY1305 {
            return Err(CoreError::UnsupportedProfile(self.profile_id));
        }
        if self.flags & !flags::ALL_KNOWN_BITS != 0 {
            return Err(CoreError::UnknownFlags(self.flags));
        }
        Ok(())
    }
}

/// Complete encrypted frame (header + ciphertext).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// Plaintext authenticated header.
    pub header: FrameHeader,
    /// AEAD ciphertext (including tag).
    pub ciphertext: Vec<u8>,
}

impl Frame {
    /// Serializes frame to wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses a complete frame from wire bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, CoreError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(CoreError::InvalidHeaderLength(buf.len()));
        }
        let header = FrameHeader::decode(&buf[..FRAME_HEADER_LEN])?;
        let ciphertext = buf[FRAME_HEADER_LEN..].to_vec();
        if ciphertext.len() != header.ct_len as usize {
            return Err(CoreError::CiphertextLengthMismatch {
                expected: header.ct_len as usize,
                actual: ciphertext.len(),
            });
        }
        Ok(Self { header, ciphertext })
    }
}

/// Frame decoded by transport layer with plaintext payload bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedFrame {
    /// Parsed authenticated header.
    pub header: FrameHeader,
    /// Decrypted frame payload bytes.
    pub plaintext: Vec<u8>,
}

/// Framed Foctet transport over a poll-based I/O backend.
#[derive(Clone, Debug)]
pub struct FoctetFramed<T> {
    io: T,
    keys: Vec<KeyHandle>,
    active_key_id: u8,
    limits: ProtocolLimits,
    inbound_direction: Direction,
    outbound_direction: Direction,
    default_stream_id: u32,
    default_flags: u8,
    next_seq: OutboundSequence,
    rx: BytesMut,
    tx: BytesMut,
    replay: ReplayProtector,
    eof: bool,
    terminal: bool,
}

impl<T> FoctetFramed<T> {
    /// Creates a framed transport with initial traffic keys.
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
            rx: BytesMut::with_capacity(8 * 1024),
            tx: BytesMut::new(),
            replay: limits.replay_protector(),
            limits,
            eof: false,
            terminal: false,
        }
    }

    /// Sets default stream ID for sink-based sending.
    pub fn with_stream_id(mut self, stream_id: u32) -> Self {
        self.default_stream_id = stream_id;
        self
    }

    /// Sets default frame flags for sink-based sending.
    pub fn with_default_flags(mut self, flags: u8) -> Self {
        self.default_flags = flags;
        self
    }

    /// Applies a complete set of [`ProtocolLimits`], rebuilding the replay
    /// protector from the new replay-window size and window cap.
    ///
    /// Intended to be called immediately after [`FoctetFramed::new`], before any
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

    /// Returns immutable reference to underlying I/O object.
    pub fn get_ref(&self) -> &T {
        &self.io
    }

    /// Returns mutable reference to underlying I/O object.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.io
    }

    /// Consumes wrapper and returns underlying I/O object.
    pub fn into_inner(self) -> T {
        self.io
    }

    /// Returns known key IDs, active first.
    pub fn known_key_ids(&self) -> Vec<u8> {
        self.keys.iter().map(|k| k.key_id).collect()
    }

    /// Returns active key ID.
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
    /// this transport. A terminal transport must be discarded with its session;
    /// it cannot safely retry queued ciphertext or encrypt new plaintext.
    pub fn is_terminal(&self) -> bool {
        self.terminal
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

    fn enqueue_with_specific_key(
        &mut self,
        key_id: u8,
        flags: u8,
        stream_id: u32,
        plaintext: &[u8],
    ) -> Result<(), CoreError> {
        let keys = self
            .key_for_id(key_id)
            .ok_or(CoreError::UnexpectedKeyId {
                expected: self.active_key_id,
                actual: key_id,
            })?
            .clone();
        self.enqueue_encrypted(&keys, flags, stream_id, plaintext)
    }

    /// Encrypts one frame and appends it to the outbound buffer, enforcing the
    /// configured plaintext and buffered-bytes limits. The sequence number is
    /// only committed once the frame is actually enqueued, so a rejected send
    /// consumes no nonce.
    fn enqueue_encrypted(
        &mut self,
        keys: &KeyHandle,
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
        let bytes = frame.to_bytes();
        if self.tx.len().saturating_add(bytes.len()) > self.limits.max_buffered_tx_bytes {
            return Err(CoreError::OutboundBufferLimitExceeded);
        }
        let next_seq = self.next_seq.prepared_next()?;
        self.next_seq.commit(next_seq);
        self.tx.extend_from_slice(&bytes);
        Ok(())
    }
}

impl<T: PollIo + Unpin> FoctetFramed<T> {
    /// Poll-based helper to send one payload frame.
    pub fn poll_send_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        flags: u8,
        stream_id: u32,
        plaintext: &[u8],
    ) -> Poll<Result<(), CoreError>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut *this).poll_ready(cx))?;
        Pin::new(&mut *this).start_send_with(flags, stream_id, plaintext)?;
        Poll::Ready(Ok(()))
    }

    /// Enqueues one encrypted frame into outbound buffer.
    pub fn start_send_with(
        self: Pin<&mut Self>,
        flags: u8,
        stream_id: u32,
        plaintext: &[u8],
    ) -> Result<(), CoreError> {
        let this = self.get_mut();
        let active = this.active_keys()?.clone();
        this.enqueue_encrypted(&active, flags, stream_id, plaintext)
    }

    /// Enqueues a control payload frame.
    pub fn start_send_control(
        self: Pin<&mut Self>,
        stream_id: u32,
        msg: &ControlMessage,
    ) -> Result<(), CoreError> {
        self.start_send_with(flags::IS_CONTROL, stream_id, &msg.encode())
    }

    /// Enqueues TLV payload bytes in a data frame.
    pub fn start_send_tlvs_with(
        self: Pin<&mut Self>,
        flags: u8,
        stream_id: u32,
        tlvs: &[Tlv],
    ) -> Result<(), CoreError> {
        let payload = payload::encode_tlvs(tlvs)?;
        self.start_send_with(flags, stream_id, &payload)
    }

    /// Enqueues a control payload frame using explicit key ID.
    pub fn start_send_control_with_key_id(
        self: Pin<&mut Self>,
        stream_id: u32,
        key_id: u8,
        msg: &ControlMessage,
    ) -> Result<(), CoreError> {
        let this = self.get_mut();
        this.enqueue_with_specific_key(key_id, flags::IS_CONTROL, stream_id, &msg.encode())
    }

    /// Decodes a control message from a decoded control frame.
    pub fn decode_control(frame: &DecodedFrame) -> Result<ControlMessage, CoreError> {
        if frame.header.flags & flags::IS_CONTROL == 0 {
            return Err(CoreError::UnexpectedControlMessage);
        }
        ControlMessage::decode(&frame.plaintext)
    }

    /// Decodes TLV records from a decoded frame payload.
    pub fn decode_tlvs(frame: &DecodedFrame) -> Result<Vec<Tlv>, CoreError> {
        payload::decode_tlvs(&frame.plaintext)
    }

    /// Sends application payload with session-aware automatic rekey handling.
    pub fn start_send_data_with_session(
        self: Pin<&mut Self>,
        session: &mut Session,
        flags: u8,
        stream_id: u32,
        plaintext: &[u8],
    ) -> Result<(), CoreError> {
        let this = self.get_mut();
        this.set_key_ring_from_session(session)?;
        let app_tlv = Tlv::application_data(plaintext)?;
        let app_payload = payload::encode_tlvs(&[app_tlv])?;
        this.enqueue_with_specific_key(this.active_key_id, flags, stream_id, &app_payload)?;

        if let Some(prepared) = session.on_outbound_payload(plaintext.len())? {
            let ctrl_bytes = prepared.control_message().encode();
            if let Err(error) = this.enqueue_with_specific_key(
                prepared.old_key_id(),
                flags::IS_CONTROL,
                0,
                &ctrl_bytes,
            ) {
                // The application frame was already queued. Continuing without
                // its required rekey control would leave counters and peer
                // expectations ambiguous, so discard this transport/session.
                this.terminal = true;
                return Err(error);
            }
            session.commit_rekey(prepared)?;
            this.set_key_ring_from_session(session)?;
        }
        Ok(())
    }

    /// Processes one incoming decoded frame with session-aware control handling.
    pub fn handle_incoming_with_session(
        self: Pin<&mut Self>,
        session: &mut Session,
        frame: DecodedFrame,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let this = self.get_mut();
        if this.terminal {
            return Err(CoreError::TransportTerminal);
        }
        let result = this.handle_incoming_with_session_inner(session, frame);
        if result.is_err() {
            this.terminal = true;
        }
        result
    }

    fn handle_incoming_with_session_inner(
        &mut self,
        session: &mut Session,
        frame: DecodedFrame,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        if frame.header.flags & flags::IS_CONTROL != 0 {
            let msg = ControlMessage::decode(&frame.plaintext)?;
            let response = session.handle_control(&msg)?;
            self.set_key_ring_from_session(session)?;
            if let Some(resp) = response {
                self.enqueue_with_specific_key(
                    self.active_key_id,
                    flags::IS_CONTROL,
                    0,
                    &resp.encode(),
                )?;
            }
            return Ok(None);
        }
        Ok(Some(frame.plaintext))
    }

    fn try_decode(&mut self) -> Result<Option<DecodedFrame>, CoreError> {
        if self.rx.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        let header = FrameHeader::decode(&self.rx[..FRAME_HEADER_LEN])?;
        header.validate_v0()?;

        let ct_len = header.ct_len as usize;
        if ct_len > self.limits.max_ciphertext_len {
            return Err(CoreError::FrameTooLarge);
        }

        let total = FRAME_HEADER_LEN + ct_len;
        if self.rx.len() < total {
            return Ok(None);
        }

        let frame_bytes = self.rx.split_to(total);
        let frame = Frame::from_bytes(&frame_bytes)?;

        let keys = self
            .key_for_id(frame.header.key_id)
            .ok_or(CoreError::UnexpectedKeyId {
                expected: self.active_key_id,
                actual: frame.header.key_id,
            })?;

        // Authenticate the ciphertext *before* committing replay-window state so
        // an unauthenticated frame carrying an attacker-chosen sequence number
        // cannot permanently advance the window and reject later legitimate
        // frames (receive-side desynchronization / DoS).
        let plaintext = decrypt_frame_with_key(keys, self.inbound_direction, &frame)?;
        self.replay.check_and_record(
            frame.header.key_id,
            frame.header.stream_id,
            frame.header.seq,
        )?;

        Ok(Some(DecodedFrame {
            header: frame.header,
            plaintext,
        }))
    }

    fn poll_fill_rx(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        let mut tmp = [0u8; 8192];
        match Pin::new(&mut self.io).poll_read(cx, &mut tmp) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(n)) => {
                self.rx.extend_from_slice(&tmp[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(CoreError::Io(e))),
        }
    }

    fn poll_drain_tx(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CoreError>> {
        while !self.tx.is_empty() {
            let n = match ready!(Pin::new(&mut self.io).poll_write(cx, &self.tx)) {
                Ok(n) => n,
                Err(error) => {
                    self.terminal = true;
                    return Poll::Ready(Err(CoreError::Io(error)));
                }
            };
            if n == 0 {
                self.terminal = true;
                return Poll::Ready(Err(CoreError::UnexpectedEof));
            }
            self.tx.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: PollIo + Unpin> Stream for FoctetFramed<T> {
    type Item = Result<DecodedFrame, CoreError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.terminal {
            return Poll::Ready(Some(Err(CoreError::TransportTerminal)));
        }

        loop {
            match this.try_decode() {
                Ok(Some(frame)) => return Poll::Ready(Some(Ok(frame))),
                Ok(None) => {}
                Err(e) => {
                    this.terminal = true;
                    return Poll::Ready(Some(Err(e)));
                }
            }

            if this.eof {
                if this.rx.is_empty() {
                    return Poll::Ready(None);
                }
                return Poll::Ready(Some(Err(CoreError::UnexpectedEof)));
            }

            match ready!(this.poll_fill_rx(cx)) {
                Ok(()) => {}
                Err(error) => {
                    this.terminal = true;
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }
    }
}

impl<T: PollIo + Unpin> Sink<Vec<u8>> for FoctetFramed<T> {
    type Error = CoreError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.terminal {
            return Poll::Ready(Err(CoreError::TransportTerminal));
        }
        if this.tx.is_empty() {
            return Poll::Ready(Ok(()));
        }
        this.poll_drain_tx(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let active = this.active_keys()?.clone();
        this.enqueue_encrypted(&active, this.default_flags, this.default_stream_id, &item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.terminal {
            return Poll::Ready(Err(CoreError::TransportTerminal));
        }
        ready!(this.poll_drain_tx(cx))?;
        match Pin::new(&mut this.io).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                this.terminal = true;
                Poll::Ready(Err(CoreError::Io(error)))
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.terminal {
            return Poll::Ready(Err(CoreError::TransportTerminal));
        }
        ready!(this.poll_drain_tx(cx))?;
        match ready!(Pin::new(&mut this.io).poll_flush(cx)) {
            Ok(()) => {}
            Err(error) => {
                this.terminal = true;
                return Poll::Ready(Err(CoreError::Io(error)));
            }
        }
        match Pin::new(&mut this.io).poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                this.terminal = true;
                Poll::Ready(Err(CoreError::Io(error)))
            }
        }
    }
}

/// Plain byte-stream convenience wrapper over [`FoctetFramed`].
#[derive(Clone, Debug)]
pub struct FoctetStream<T> {
    framed: FoctetFramed<T>,
    read_buf: BytesMut,
    max_write_frame: usize,
}

impl<T> FoctetStream<T> {
    /// Creates a stream wrapper from a framed transport.
    pub fn new(framed: FoctetFramed<T>) -> Self {
        Self {
            framed,
            read_buf: BytesMut::new(),
            max_write_frame: 64 * 1024,
        }
    }

    /// Sets max plaintext bytes packed per write call.
    pub fn with_max_write_frame(mut self, max: usize) -> Self {
        self.max_write_frame = max.max(1);
        self
    }

    /// Returns inner framed transport.
    pub fn into_inner(self) -> FoctetFramed<T> {
        self.framed
    }

    /// Returns immutable reference to inner framed transport.
    pub fn framed_ref(&self) -> &FoctetFramed<T> {
        &self.framed
    }

    /// Returns mutable reference to inner framed transport.
    pub fn framed_mut(&mut self) -> &mut FoctetFramed<T> {
        &mut self.framed
    }
}

impl<T: PollIo + Unpin> FoctetStream<T> {
    /// Poll-based plaintext read from encrypted framed transport.
    pub fn poll_read_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<Result<usize, CoreError>> {
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let n = out.len().min(this.read_buf.len());
            out[..n].copy_from_slice(&this.read_buf.split_to(n));
            return Poll::Ready(Ok(n));
        }

        match ready!(Pin::new(&mut this.framed).poll_next(cx)) {
            Some(Ok(frame)) => {
                this.read_buf.extend_from_slice(&frame.plaintext);
                let n = out.len().min(this.read_buf.len());
                out[..n].copy_from_slice(&this.read_buf.split_to(n));
                Poll::Ready(Ok(n))
            }
            Some(Err(e)) => Poll::Ready(Err(e)),
            None => Poll::Ready(Ok(0)),
        }
    }

    /// Poll-based plaintext write into encrypted framed transport.
    pub fn poll_write_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, CoreError>> {
        let this = self.get_mut();
        let n = buf.len().min(this.max_write_frame);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }

        ready!(Pin::new(&mut this.framed).poll_ready(cx))?;
        Pin::new(&mut this.framed).start_send(buf[..n].to_vec())?;
        Poll::Ready(Ok(n))
    }

    /// Poll-based flush for pending encrypted writes.
    pub fn poll_flush_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), CoreError>> {
        Pin::new(&mut self.get_mut().framed).poll_flush(cx)
    }

    /// Poll-based close for encrypted transport.
    pub fn poll_close_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), CoreError>> {
        Pin::new(&mut self.get_mut().framed).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use futures_core::Stream;
    use futures_sink::Sink;

    use crate::{
        ControlMessage, CoreError, RekeyThresholds, Session, SessionAuthConfig,
        crypto::{
            Direction, EphemeralKeyPair, KeyHandle, derive_traffic_keys, encrypt_frame,
            random_session_salt,
        },
        io::{PollRead, PollWrite},
    };

    use super::{
        DecodedFrame, FoctetFramed, FrameHeader, PROFILE_X25519_HKDF_XCHACHA20POLY1305, flags,
    };

    #[derive(Default, Debug)]
    struct MemoryIo {
        inbound: VecDeque<u8>,
        outbound: Vec<u8>,
    }

    #[derive(Debug)]
    struct FailingWriteIo {
        outbound: Vec<u8>,
        fail_after: usize,
        fail_flush: bool,
    }

    impl PollRead for FailingWriteIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
    }

    impl PollWrite for FailingWriteIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let remaining = self.fail_after.saturating_sub(self.outbound.len());
            if remaining == 0 {
                return Poll::Ready(Err(std::io::Error::other("injected write failure")));
            }
            let written = remaining.min(buf.len());
            self.outbound.extend_from_slice(&buf[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            if self.fail_flush {
                Poll::Ready(Err(std::io::Error::other("injected flush failure")))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl MemoryIo {
        fn push_inbound(&mut self, bytes: &[u8]) {
            self.inbound.extend(bytes.iter().copied());
        }
    }

    impl PollRead for MemoryIo {
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

    impl PollWrite for MemoryIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.outbound.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn noop_waker() -> Waker {
        Waker::noop().clone()
    }

    #[test]
    fn framed_sink_stream_roundtrip() {
        let eph_a = EphemeralKeyPair::generate();
        let eph_b = EphemeralKeyPair::generate();
        let ss = eph_a.shared_secret(eph_b.public).expect("shared secret");
        let salt = random_session_salt();
        let keys = KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("traffic keys"));

        let io = MemoryIo::default();
        let mut framed = FoctetFramed::new(io, keys.clone(), Direction::C2S, Direction::C2S)
            .with_stream_id(9)
            .with_default_flags(flags::IS_CONTROL);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        Pin::new(&mut framed)
            .start_send(b"hello framed".to_vec())
            .expect("queue");
        match Pin::new(&mut framed).poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => {}
            _ => panic!("flush failed"),
        }

        let outbound = framed.get_ref().outbound.clone();
        framed.get_mut().push_inbound(&outbound);

        let item = match Pin::new(&mut framed).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => frame,
            other => panic!("unexpected poll_next: {other:?}"),
        };
        assert_eq!(item.plaintext, b"hello framed");
        assert_eq!(item.header.stream_id, 9);
        assert_eq!(item.header.flags, flags::IS_CONTROL);
    }

    #[test]
    fn partial_write_failure_makes_framed_transport_terminal() {
        let keys = KeyHandle::new(crate::TrafficKeys {
            key_id: 1,
            c2s: [0x11; 32],
            s2c: [0x22; 32],
        });
        let io = FailingWriteIo {
            outbound: Vec::new(),
            fail_after: 7,
            fail_flush: false,
        };
        let mut framed = FoctetFramed::new(io, keys, Direction::C2S, Direction::C2S);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        Pin::new(&mut framed)
            .start_send_with(0, 0, b"first")
            .expect("queue first frame");
        assert!(matches!(
            Pin::new(&mut framed).poll_flush(&mut cx),
            Poll::Ready(Err(CoreError::Io(_)))
        ));
        assert!(framed.is_terminal());
        let emitted = framed.get_ref().outbound.clone();

        assert!(matches!(
            Pin::new(&mut framed).start_send_with(0, 0, b"different retry"),
            Err(CoreError::TransportTerminal)
        ));
        assert_eq!(framed.get_ref().outbound, emitted);
    }

    #[test]
    fn flush_failure_after_frame_drain_makes_framed_transport_terminal() {
        let keys = KeyHandle::new(crate::TrafficKeys {
            key_id: 1,
            c2s: [0x11; 32],
            s2c: [0x22; 32],
        });
        let io = FailingWriteIo {
            outbound: Vec::new(),
            fail_after: usize::MAX,
            fail_flush: true,
        };
        let mut framed = FoctetFramed::new(io, keys, Direction::C2S, Direction::C2S);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        Pin::new(&mut framed)
            .start_send_with(0, 0, b"complete but ambiguous")
            .expect("queue frame");
        assert!(matches!(
            Pin::new(&mut framed).poll_flush(&mut cx),
            Poll::Ready(Err(CoreError::Io(_)))
        ));
        assert!(framed.is_terminal());
        assert!(matches!(
            Pin::new(&mut framed).poll_ready(&mut cx),
            Poll::Ready(Err(CoreError::TransportTerminal))
        ));
    }

    #[test]
    fn auto_rekey_does_not_commit_when_control_cannot_be_enqueued() {
        use crate::limits::ProtocolLimits;

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
            .expect("initiator completes handshake");
        let active = initiator.active_keys().expect("active key");

        // The application frame fits; the following rekey control does not.
        let mut framed = FoctetFramed::new(
            MemoryIo::default(),
            active.clone(),
            initiator.inbound_direction(),
            initiator.outbound_direction(),
        )
        .with_limits(ProtocolLimits::default().with_max_buffered_tx_bytes(64));

        let err = Pin::new(&mut framed)
            .start_send_data_with_session(&mut initiator, 0, 0, b"x")
            .expect_err("rekey control must exceed tx cap");
        assert!(matches!(err, CoreError::OutboundBufferLimitExceeded));
        assert!(framed.is_terminal());
        assert_eq!(initiator.active_keys().expect("old key retained"), active);
        assert!(
            initiator.can_rekey(),
            "failed enqueue must not hand over turn"
        );
    }

    #[test]
    fn authentication_failure_makes_framed_transport_terminal() {
        let eph_a = EphemeralKeyPair::generate();
        let eph_b = EphemeralKeyPair::generate();
        let ss = eph_a.shared_secret(eph_b.public).expect("shared secret");
        let salt = random_session_salt();
        let keys = KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("traffic keys"));

        let valid = encrypt_frame(&keys, Direction::C2S, 0, 0, 0, b"hello").expect("valid frame");
        let forged =
            encrypt_frame(&keys, Direction::C2S, 0, 0, 1_000_000, b"forged").expect("forged frame");
        let mut forged_bytes = forged.to_bytes();
        let last = forged_bytes.len() - 1;
        forged_bytes[last] ^= 0xff; // corrupt the AEAD tag

        let io = MemoryIo::default();
        let mut framed = FoctetFramed::new(io, keys, Direction::C2S, Direction::S2C);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        framed.get_mut().push_inbound(&forged_bytes);
        match Pin::new(&mut framed).poll_next(&mut cx) {
            Poll::Ready(Some(Err(CoreError::Aead))) => {}
            other => panic!("expected aead failure, got {other:?}"),
        }
        assert!(framed.is_terminal());

        framed.get_mut().push_inbound(&valid.to_bytes());
        match Pin::new(&mut framed).poll_next(&mut cx) {
            Poll::Ready(Some(Err(CoreError::TransportTerminal))) => {}
            other => panic!("expected terminal error, got {other:?}"),
        }
    }

    #[test]
    fn start_send_rejects_plaintext_over_the_configured_limit() {
        use crate::limits::ProtocolLimits;

        let eph_a = EphemeralKeyPair::generate();
        let eph_b = EphemeralKeyPair::generate();
        let ss = eph_a.shared_secret(eph_b.public).expect("shared secret");
        let salt = random_session_salt();
        let keys = KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("traffic keys"));

        let mut framed =
            FoctetFramed::new(MemoryIo::default(), keys, Direction::C2S, Direction::C2S)
                .with_limits(ProtocolLimits::default().with_max_plaintext_len(4));

        let err = Pin::new(&mut framed)
            .start_send_with(0, 0, b"way past the limit")
            .expect_err("oversized plaintext must be rejected before encryption");
        assert!(matches!(err, CoreError::FrameTooLarge));

        // A rejected send must not consume a sequence number: the next small
        // frame still starts at seq 0 and decrypts.
        Pin::new(&mut framed)
            .start_send_with(0, 0, b"ok")
            .expect("small payload still sends");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        match Pin::new(&mut framed).poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("flush failed: {other:?}"),
        }
        let outbound = framed.get_ref().outbound.clone();
        framed.get_mut().push_inbound(&outbound);
        match Pin::new(&mut framed).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.plaintext, b"ok");
                assert_eq!(frame.header.seq, 0);
            }
            other => panic!("unexpected poll_next: {other:?}"),
        }
    }

    #[test]
    fn enqueue_fails_once_the_tx_buffer_limit_is_hit() {
        use crate::limits::ProtocolLimits;

        let eph_a = EphemeralKeyPair::generate();
        let eph_b = EphemeralKeyPair::generate();
        let ss = eph_a.shared_secret(eph_b.public).expect("shared secret");
        let salt = random_session_salt();
        let keys = KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("traffic keys"));

        // Budget: exactly one small frame fits, a second enqueue without a
        // flush must fail closed instead of growing the buffer unboundedly.
        let one_frame_budget = super::FRAME_HEADER_LEN + b"payload".len() + 16;
        let mut framed =
            FoctetFramed::new(MemoryIo::default(), keys, Direction::C2S, Direction::C2S)
                .with_limits(
                    ProtocolLimits::default().with_max_buffered_tx_bytes(one_frame_budget),
                );

        Pin::new(&mut framed)
            .start_send_with(0, 0, b"payload")
            .expect("first frame fits the budget");
        let err = Pin::new(&mut framed)
            .start_send_with(0, 0, b"payload")
            .expect_err("second frame must exceed the buffered-tx budget");
        assert!(matches!(err, CoreError::OutboundBufferLimitExceeded));

        // Draining the buffer makes room again.
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        match Pin::new(&mut framed).poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("flush failed: {other:?}"),
        }
        Pin::new(&mut framed)
            .start_send_with(0, 0, b"payload")
            .expect("after draining, sending works again");
    }

    #[test]
    fn decode_control_rejects_a_frame_without_the_control_flag() {
        // A data frame whose plaintext happens to look like a valid encoded
        // `ControlMessage` must still be rejected by `decode_control`: the
        // `IS_CONTROL` header flag, not the payload shape, is the sole
        // authority over how a frame is interpreted.
        let msg = ControlMessage::Error { code: 1 };
        let frame = DecodedFrame {
            header: FrameHeader::new(0, PROFILE_X25519_HKDF_XCHACHA20POLY1305, 0, 0, 0, 0),
            plaintext: msg.encode(),
        };
        let err = FoctetFramed::<MemoryIo>::decode_control(&frame)
            .expect_err("must reject a frame without IS_CONTROL set");
        assert!(matches!(err, CoreError::UnexpectedControlMessage));
    }

    #[test]
    fn handle_incoming_with_session_ignores_control_shaped_bytes_without_the_flag() {
        // Same flag-confusion property, exercised through the session-aware
        // dispatcher: control-shaped bytes delivered as a *data* frame
        // (IS_CONTROL unset) must surface as plain application data, never be
        // parsed and acted on as a control message.
        let eph_a = EphemeralKeyPair::generate();
        let eph_b = EphemeralKeyPair::generate();
        let ss = eph_a.shared_secret(eph_b.public).expect("shared secret");
        let salt = random_session_salt();
        let keys = KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("traffic keys"));

        let (mut session, _hello) = crate::Session::new_initiator_with_auth(
            crate::RekeyThresholds::default(),
            crate::SessionAuthConfig::unauthenticated_for_testing(),
        );

        let control_shaped_bytes = ControlMessage::Error { code: 7 }.encode();
        let frame = encrypt_frame(&keys, Direction::C2S, 0, 0, 0, &control_shaped_bytes)
            .expect("encrypt frame");

        let io = MemoryIo::default();
        let mut framed = FoctetFramed::new(io, keys, Direction::C2S, Direction::S2C);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        framed.get_mut().push_inbound(&frame.to_bytes());

        let decoded = match Pin::new(&mut framed).poll_next(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => frame,
            other => panic!("expected decoded data frame, got {other:?}"),
        };
        assert_eq!(decoded.header.flags & flags::IS_CONTROL, 0);

        let result = Pin::new(&mut framed)
            .handle_incoming_with_session(&mut session, decoded)
            .expect("data frame must not be treated as control");
        assert_eq!(result, Some(control_shaped_bytes));
    }
}
