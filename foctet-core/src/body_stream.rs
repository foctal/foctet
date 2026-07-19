//! Streaming `application/foctet` body: per-chunk AEAD with end-to-end integrity.
//!
//! The one-shot [`crate::body`] envelope must buffer the whole payload. This
//! module instead seals a payload as an ordered sequence of independently
//! authenticated chunks, so a large HTTP body can be encrypted and decrypted as
//! it streams without holding it all in memory.
//!
//! # Construction
//!
//! A single random content key (CEK) is generated for the stream and wrapped for
//! the recipient with the same ECIES construction as the one-shot envelope
//! (ephemeral X25519 → HKDF → AEAD key-wrap). The wrapped key, a random 16-byte
//! per-stream nonce prefix, and the recipient key id travel once in a **stream
//! header** (prologue). Each chunk is then sealed with the CEK under a unique
//! nonce `prefix || chunk_index` and authenticates, as associated data, the full
//! stream header, the chunk index, a flags byte, and the caller-supplied context.
//!
//! # Security properties
//!
//! - **Per-chunk AEAD, unique nonces.** Every chunk uses a distinct
//!   `(content key, nonce)` because the 8-byte big-endian chunk index is part of
//!   the nonce and the 16-byte prefix is unique per stream.
//! - **Truncation and extension resistance.** Exactly one chunk carries the
//!   authenticated `FINAL` flag. A receiver only treats the stream as complete
//!   after it opens that chunk ([`StreamOpener::is_finished`]); a dropped tail is
//!   detected as an unfinished stream, and any chunk after the final one (or a
//!   forged extra chunk, which cannot be decrypted) is rejected.
//! - **Ordering.** Chunk indices are sequential and checked, so reordering,
//!   gaps, or duplicates fail closed.
//! - **Context / replay binding.** The `context` bytes are bound into every
//!   chunk's AAD, so a captured stream cannot be replayed onto a different
//!   request when the context carries a unique message id (see `foctet-http`).
//!
//! # Cancellation
//!
//! An aborted stream simply never delivers a `FINAL` chunk; the receiver detects
//! this via [`StreamOpener::is_finished`] returning `false` and MUST discard the
//! partial plaintext. A truncated and a cancelled stream are indistinguishable,
//! which is the safe outcome.

use bytes::{Buf, BytesMut};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use getrandom::SysRng;
use rand_core::{TryRng, UnwrapErr};
use zeroize::Zeroizing;

use crate::body::{
    BodyEnvelopeError, BodyEnvelopeLimits, CONTENT_KEY_LEN, TAG_LEN, unwrap_content_key,
    wrap_content_key,
};
use x25519_dalek::{PublicKey, StaticSecret};

/// Magic marker for a streaming body header (`FOCTETHS` = Foctet HTTP Stream).
pub const STREAM_MAGIC: [u8; 8] = *b"FOCTETHS";
/// Streaming body wire version.
pub const STREAM_VERSION_V0: u8 = 0x01;
/// Streaming body cryptographic profile (X25519 + HKDF + XChaCha20-Poly1305).
pub const STREAM_PROFILE_V0: u8 = 0x01;
/// Length of the random per-stream nonce prefix in bytes.
pub const STREAM_NONCE_PREFIX_LEN: usize = 16;
/// Per-chunk frame overhead (index + flags + ct_len fields), excluding the AEAD
/// tag carried inside the ciphertext.
pub const STREAM_CHUNK_OVERHEAD: usize = 8 + 1 + 4;

/// Flag bit marking the final chunk of a stream.
const FLAG_FINAL: u8 = 1 << 0;

fn chunk_nonce(prefix: &[u8; STREAM_NONCE_PREFIX_LEN], index: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..STREAM_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[STREAM_NONCE_PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    nonce
}

/// Builds the per-chunk AEAD associated data: stream header ‖ index ‖ flags ‖ context.
fn chunk_aad(header: &[u8], index: u64, flags: u8, context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 8 + 1 + context.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(flags);
    aad.extend_from_slice(context);
    aad
}

fn encode_stream_header(
    nonce_prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    eph_pub: &[u8; 32],
    recipient_key_id: &[u8],
    wrapped_key: &[u8],
) -> Result<Vec<u8>, BodyEnvelopeError> {
    let key_id_len = u16::try_from(recipient_key_id.len())
        .map_err(|_| BodyEnvelopeError::LimitExceeded("key_id_len"))?;
    let wrapped_len = u16::try_from(wrapped_key.len())
        .map_err(|_| BodyEnvelopeError::LimitExceeded("wrapped_key_len"))?;

    let mut out = Vec::with_capacity(
        STREAM_MAGIC.len()
            + 2
            + STREAM_NONCE_PREFIX_LEN
            + 32
            + 2
            + recipient_key_id.len()
            + 2
            + wrapped_key.len(),
    );
    out.extend_from_slice(&STREAM_MAGIC);
    out.push(STREAM_VERSION_V0);
    out.push(STREAM_PROFILE_V0);
    out.extend_from_slice(nonce_prefix);
    out.extend_from_slice(eph_pub);
    out.extend_from_slice(&key_id_len.to_be_bytes());
    out.extend_from_slice(recipient_key_id);
    out.extend_from_slice(&wrapped_len.to_be_bytes());
    out.extend_from_slice(wrapped_key);
    Ok(out)
}

struct ParsedStreamHeader {
    nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    eph_pub: [u8; 32],
    key_id: Vec<u8>,
    wrapped_key: Vec<u8>,
    header_len: usize,
}

fn parse_stream_header(
    header: &[u8],
    limits: &BodyEnvelopeLimits,
) -> Result<ParsedStreamHeader, BodyEnvelopeError> {
    if header.len() > limits.max_header_bytes {
        return Err(BodyEnvelopeError::LimitExceeded("header_len"));
    }
    let mut cur = 0usize;
    let take = |buf: &[u8], cur: &mut usize, n: usize| -> Result<Vec<u8>, BodyEnvelopeError> {
        let end = cur.checked_add(n).ok_or(BodyEnvelopeError::Truncated)?;
        if end > buf.len() {
            return Err(BodyEnvelopeError::Truncated);
        }
        let out = buf[*cur..end].to_vec();
        *cur = end;
        Ok(out)
    };

    if take(header, &mut cur, STREAM_MAGIC.len())? != STREAM_MAGIC {
        return Err(BodyEnvelopeError::InvalidHeader("magic"));
    }
    let version = take(header, &mut cur, 1)?[0];
    if version != STREAM_VERSION_V0 {
        return Err(BodyEnvelopeError::UnsupportedVersion(version));
    }
    let profile = take(header, &mut cur, 1)?[0];
    if profile != STREAM_PROFILE_V0 {
        return Err(BodyEnvelopeError::UnsupportedProfile(profile));
    }

    let mut nonce_prefix = [0u8; STREAM_NONCE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&take(header, &mut cur, STREAM_NONCE_PREFIX_LEN)?);
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&take(header, &mut cur, 32)?);

    let key_id_len = u16::from_be_bytes(
        take(header, &mut cur, 2)?
            .try_into()
            .map_err(|_| BodyEnvelopeError::Truncated)?,
    ) as usize;
    if key_id_len == 0 || key_id_len > limits.max_key_id_len {
        return Err(BodyEnvelopeError::InvalidHeader("key_id_len"));
    }
    let key_id = take(header, &mut cur, key_id_len)?;

    let wrapped_len = u16::from_be_bytes(
        take(header, &mut cur, 2)?
            .try_into()
            .map_err(|_| BodyEnvelopeError::Truncated)?,
    ) as usize;
    if wrapped_len != CONTENT_KEY_LEN + TAG_LEN {
        return Err(BodyEnvelopeError::InvalidHeader("wrapped_key_len"));
    }
    let wrapped_key = take(header, &mut cur, wrapped_len)?;

    Ok(ParsedStreamHeader {
        nonce_prefix,
        eph_pub,
        key_id,
        wrapped_key,
        header_len: cur,
    })
}

/// Seals a payload as an ordered sequence of authenticated chunks.
///
/// Create one with [`StreamSealer::new`], send the returned header bytes first,
/// then call [`StreamSealer::seal_chunk`] for each chunk, passing `is_final =
/// true` for the last.
pub struct StreamSealer {
    cipher: XChaCha20Poly1305,
    nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    header: Vec<u8>,
    context: Vec<u8>,
    next_index: u64,
    finished: bool,
    max_chunk_plaintext: usize,
}

impl StreamSealer {
    /// Creates a sealer for `recipient_public_key` and returns `(sealer,
    /// stream_header_bytes)`. Send `stream_header_bytes` before any chunk.
    ///
    /// `context` is bound into every chunk's AEAD (empty is allowed and is
    /// byte-compatible with an empty-context opener).
    pub fn new(
        recipient_public_key: [u8; 32],
        recipient_key_id: &[u8],
        context: &[u8],
        limits: &BodyEnvelopeLimits,
    ) -> Result<(Self, Vec<u8>), BodyEnvelopeError> {
        if context.len() > limits.max_context_len {
            return Err(BodyEnvelopeError::LimitExceeded("context_len"));
        }
        if recipient_key_id.is_empty() {
            return Err(BodyEnvelopeError::InvalidHeader("empty recipient key id"));
        }
        if recipient_key_id.len() > limits.max_key_id_len {
            return Err(BodyEnvelopeError::LimitExceeded("key_id_len"));
        }

        let mut content_key = Zeroizing::new([0u8; CONTENT_KEY_LEN]);
        SysRng
            .try_fill_bytes(&mut content_key[..])
            .expect("OS random number generator is unavailable");
        let mut nonce_prefix = [0u8; STREAM_NONCE_PREFIX_LEN];
        SysRng
            .try_fill_bytes(&mut nonce_prefix)
            .expect("OS random number generator is unavailable");

        let eph_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let eph_pub = PublicKey::from(&eph_priv).to_bytes();
        let wrapped_key = wrap_content_key(
            &content_key,
            recipient_public_key,
            eph_priv,
            eph_pub,
            recipient_key_id,
        )?;

        let header = encode_stream_header(&nonce_prefix, &eph_pub, recipient_key_id, &wrapped_key)?;
        if header.len() > limits.max_header_bytes {
            return Err(BodyEnvelopeError::LimitExceeded("header_len"));
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&content_key[..])
            .map_err(|_| BodyEnvelopeError::EncryptFailed)?;

        let sealer = Self {
            cipher,
            nonce_prefix,
            header: header.clone(),
            context: context.to_vec(),
            next_index: 0,
            finished: false,
            max_chunk_plaintext: limits.max_payload_len.saturating_sub(TAG_LEN),
        };
        Ok((sealer, header))
    }

    /// Returns the stream header bytes (the prologue to send before chunks).
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// Seals one chunk; pass `is_final = true` for the last chunk of the stream.
    ///
    /// Fails with [`BodyEnvelopeError::StreamFinished`] if called after the final
    /// chunk.
    pub fn seal_chunk(
        &mut self,
        plaintext: &[u8],
        is_final: bool,
    ) -> Result<Vec<u8>, BodyEnvelopeError> {
        if self.finished {
            return Err(BodyEnvelopeError::StreamFinished);
        }
        if plaintext.len() > self.max_chunk_plaintext {
            return Err(BodyEnvelopeError::LimitExceeded("chunk_plaintext"));
        }

        let index = self.next_index;
        let flags = if is_final { FLAG_FINAL } else { 0 };
        let nonce = chunk_nonce(&self.nonce_prefix, index);
        let aad = chunk_aad(&self.header, index, flags, &self.context);

        let ciphertext = self
            .cipher
            .encrypt(
                &XNonce::try_from(&nonce[..]).expect("fixed-size nonce"),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| BodyEnvelopeError::EncryptFailed)?;

        let ct_len = u32::try_from(ciphertext.len())
            .map_err(|_| BodyEnvelopeError::LimitExceeded("chunk_ct_len"))?;

        let mut out = Vec::with_capacity(STREAM_CHUNK_OVERHEAD + ciphertext.len());
        out.extend_from_slice(&index.to_be_bytes());
        out.push(flags);
        out.extend_from_slice(&ct_len.to_be_bytes());
        out.extend_from_slice(&ciphertext);

        self.next_index = self.next_index.wrapping_add(1);
        if is_final {
            self.finished = true;
        }
        Ok(out)
    }

    /// Returns whether the final chunk has been sealed.
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

/// One decrypted stream chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedChunk {
    /// Decrypted chunk payload bytes.
    pub plaintext: Vec<u8>,
    /// Whether this was the final chunk of the stream.
    pub is_final: bool,
}

/// Opens a stream sealed by [`StreamSealer`], chunk by chunk.
///
/// Create one from the stream header with [`StreamOpener::new`], then call
/// [`StreamOpener::open_chunk`] for each received chunk. **After the stream you
/// MUST check [`StreamOpener::is_finished`]** — a `false` result means the
/// stream was truncated or cancelled and the assembled plaintext must be
/// discarded.
pub struct StreamOpener {
    cipher: XChaCha20Poly1305,
    nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    header: Vec<u8>,
    context: Vec<u8>,
    expected_index: u64,
    finished: bool,
    max_chunk_ct: usize,
}

impl StreamOpener {
    /// Parses the stream `header`, unwraps the content key with
    /// `recipient_secret_key`, and prepares to open chunks bound to `context`.
    pub fn new(
        recipient_secret_key: [u8; 32],
        header: &[u8],
        context: &[u8],
        limits: &BodyEnvelopeLimits,
    ) -> Result<Self, BodyEnvelopeError> {
        if context.len() > limits.max_context_len {
            return Err(BodyEnvelopeError::LimitExceeded("context_len"));
        }
        let parsed = parse_stream_header(header, limits)?;
        let content_key = unwrap_content_key(
            &parsed.wrapped_key,
            &parsed.key_id,
            recipient_secret_key,
            parsed.eph_pub,
        )?;
        let cipher = XChaCha20Poly1305::new_from_slice(&content_key)
            .map_err(|_| BodyEnvelopeError::KeyUnwrapFailed)?;

        Ok(Self {
            cipher,
            nonce_prefix: parsed.nonce_prefix,
            header: header[..parsed.header_len].to_vec(),
            context: context.to_vec(),
            expected_index: 0,
            finished: false,
            max_chunk_ct: limits.max_payload_len,
        })
    }

    /// Opens one received chunk into its plaintext.
    ///
    /// Fails closed on an out-of-order/duplicate index
    /// ([`BodyEnvelopeError::ChunkOutOfOrder`]), on any chunk after the final one
    /// ([`BodyEnvelopeError::StreamFinished`]), or on authentication failure.
    pub fn open_chunk(&mut self, chunk: &[u8]) -> Result<DecodedChunk, BodyEnvelopeError> {
        if self.finished {
            return Err(BodyEnvelopeError::StreamFinished);
        }
        if chunk.len() < STREAM_CHUNK_OVERHEAD {
            return Err(BodyEnvelopeError::Truncated);
        }

        let index = u64::from_be_bytes(chunk[0..8].try_into().expect("8 bytes"));
        let flags = chunk[8];
        let ct_len = u32::from_be_bytes(chunk[9..13].try_into().expect("4 bytes")) as usize;
        let ciphertext = &chunk[STREAM_CHUNK_OVERHEAD..];
        if ciphertext.len() != ct_len {
            return Err(BodyEnvelopeError::Truncated);
        }
        if ct_len > self.max_chunk_ct {
            return Err(BodyEnvelopeError::LimitExceeded("chunk_ct_len"));
        }
        if index != self.expected_index {
            return Err(BodyEnvelopeError::ChunkOutOfOrder);
        }
        // Only the FINAL flag is defined; reject unknown flag bits so they cannot
        // be flipped without breaking authentication-equivalent expectations.
        if flags & !FLAG_FINAL != 0 {
            return Err(BodyEnvelopeError::InvalidHeader("chunk flags"));
        }

        let nonce = chunk_nonce(&self.nonce_prefix, index);
        let aad = chunk_aad(&self.header, index, flags, &self.context);
        let plaintext = self
            .cipher
            .decrypt(
                &XNonce::try_from(&nonce[..]).expect("fixed-size nonce"),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| BodyEnvelopeError::DecryptFailed)?;

        self.expected_index = self.expected_index.wrapping_add(1);
        let is_final = flags & FLAG_FINAL != 0;
        if is_final {
            self.finished = true;
        }
        Ok(DecodedChunk {
            plaintext,
            is_final,
        })
    }

    /// Returns whether the final chunk has been opened. A complete stream MUST
    /// end with this returning `true`; otherwise the stream was truncated or
    /// cancelled and its plaintext must be discarded.
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

/// Fixed-size prefix of a stream header before the variable key-id / wrapped-key
/// fields: magic(8) + version(1) + profile(1) + nonce_prefix + eph_pub(32).
const STREAM_HEADER_FIXED_PREFIX: usize = 8 + 1 + 1 + STREAM_NONCE_PREFIX_LEN + 32;

/// Returns the full stream-header length once enough bytes are buffered to
/// determine it, `None` if more bytes are needed, or an error if the
/// length-prefix fields are invalid.
fn stream_header_len(
    buf: &[u8],
    limits: &BodyEnvelopeLimits,
) -> Result<Option<usize>, BodyEnvelopeError> {
    if buf.len() < STREAM_HEADER_FIXED_PREFIX + 2 {
        return Ok(None);
    }
    let key_id_len = u16::from_be_bytes([
        buf[STREAM_HEADER_FIXED_PREFIX],
        buf[STREAM_HEADER_FIXED_PREFIX + 1],
    ]) as usize;
    if key_id_len == 0 || key_id_len > limits.max_key_id_len {
        return Err(BodyEnvelopeError::InvalidHeader("key_id_len"));
    }
    let wrapped_off = STREAM_HEADER_FIXED_PREFIX + 2 + key_id_len;
    if buf.len() < wrapped_off + 2 {
        return Ok(None);
    }
    let wrapped_len = u16::from_be_bytes([buf[wrapped_off], buf[wrapped_off + 1]]) as usize;
    if wrapped_len != CONTENT_KEY_LEN + TAG_LEN {
        return Err(BodyEnvelopeError::InvalidHeader("wrapped_key_len"));
    }
    let total = wrapped_off + 2 + wrapped_len;
    if total > limits.max_header_bytes {
        return Err(BodyEnvelopeError::LimitExceeded("header_len"));
    }
    // Only report the header as ready once all of its bytes have arrived.
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(total))
}

/// One framed unit produced by a [`StreamFrameDecoder`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamItem {
    /// The stream header (prologue), produced once before any chunk. Feed it to
    /// [`StreamOpener::new`].
    Header(Vec<u8>),
    /// One complete chunk frame. Feed it to [`StreamOpener::open_chunk`].
    Chunk(Vec<u8>),
}

/// Reassembles a streaming body's self-delimiting frames from arbitrarily split
/// byte chunks (e.g. HTTP body data frames that do not align to Foctet chunk
/// boundaries).
///
/// Push received bytes with [`Self::push`], then drain complete frames with
/// [`Self::decode_next`]: it yields exactly one [`StreamItem::Header`] first,
/// then [`StreamItem::Chunk`]s, returning `None` whenever more bytes are needed.
/// This makes the streaming body usable over any byte transport — an axum/hyper
/// request body, a Cloudflare Workers `ReadableStream`, or a raw socket.
pub struct StreamFrameDecoder {
    buf: BytesMut,
    header_done: bool,
    limits: BodyEnvelopeLimits,
}

impl StreamFrameDecoder {
    /// Creates a decoder bounded by `limits` (header size, chunk ciphertext size).
    pub fn new(limits: &BodyEnvelopeLimits) -> Self {
        Self {
            buf: BytesMut::new(),
            header_done: false,
            limits: limits.clone(),
        }
    }

    /// Appends received bytes to the internal buffer.
    ///
    /// At most one maximum-sized undecoded frame may be buffered. Callers
    /// should drain [`Self::decode_next`] between input reads; oversized reads
    /// are rejected so transport backpressure cannot turn this decoder into an
    /// unbounded queue.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), BodyEnvelopeError> {
        let max_buffered = self.limits.max_header_bytes.max(
            STREAM_CHUNK_OVERHEAD
                .checked_add(self.limits.max_payload_len)
                .ok_or(BodyEnvelopeError::LimitExceeded("stream_buffer_len"))?,
        );
        let new_len = self
            .buf
            .len()
            .checked_add(bytes.len())
            .ok_or(BodyEnvelopeError::LimitExceeded("stream_buffer_len"))?;
        if new_len > max_buffered {
            return Err(BodyEnvelopeError::LimitExceeded("stream_buffer_len"));
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Drains the next complete frame, or `None` if more bytes are needed.
    pub fn decode_next(&mut self) -> Result<Option<StreamItem>, BodyEnvelopeError> {
        if !self.header_done {
            return match stream_header_len(&self.buf, &self.limits)? {
                None => Ok(None),
                Some(len) => {
                    let header = self.buf[..len].to_vec();
                    self.buf.advance(len);
                    self.header_done = true;
                    Ok(Some(StreamItem::Header(header)))
                }
            };
        }

        if self.buf.len() < STREAM_CHUNK_OVERHEAD {
            return Ok(None);
        }
        // Chunk layout: index(8) ‖ flags(1) ‖ ct_len(4) ‖ ciphertext.
        let ct_len =
            u32::from_be_bytes([self.buf[9], self.buf[10], self.buf[11], self.buf[12]]) as usize;
        if ct_len > self.limits.max_payload_len {
            return Err(BodyEnvelopeError::LimitExceeded("chunk_ct_len"));
        }
        let total = STREAM_CHUNK_OVERHEAD + ct_len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let chunk = self.buf[..total].to_vec();
        self.buf.advance(total);
        Ok(Some(StreamItem::Chunk(chunk)))
    }

    /// Returns whether the header has been decoded yet.
    pub fn header_decoded(&self) -> bool {
        self.header_done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;
    use rand_core::UnwrapErr;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn recipient() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let public = PublicKey::from(&secret).to_bytes();
        (secret.to_bytes(), public)
    }

    fn seal_stream(public: [u8; 32], context: &[u8], chunks: &[&[u8]]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let limits = BodyEnvelopeLimits::default();
        let (mut sealer, header) =
            StreamSealer::new(public, b"kid", context, &limits).expect("sealer");
        let mut out = Vec::new();
        for (i, c) in chunks.iter().enumerate() {
            let is_final = i + 1 == chunks.len();
            out.push(sealer.seal_chunk(c, is_final).expect("seal chunk"));
        }
        assert!(sealer.is_finished());
        (header, out)
    }

    #[test]
    fn decoder_reassembles_frames_from_arbitrary_byte_splits() {
        let (secret, public) = recipient();
        let context = b"ctx";
        let parts: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma", b"delta"];
        let (header, chunks) = seal_stream(public, context, &parts);

        // The whole wire stream: header followed by the self-delimiting chunks.
        let mut wire = header.clone();
        for c in &chunks {
            wire.extend_from_slice(c);
        }

        let limits = BodyEnvelopeLimits::default();
        let mut decoder = StreamFrameDecoder::new(&limits);
        let mut opener: Option<StreamOpener> = None;
        let mut assembled = Vec::new();

        // Feed the wire 3 bytes at a time to exercise frames split across pushes.
        for piece in wire.chunks(3) {
            decoder.push(piece).expect("push");
            while let Some(item) = decoder.decode_next().expect("decode") {
                match item {
                    StreamItem::Header(h) => {
                        assert_eq!(h, header);
                        opener =
                            Some(StreamOpener::new(secret, &h, context, &limits).expect("opener"));
                    }
                    StreamItem::Chunk(c) => {
                        let decoded = opener
                            .as_mut()
                            .expect("header before chunks")
                            .open_chunk(&c)
                            .expect("open chunk");
                        assembled.extend_from_slice(&decoded.plaintext);
                    }
                }
            }
        }

        assert!(opener.expect("opener built").is_finished());
        assert_eq!(assembled, b"alphabetagammadelta");
    }

    #[test]
    fn decoder_rejects_an_oversized_input_queue() {
        let limits = BodyEnvelopeLimits {
            max_header_bytes: 128,
            max_payload_len: 256,
            ..BodyEnvelopeLimits::default()
        };
        let mut decoder = StreamFrameDecoder::new(&limits);
        let oversized = vec![0u8; STREAM_CHUNK_OVERHEAD + limits.max_payload_len + 1];
        assert!(matches!(
            decoder.push(&oversized),
            Err(BodyEnvelopeError::LimitExceeded("stream_buffer_len"))
        ));
    }

    #[test]
    fn stream_roundtrip_reassembles_payload() {
        let (secret, public) = recipient();
        let context = b"foctet-http-ctx-v1|POST|/upload";
        let parts: Vec<&[u8]> = vec![b"hello ", b"streaming ", b"world"];
        let (header, chunks) = seal_stream(public, context, &parts);

        let limits = BodyEnvelopeLimits::default();
        let mut opener = StreamOpener::new(secret, &header, context, &limits).expect("opener");
        let mut assembled = Vec::new();
        for chunk in &chunks {
            let decoded = opener.open_chunk(chunk).expect("open chunk");
            assembled.extend_from_slice(&decoded.plaintext);
        }
        assert!(opener.is_finished());
        assert_eq!(assembled, b"hello streaming world");
    }

    #[test]
    fn truncation_is_detected_as_unfinished() {
        let (secret, public) = recipient();
        let parts: Vec<&[u8]> = vec![b"part0", b"part1", b"part2"];
        let (header, chunks) = seal_stream(public, b"", &parts);

        let limits = BodyEnvelopeLimits::default();
        let mut opener = StreamOpener::new(secret, &header, b"", &limits).expect("opener");
        // Deliver all but the final chunk.
        for chunk in &chunks[..chunks.len() - 1] {
            opener.open_chunk(chunk).expect("open chunk");
        }
        // The stream never reached its FINAL chunk: it must be treated as
        // incomplete and the partial plaintext discarded.
        assert!(!opener.is_finished());
    }

    #[test]
    fn extension_after_final_is_rejected() {
        let (secret, public) = recipient();
        let parts: Vec<&[u8]> = vec![b"only-chunk"];
        let (header, chunks) = seal_stream(public, b"", &parts);

        let limits = BodyEnvelopeLimits::default();
        let mut opener = StreamOpener::new(secret, &header, b"", &limits).expect("opener");
        opener.open_chunk(&chunks[0]).expect("final chunk");
        assert!(opener.is_finished());
        // A second chunk after the final one must be rejected.
        let err = opener
            .open_chunk(&chunks[0])
            .expect_err("post-final chunk must be rejected");
        assert!(matches!(err, BodyEnvelopeError::StreamFinished));
    }

    #[test]
    fn reordered_chunk_is_rejected() {
        let (secret, public) = recipient();
        let parts: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let (header, chunks) = seal_stream(public, b"", &parts);

        let limits = BodyEnvelopeLimits::default();
        let mut opener = StreamOpener::new(secret, &header, b"", &limits).expect("opener");
        opener.open_chunk(&chunks[0]).expect("chunk 0");
        // Skipping chunk 1 and delivering chunk 2 must fail closed.
        let err = opener
            .open_chunk(&chunks[2])
            .expect_err("out-of-order chunk must be rejected");
        assert!(matches!(err, BodyEnvelopeError::ChunkOutOfOrder));
    }

    #[test]
    fn wrong_context_fails_authentication() {
        let (secret, public) = recipient();
        let (header, chunks) = seal_stream(public, b"context-A", &[b"data"]);

        let limits = BodyEnvelopeLimits::default();
        let mut opener = StreamOpener::new(secret, &header, b"context-B", &limits).expect("opener");
        let err = opener
            .open_chunk(&chunks[0])
            .expect_err("mismatched context must fail authentication");
        assert!(matches!(err, BodyEnvelopeError::DecryptFailed));
    }

    #[test]
    fn tampered_chunk_fails_authentication() {
        let (secret, public) = recipient();
        let (header, mut chunks) = seal_stream(public, b"", &[b"sensitive"]);

        // Flip a ciphertext byte.
        let last = chunks[0].len() - 1;
        chunks[0][last] ^= 0xff;

        let limits = BodyEnvelopeLimits::default();
        let mut opener = StreamOpener::new(secret, &header, b"", &limits).expect("opener");
        let err = opener
            .open_chunk(&chunks[0])
            .expect_err("tampered ciphertext must fail");
        assert!(matches!(err, BodyEnvelopeError::DecryptFailed));
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let (_secret, public) = recipient();
        let (other_secret, _other_public) = recipient();
        let (header, _chunks) = seal_stream(public, b"", &[b"data"]);

        let limits = BodyEnvelopeLimits::default();
        let result = StreamOpener::new(other_secret, &header, b"", &limits);
        assert!(matches!(result, Err(BodyEnvelopeError::KeyUnwrapFailed)));
    }
}
