//! Streaming (chunked) HTTP bodies bound to the protected context.
//!
//! This is the streaming counterpart to the one-shot
//! [`HttpSealer::seal_request_with_context`](crate::HttpSealer) path: instead of
//! buffering the whole body, a large request body is sealed and opened as an
//! ordered sequence of per-chunk-authenticated frames
//! ([`foctet_core::body_stream`]), each binding the same HTTP protected context
//! (method, path, query, message id, timestamp, expiry). The unique message id
//! makes the whole stream single-use via a [`ReplayStore`].
//!
//! # Wire shape
//!
//! Send the carrier headers and the **stream header** (returned by
//! [`HttpStreamSealer::for_request`]) first, then each chunk from
//! [`HttpStreamSealer::seal_chunk`]. The receiver reconstructs the carrier from
//! the headers, validates freshness and single use, then opens chunks with
//! [`HttpStreamOpener`].
//!
//! # Completion
//!
//! A complete stream ends with a chunk for which
//! [`HttpStreamOpener::is_finished`] becomes `true`. If the request body ends
//! before that (truncation or a cancelled upload), the assembled plaintext MUST
//! be discarded — `is_finished()` stays `false`.

use foctet_core::{
    BodyEnvelopeError, BodyEnvelopeLimits, DecodedChunk, StreamFrameDecoder, StreamItem,
    StreamOpener, StreamSealer,
};

use crate::{
    ContextBinding, ContextCarrier, HttpError, ProtectedContext, ReplayCheck, ReplayStore,
};

/// Seals an HTTP request body as a context-bound stream of chunks.
pub struct HttpStreamSealer {
    inner: StreamSealer,
}

impl HttpStreamSealer {
    /// Begins a context-bound request stream.
    ///
    /// Returns the sealer and the **stream header** bytes to send before any
    /// chunk. Apply `carrier` to the outgoing request headers (with
    /// [`ContextCarrier::apply_to_headers`]) so the opener reconstructs the same
    /// protected context.
    pub fn for_request(
        parts: &http::request::Parts,
        carrier: &ContextCarrier,
        binding: ContextBinding,
        recipient_public_key: [u8; 32],
        recipient_key_id: &[u8],
        limits: &BodyEnvelopeLimits,
    ) -> Result<(Self, Vec<u8>), HttpError> {
        let context = ProtectedContext::for_request(parts, carrier.clone(), binding);
        let aad = context.to_aad_bytes();
        let (inner, header) =
            StreamSealer::new(recipient_public_key, recipient_key_id, &aad, limits)
                .map_err(HttpError::SealFailed)?;
        Ok((Self { inner }, header))
    }

    /// Seals one body chunk; pass `is_final = true` for the last chunk.
    pub fn seal_chunk(&mut self, plaintext: &[u8], is_final: bool) -> Result<Vec<u8>, HttpError> {
        self.inner
            .seal_chunk(plaintext, is_final)
            .map_err(HttpError::SealFailed)
    }

    /// Returns whether the final chunk has been sealed.
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

/// Opens a context-bound HTTP request body stream.
pub struct HttpStreamOpener {
    inner: StreamOpener,
}

impl HttpStreamOpener {
    /// Begins opening a context-bound request stream.
    ///
    /// Parses the carrier from the request headers, validates freshness, and
    /// enforces single use against `store` (the message id is consumed once for
    /// the whole stream), then prepares to open chunks bound to the protected
    /// context. `stream_header` is the prologue produced by
    /// [`HttpStreamSealer::for_request`].
    #[allow(clippy::too_many_arguments)]
    pub fn for_request<S>(
        parts: &http::request::Parts,
        recipient_secret_key: [u8; 32],
        stream_header: &[u8],
        store: &S,
        now_secs: u64,
        max_skew_secs: u64,
        binding: ContextBinding,
        limits: &BodyEnvelopeLimits,
    ) -> Result<Self, HttpError>
    where
        S: ReplayStore + ?Sized,
    {
        let carrier = ContextCarrier::from_headers(&parts.headers)?;
        let context = ProtectedContext::for_request(parts, carrier.clone(), binding);
        context.validate_freshness(now_secs, max_skew_secs)?;

        match ReplayStore::check_and_insert(
            store,
            &carrier.message_id,
            carrier.expiry_secs,
            now_secs,
        )
        .map_err(HttpError::ReplayStore)?
        {
            ReplayCheck::Accepted => {}
            ReplayCheck::Replay => return Err(HttpError::Replayed),
        }

        let aad = context.to_aad_bytes();
        let inner = StreamOpener::new(recipient_secret_key, stream_header, &aad, limits)
            .map_err(HttpError::OpenFailed)?;
        Ok(Self { inner })
    }

    /// Opens one received body chunk into its plaintext.
    pub fn open_chunk(&mut self, chunk: &[u8]) -> Result<DecodedChunk, HttpError> {
        self.inner.open_chunk(chunk).map_err(HttpError::OpenFailed)
    }

    /// Returns whether the final chunk has been opened. A complete stream MUST
    /// end with this `true`; otherwise it was truncated or cancelled and its
    /// plaintext must be discarded.
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

/// Turn-key, framework-agnostic reader for a context-bound streaming request
/// body.
///
/// Feed it the raw body bytes as they arrive — from an `axum`/`hyper` body data
/// stream, a Cloudflare Workers `ReadableStream`, or any other byte source — and
/// it incrementally reassembles the stream frames ([`StreamFrameDecoder`]),
/// builds an [`HttpStreamOpener`] when the header completes (validating freshness
/// and single use against the replay store at that point), and returns decrypted
/// plaintext chunks.
///
/// After the body ends, call [`HttpRequestStreamReader::finish`]: it errors with
/// [`HttpError::StreamIncomplete`] unless the authenticated final chunk was seen,
/// so a truncated or cancelled upload is rejected rather than silently accepted.
///
/// ```rust,ignore
/// // axum handler sketch
/// let (parts, body) = request.into_parts();
/// let mut reader = HttpRequestStreamReader::new(
///     parts, recipient_secret_key, &store, now, skew, ContextBinding::default(), &limits);
/// let mut stream = body.into_data_stream();
/// while let Some(frame) = stream.next().await {
///     for plaintext in reader.push(&frame?)? {
///         sink.write_all(&plaintext).await?; // process without buffering the whole body
///     }
/// }
/// reader.finish()?; // rejects a truncated upload
/// ```
pub struct HttpRequestStreamReader<'s, S: ?Sized> {
    decoder: StreamFrameDecoder,
    opener: Option<HttpStreamOpener>,
    parts: http::request::Parts,
    recipient_secret_key: [u8; 32],
    store: &'s S,
    now_secs: u64,
    max_skew_secs: u64,
    binding: ContextBinding,
    limits: BodyEnvelopeLimits,
}

impl<'s, S: ReplayStore + ?Sized> HttpRequestStreamReader<'s, S> {
    /// Creates a reader bound to the request `parts` and replay `store`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parts: http::request::Parts,
        recipient_secret_key: [u8; 32],
        store: &'s S,
        now_secs: u64,
        max_skew_secs: u64,
        binding: ContextBinding,
        limits: &BodyEnvelopeLimits,
    ) -> Self {
        Self {
            decoder: StreamFrameDecoder::new(limits),
            opener: None,
            parts,
            recipient_secret_key,
            store,
            now_secs,
            max_skew_secs,
            binding,
            limits: limits.clone(),
        }
    }

    /// Feeds received body bytes and returns any plaintext chunks now available
    /// (possibly none, if a frame is still incomplete).
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, HttpError> {
        self.decoder.push(bytes);
        let mut out = Vec::new();
        while let Some(item) = self.decoder.decode_next().map_err(HttpError::OpenFailed)? {
            match item {
                StreamItem::Header(header) => {
                    if self.opener.is_some() {
                        return Err(HttpError::OpenFailed(BodyEnvelopeError::InvalidHeader(
                            "duplicate stream header",
                        )));
                    }
                    self.opener = Some(HttpStreamOpener::for_request(
                        &self.parts,
                        self.recipient_secret_key,
                        &header,
                        self.store,
                        self.now_secs,
                        self.max_skew_secs,
                        self.binding,
                        &self.limits,
                    )?);
                }
                StreamItem::Chunk(chunk) => {
                    let opener = self.opener.as_mut().ok_or(HttpError::OpenFailed(
                        BodyEnvelopeError::InvalidHeader("chunk before stream header"),
                    ))?;
                    out.push(opener.open_chunk(&chunk)?.plaintext);
                }
            }
        }
        Ok(out)
    }

    /// Whether the authenticated final chunk has been opened.
    pub fn is_finished(&self) -> bool {
        self.opener
            .as_ref()
            .is_some_and(HttpStreamOpener::is_finished)
    }

    /// Consumes the reader, succeeding only if the stream reached its final
    /// chunk; otherwise the body was truncated/cancelled
    /// ([`HttpError::StreamIncomplete`]).
    pub fn finish(self) -> Result<(), HttpError> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(HttpError::StreamIncomplete)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryReplayStore;
    use getrandom::SysRng;
    use http::Request;
    use rand_core::UnwrapErr;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn recipient() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let public = PublicKey::from(&secret).to_bytes();
        (secret.to_bytes(), public)
    }

    fn request() -> Request<()> {
        Request::builder()
            .method("POST")
            .uri("https://example.com/upload?id=7")
            .body(())
            .expect("request")
    }

    #[test]
    fn streaming_request_roundtrip_with_replay_protection() {
        let (secret, public) = recipient();
        let limits = BodyEnvelopeLimits::default();
        let now = 1000;

        // Seal: build the carrier, bind it to the request, and seal chunks.
        let carrier = ContextCarrier::generate(now, 60);
        let (mut req_parts, _) = request().into_parts();
        let (mut sealer, header) = HttpStreamSealer::for_request(
            &req_parts,
            &carrier,
            ContextBinding::default(),
            public,
            b"kid",
            &limits,
        )
        .expect("sealer");
        carrier
            .apply_to_headers(&mut req_parts.headers)
            .expect("apply carrier");

        let chunks = vec![
            sealer.seal_chunk(b"streamed ", false).expect("c0"),
            sealer.seal_chunk(b"http ", false).expect("c1"),
            sealer.seal_chunk(b"body", true).expect("c2"),
        ];
        assert!(sealer.is_finished());

        // Open: the opener reconstructs the carrier from the (now populated)
        // request headers, checks freshness + single use, and opens the chunks.
        let store = InMemoryReplayStore::new();
        let mut opener = HttpStreamOpener::for_request(
            &req_parts,
            secret,
            &header,
            &store,
            now,
            5,
            ContextBinding::default(),
            &limits,
        )
        .expect("opener");

        let mut body = Vec::new();
        for chunk in &chunks {
            body.extend_from_slice(&opener.open_chunk(chunk).expect("open chunk").plaintext);
        }
        assert!(opener.is_finished());
        assert_eq!(body, b"streamed http body");

        // The same request opened again is rejected as a replay (the message id
        // was consumed for the whole stream).
        let replay = HttpStreamOpener::for_request(
            &req_parts,
            secret,
            &header,
            &store,
            now,
            5,
            ContextBinding::default(),
            &limits,
        );
        assert!(matches!(replay, Err(HttpError::Replayed)));
    }

    #[test]
    fn stream_reader_decodes_a_split_body_and_rejects_replay() {
        let (secret, public) = recipient();
        let limits = BodyEnvelopeLimits::default();
        let now = 3000;

        // Seal a stream and lay it out as one contiguous request body:
        // stream header followed by the self-delimiting chunks.
        let carrier = ContextCarrier::generate(now, 60);
        let (mut req_parts, _) = request().into_parts();
        let (mut sealer, header) = HttpStreamSealer::for_request(
            &req_parts,
            &carrier,
            ContextBinding::default(),
            public,
            b"kid",
            &limits,
        )
        .expect("sealer");
        carrier
            .apply_to_headers(&mut req_parts.headers)
            .expect("apply carrier");

        let mut wire = header;
        for part in [b"chunk-one ".as_slice(), b"chunk-two ", b"chunk-three"] {
            let is_final = part == b"chunk-three";
            wire.extend_from_slice(&sealer.seal_chunk(part, is_final).expect("seal"));
        }

        // Drive the reader with 5-byte body pieces (frames split across pushes).
        let store = InMemoryReplayStore::new();
        let mut reader = HttpRequestStreamReader::new(
            req_parts.clone(),
            secret,
            &store,
            now,
            5,
            ContextBinding::default(),
            &limits,
        );
        let mut body = Vec::new();
        for piece in wire.chunks(5) {
            for plaintext in reader.push(piece).expect("push") {
                body.extend_from_slice(&plaintext);
            }
        }
        reader.finish().expect("stream completed");
        assert_eq!(body, b"chunk-one chunk-two chunk-three");

        // A second reader over the same request must be rejected as a replay when
        // its header completes (the message id was already consumed).
        let mut replay_reader = HttpRequestStreamReader::new(
            req_parts,
            secret,
            &store,
            now,
            5,
            ContextBinding::default(),
            &limits,
        );
        assert!(matches!(
            replay_reader.push(&wire),
            Err(HttpError::Replayed)
        ));
    }

    #[test]
    fn stream_reader_finish_rejects_a_truncated_body() {
        let (secret, public) = recipient();
        let limits = BodyEnvelopeLimits::default();
        let now = 3100;

        let carrier = ContextCarrier::generate(now, 60);
        let (mut req_parts, _) = request().into_parts();
        let (mut sealer, header) = HttpStreamSealer::for_request(
            &req_parts,
            &carrier,
            ContextBinding::default(),
            public,
            b"kid",
            &limits,
        )
        .expect("sealer");
        carrier
            .apply_to_headers(&mut req_parts.headers)
            .expect("apply carrier");

        // Only the non-final chunk reaches the reader; the final chunk is dropped.
        let mut wire = header;
        wire.extend_from_slice(&sealer.seal_chunk(b"partial", false).expect("seal"));
        let _final = sealer.seal_chunk(b"rest", true).expect("seal final");

        let store = InMemoryReplayStore::new();
        let mut reader = HttpRequestStreamReader::new(
            req_parts,
            secret,
            &store,
            now,
            5,
            ContextBinding::default(),
            &limits,
        );
        reader.push(&wire).expect("push");
        assert!(matches!(reader.finish(), Err(HttpError::StreamIncomplete)));
    }

    #[test]
    fn streaming_request_truncation_is_detectable() {
        let (secret, public) = recipient();
        let limits = BodyEnvelopeLimits::default();
        let now = 2000;

        let carrier = ContextCarrier::generate(now, 60);
        let (mut req_parts, _) = request().into_parts();
        let (mut sealer, header) = HttpStreamSealer::for_request(
            &req_parts,
            &carrier,
            ContextBinding::default(),
            public,
            b"kid",
            &limits,
        )
        .expect("sealer");
        carrier
            .apply_to_headers(&mut req_parts.headers)
            .expect("apply carrier");

        let c0 = sealer.seal_chunk(b"first", false).expect("c0");
        let _c1_final = sealer.seal_chunk(b"second", true).expect("c1");

        let store = InMemoryReplayStore::new();
        let mut opener = HttpStreamOpener::for_request(
            &req_parts,
            secret,
            &header,
            &store,
            now,
            5,
            ContextBinding::default(),
            &limits,
        )
        .expect("opener");

        opener.open_chunk(&c0).expect("open c0");
        // The final chunk is withheld (truncated/cancelled upload): the stream
        // must not be considered complete.
        assert!(!opener.is_finished());
    }
}
