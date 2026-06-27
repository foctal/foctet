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

use foctet_core::{BodyEnvelopeLimits, DecodedChunk, StreamOpener, StreamSealer};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryReplayStore;
    use http::Request;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn recipient() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(OsRng);
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
