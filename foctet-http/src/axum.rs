//! Axum adapters built on top of the high-level Foctet HTTP API.
//!
//! These adapters preserve the surrounding HTTP request and response metadata.
//! Only the body bytes are protected by the Foctet envelope.
//!
//! # Body limits and backpressure
//!
//! Every opener bounds the request body (`max_body_bytes`) **before**
//! decryption, so a hostile client cannot make the server buffer or decrypt
//! an unbounded body. Recommended values:
//!
//! - **One-shot envelopes** (`open_request_with_context`): size for your
//!   actual payloads, not your tolerance — typical API bodies fit in
//!   **1–4 MiB**; treat ≥ 16 MiB as a signal to switch to the streaming path.
//!   The whole ciphertext is buffered in memory, so the worst-case memory per
//!   in-flight request is `max_body_bytes` × concurrency; set your HTTP
//!   server's concurrency limit (e.g. `tower::limit::ConcurrencyLimitLayer`)
//!   with that product in mind.
//! - **Streaming bodies** ([`open_request_stream`]): memory use is bounded by
//!   the chunk size (default ≤ 64 KiB sealed) rather than the body size —
//!   prefer it for uploads beyond a few MiB. Backpressure is natural: chunks
//!   are decrypted only as your callback consumes them, so a slow consumer
//!   slows the sender through the HTTP layer's own flow control. Tuning: the
//!   sealer's chunk size trades per-chunk overhead (AEAD tag + frame header,
//!   ~tens of bytes) against buffering granularity — **64 KiB–256 KiB** chunks
//!   are a good default; below ~4 KiB the overhead dominates, above ~1 MiB you
//!   lose backpressure granularity and hold larger buffers.
//!
//! Whichever path you use, reject early: the context (freshness, replay,
//! route binding) is verified from the headers/stream header **before** body
//! chunks are processed, so replayed or expired requests cost no decryption.

use ::axum::body::{Body, to_bytes};
use ::axum::extract::Request as AxumRequest;
use ::axum::response::Response as AxumResponse;
use foctet_core::BodyEnvelopeLimits;
use http_body_util::BodyExt;
use thiserror::Error;

use crate::{
    AsyncReplayStore, ContextBinding, ContextCarrier, HttpError, HttpErrorDisposition,
    HttpOpenOptions, HttpOpener, HttpRequestStreamReader, HttpSealOptions, HttpSealer, ReplayStore,
};

/// Error type for Axum adapter operations.
#[derive(Debug, Error)]
pub enum AxumError {
    /// Reading Axum request body failed.
    #[error("failed to read axum request body")]
    BodyRead(#[source] ::axum::Error),
    /// Foctet HTTP-layer operation failed.
    #[error("foctet http operation failed")]
    Http(#[from] HttpError),
}

impl AxumError {
    /// Classifies the required handling of this request-scoped adapter error.
    ///
    /// An Axum body-read failure can follow partial HTTP-body delivery, so the
    /// protected request must be rejected rather than retried in place.
    pub const fn disposition(&self) -> HttpErrorDisposition {
        match self {
            Self::BodyRead(_) => HttpErrorDisposition::Reject,
            Self::Http(error) => error.disposition(),
        }
    }
}

/// High-level Axum request opener.
#[derive(Clone, Debug)]
pub struct AxumOpener {
    opener: HttpOpener,
    max_body_bytes: usize,
}

/// High-level Axum response sealer.
#[derive(Clone, Debug)]
pub struct AxumSealer {
    sealer: HttpSealer,
}

impl AxumOpener {
    /// Creates an Axum opener with the given Foctet open options and body-size limit.
    pub fn new(options: HttpOpenOptions, max_body_bytes: usize) -> Self {
        Self {
            opener: HttpOpener::new(options),
            max_body_bytes,
        }
    }

    /// Creates an Axum opener from an already-configured HTTP opener.
    pub fn from_http_opener(opener: HttpOpener, max_body_bytes: usize) -> Self {
        Self {
            opener,
            max_body_bytes,
        }
    }

    /// Returns the maximum number of bytes read from an Axum request body.
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Returns the inner HTTP opener.
    pub fn opener(&self) -> &HttpOpener {
        &self.opener
    }

    /// Opens an encrypted Axum request body into plaintext bytes.
    ///
    /// Body-only; no replay protection or HTTP-context binding. Prefer
    /// [`AxumOpener::open_request_with_context`] for production.
    #[deprecated(
        since = "0.3.0",
        note = "stateless full-request protection has no replay defense or HTTP-context \
                binding and is replayable by design; use open_request_with_context (or \
                open_request_with_async_store) with a ReplayStore for production"
    )]
    #[allow(deprecated)]
    pub async fn open_request(
        &self,
        request: AxumRequest,
    ) -> Result<http::Request<Vec<u8>>, AxumError> {
        let (parts, body) = request.into_parts();
        let body_bytes = to_bytes(body, self.max_body_bytes)
            .await
            .map_err(AxumError::BodyRead)?;
        let request = http::Request::from_parts(parts, body_bytes.to_vec());
        self.opener.open_request(request).map_err(AxumError::Http)
    }

    /// Opens an encrypted Axum request, enforcing the bound HTTP protected
    /// context, freshness, and single use against `store`.
    ///
    /// The request body is bounded by `max_body_bytes` before decryption, so
    /// the library — not the application — caps memory use here.
    pub async fn open_request_with_context<S>(
        &self,
        request: AxumRequest,
        store: &S,
        now_secs: u64,
        max_skew_secs: u64,
        binding: ContextBinding,
    ) -> Result<http::Request<Vec<u8>>, AxumError>
    where
        S: ReplayStore + ?Sized,
    {
        let (parts, body) = request.into_parts();
        let body_bytes = to_bytes(body, self.max_body_bytes)
            .await
            .map_err(AxumError::BodyRead)?;
        let request = http::Request::from_parts(parts, body_bytes.to_vec());
        self.opener
            .open_request_with_context(request, store, now_secs, max_skew_secs, binding)
            .map_err(AxumError::Http)
    }

    /// Opens an encrypted Axum request using a durable [`AsyncReplayStore`]
    /// (Redis, Cloudflare KV, a shared SQL table, …) for multi-instance
    /// deployments.
    pub async fn open_request_with_async_store<S>(
        &self,
        request: AxumRequest,
        store: &S,
        now_secs: u64,
        max_skew_secs: u64,
        binding: ContextBinding,
    ) -> Result<http::Request<Vec<u8>>, AxumError>
    where
        S: AsyncReplayStore + ?Sized,
    {
        let (parts, body) = request.into_parts();
        let body_bytes = to_bytes(body, self.max_body_bytes)
            .await
            .map_err(AxumError::BodyRead)?;
        let request = http::Request::from_parts(parts, body_bytes.to_vec());
        self.opener
            .open_request_with_async_store(request, store, now_secs, max_skew_secs, binding)
            .await
            .map_err(AxumError::Http)
    }
}

impl AxumSealer {
    /// Creates an Axum sealer with the given Foctet seal options.
    pub fn new(options: HttpSealOptions) -> Self {
        Self {
            sealer: HttpSealer::new(options),
        }
    }

    /// Creates an Axum sealer from an already-configured HTTP sealer.
    pub fn from_http_sealer(sealer: HttpSealer) -> Self {
        Self { sealer }
    }

    /// Returns the inner HTTP sealer.
    pub fn sealer(&self) -> &HttpSealer {
        &self.sealer
    }

    /// Seals a plaintext HTTP response and converts it into an Axum response.
    pub fn seal_response(
        &self,
        response: http::Response<Vec<u8>>,
    ) -> Result<AxumResponse, AxumError> {
        let encrypted = self.sealer.seal_response(response)?;
        Ok(http_response_vec_to_axum(encrypted))
    }

    /// Seals a plaintext HTTP response with bound protected context and converts
    /// it into an Axum response.
    pub fn seal_response_with_context(
        &self,
        response: http::Response<Vec<u8>>,
        carrier: ContextCarrier,
    ) -> Result<AxumResponse, AxumError> {
        let encrypted = self.sealer.seal_response_with_context(response, carrier)?;
        Ok(http_response_vec_to_axum(encrypted))
    }
}

/// Opens an encrypted Axum request body into plaintext bytes.
#[deprecated(
    since = "0.3.0",
    note = "stateless full-request protection has no replay defense or HTTP-context binding \
            and is replayable by design; use AxumOpener::open_request_with_context with a \
            ReplayStore for production"
)]
#[allow(deprecated)]
pub async fn open_axum_request_body(
    request: AxumRequest,
    recipient_secret_key: [u8; 32],
    max_body_bytes: usize,
) -> Result<http::Request<Vec<u8>>, AxumError> {
    AxumOpener::new(HttpOpenOptions::new(recipient_secret_key), max_body_bytes)
        .open_request(request)
        .await
}

/// Opens an encrypted Axum request body into plaintext bytes with explicit envelope limits.
#[deprecated(
    since = "0.3.0",
    note = "stateless full-request protection has no replay defense or HTTP-context binding \
            and is replayable by design; use AxumOpener::open_request_with_context with a \
            ReplayStore for production"
)]
#[allow(deprecated)]
pub async fn open_axum_request_body_with_limits(
    request: AxumRequest,
    recipient_secret_key: [u8; 32],
    max_body_bytes: usize,
    limits: &foctet_core::BodyEnvelopeLimits,
) -> Result<http::Request<Vec<u8>>, AxumError> {
    AxumOpener::new(
        HttpOpenOptions::new(recipient_secret_key).with_limits(limits.clone()),
        max_body_bytes,
    )
    .open_request(request)
    .await
}

/// Seals a plaintext `http::Response<Vec<u8>>` and returns an Axum response.
pub fn seal_axum_response_body(
    response: http::Response<Vec<u8>>,
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
) -> Result<AxumResponse, AxumError> {
    AxumSealer::new(HttpSealOptions::new(recipient_public_key, recipient_key_id))
        .seal_response(response)
}

/// Seals a plaintext `http::Response<Vec<u8>>` with explicit envelope limits and returns an Axum response.
pub fn seal_axum_response_body_with_limits(
    response: http::Response<Vec<u8>>,
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
    limits: &foctet_core::BodyEnvelopeLimits,
) -> Result<AxumResponse, AxumError> {
    AxumSealer::new(
        HttpSealOptions::new(recipient_public_key, recipient_key_id).with_limits(limits.clone()),
    )
    .seal_response(response)
}

fn http_response_vec_to_axum(response: http::Response<Vec<u8>>) -> AxumResponse {
    let (parts, body) = response.into_parts();
    AxumResponse::from_parts(parts, Body::from(body))
}

impl ::axum::response::IntoResponse for AxumError {
    /// Maps to a status code only; never includes the source error's detail
    /// in the response body, so an opening/replay failure cannot leak
    /// ciphertext, key, or internal-state information to the caller.
    fn into_response(self) -> AxumResponse {
        use ::axum::http::StatusCode;
        let status = match &self {
            AxumError::BodyRead(_) => StatusCode::BAD_REQUEST,
            AxumError::Http(HttpError::MissingContentType | HttpError::InvalidContentType) => {
                StatusCode::BAD_REQUEST
            }
            AxumError::Http(HttpError::LimitExceeded(_)) => StatusCode::PAYLOAD_TOO_LARGE,
            AxumError::Http(
                HttpError::MissingContext(_)
                | HttpError::InvalidContext(_)
                | HttpError::ContextTimestampInFuture,
            ) => StatusCode::BAD_REQUEST,
            AxumError::Http(HttpError::ContextExpired) => StatusCode::UNAUTHORIZED,
            AxumError::Http(HttpError::OpenFailed(_)) => StatusCode::UNAUTHORIZED,
            // A truncated/cancelled streaming body is a malformed request.
            AxumError::Http(HttpError::StreamIncomplete) => StatusCode::BAD_REQUEST,
            AxumError::Http(HttpError::Replayed) => StatusCode::CONFLICT,
            AxumError::Http(HttpError::SealFailed(_) | HttpError::ReplayStore(_)) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        status.into_response()
    }
}

/// Application state required to use the [`ProtectedRequest`] extractor.
///
/// Implement this on your Axum `State` type to wire up a ready-made,
/// `FromRequest`-based extractor that authenticates the protected context,
/// enforces single use against a replay store, and hands the handler a
/// decrypted `http::Request<Vec<u8>>` — without per-handler boilerplate.
///
/// Scoped to the synchronous [`ReplayStore`] trait, not [`AsyncReplayStore`]:
/// axum's `FromRequest` requires the extraction future to be `Send`, but
/// `AsyncReplayStore`'s future is intentionally *not* required to be `Send`
/// (so it stays usable from `!Send` runtimes such as Cloudflare Workers),
/// so a durable/networked store (e.g. [`crate::RedisReplayStore`]) can't be
/// plugged into this extractor in general. Use
/// [`AxumOpener::open_request_with_async_store`] directly in the handler for
/// that case.
pub trait ProtectedHttpState: Send + Sync {
    /// The anti-replay store backing this state.
    type Store: ReplayStore + Send + Sync;

    /// Returns the opener used to authenticate and decrypt request bodies.
    fn protected_opener(&self) -> &AxumOpener;

    /// Returns the anti-replay store consulted after authentication.
    fn protected_replay_store(&self) -> &Self::Store;

    /// Returns the current time in Unix seconds, used for freshness checks.
    fn protected_now_secs(&self) -> u64;

    /// Returns the tolerated clock skew, in seconds. Defaults to
    /// [`crate::DEFAULT_MAX_CLOCK_SKEW_SECS`].
    fn protected_max_skew_secs(&self) -> u64 {
        crate::DEFAULT_MAX_CLOCK_SKEW_SECS
    }

    /// Returns the context-binding policy to enforce. Defaults to
    /// [`ContextBinding::default`] (method/path/query/message-id/expiry, no
    /// authority or extra headers).
    fn protected_context_binding(&self) -> ContextBinding {
        ContextBinding::default()
    }
}

/// Axum extractor that authenticates a context-bound, replay-protected
/// request body and yields the decrypted `http::Request<Vec<u8>>`.
///
/// Requires the application's `State` to implement [`ProtectedHttpState`]:
///
/// ```ignore
/// async fn handler(ProtectedRequest(request): ProtectedRequest) -> impl IntoResponse {
///     let plaintext = request.body();
///     // ...
/// }
/// ```
#[derive(Debug)]
pub struct ProtectedRequest(pub http::Request<Vec<u8>>);

impl<S> ::axum::extract::FromRequest<S> for ProtectedRequest
where
    S: ProtectedHttpState,
{
    type Rejection = AxumError;

    async fn from_request(req: AxumRequest, state: &S) -> Result<Self, Self::Rejection> {
        let now = state.protected_now_secs();
        let opened = state
            .protected_opener()
            .open_request_with_context(
                req,
                state.protected_replay_store(),
                now,
                state.protected_max_skew_secs(),
                state.protected_context_binding(),
            )
            .await?;
        Ok(ProtectedRequest(opened))
    }
}

/// Opens a **streaming** Foctet request body, invoking `on_plaintext` for each
/// decrypted chunk as it arrives — without buffering the whole body.
///
/// This is the turn-key Axum wiring for [`crate::HttpStreamSealer`]: it reads the
/// request body frame by frame, reassembles the Foctet stream frames, validates
/// the protected context's freshness and single use against `store` when the
/// stream header arrives, and yields plaintext chunks through the callback. It
/// fails with [`HttpError::StreamIncomplete`] (via [`AxumError::Http`]) if the
/// body ends before the authenticated final chunk, so a truncated or cancelled
/// upload is rejected.
#[allow(clippy::too_many_arguments)]
pub async fn open_request_stream<S, F>(
    request: AxumRequest,
    recipient_secret_key: [u8; 32],
    store: &S,
    now_secs: u64,
    max_skew_secs: u64,
    binding: ContextBinding,
    limits: &BodyEnvelopeLimits,
    mut on_plaintext: F,
) -> Result<(), AxumError>
where
    S: ReplayStore + ?Sized,
    F: FnMut(&[u8]) -> Result<(), AxumError>,
{
    let (parts, mut body) = request.into_parts();
    let mut reader = HttpRequestStreamReader::new(
        parts,
        recipient_secret_key,
        store,
        now_secs,
        max_skew_secs,
        binding,
        limits,
    );

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(AxumError::BodyRead)?;
        if let Ok(data) = frame.into_data() {
            for plaintext in reader.push(&data)? {
                on_plaintext(&plaintext)?;
            }
        }
    }

    reader.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(deprecated)] // seal_http_request is deprecated; used to build a test fixture
    use crate::raw::seal_http_request;
    use crate::{BODY_ONLY_SCOPE, CONTENT_TYPE, HttpSealer, SCOPE_HEADER};
    use getrandom::SysRng;
    use http::{Request, Response, StatusCode, Version, header};
    use rand_core::UnwrapErr;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[tokio::test]
    async fn open_request_stream_decodes_a_streaming_upload() {
        use crate::{HttpStreamSealer, InMemoryReplayStore};

        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_secret = recipient_priv.to_bytes();
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();
        let limits = BodyEnvelopeLimits::default();
        let now = 1234;

        // Seal a streaming upload and lay it out as the request body.
        let carrier = ContextCarrier::generate(now, 60);
        let base = Request::builder()
            .method("POST")
            .uri("https://example.com/upload")
            .body(())
            .expect("request");
        let (mut parts, _) = base.into_parts();
        let (mut sealer, header) = HttpStreamSealer::for_request(
            &parts,
            &carrier,
            ContextBinding::default(),
            recipient_pub,
            b"kid",
            &limits,
        )
        .expect("sealer");
        carrier
            .apply_to_headers(&mut parts.headers)
            .expect("apply carrier");

        let mut wire = header;
        for part in [b"axum ".as_slice(), b"streaming ", b"upload"] {
            let is_final = part == b"upload";
            wire.extend_from_slice(&sealer.seal_chunk(part, is_final).expect("seal"));
        }

        let request = Request::from_parts(parts, Body::from(wire));
        let store = InMemoryReplayStore::new();
        let mut body = Vec::new();
        open_request_stream(
            request,
            recipient_secret,
            &store,
            now,
            5,
            ContextBinding::default(),
            &limits,
            |plaintext| {
                body.extend_from_slice(plaintext);
                Ok(())
            },
        )
        .await
        .expect("stream opened");
        assert_eq!(body, b"axum streaming upload");
    }

    #[tokio::test]
    #[allow(deprecated)] // exercises the deprecated stateless request path on purpose
    async fn open_axum_request_body_roundtrip() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let plain_request = Request::builder()
            .method("POST")
            .uri("https://example.com/axum")
            .version(Version::HTTP_11)
            .header("x-app", "axum")
            .body(b"axum plaintext".to_vec())
            .expect("request");

        let encrypted_request =
            seal_http_request(plain_request, recipient_pub, b"axum-kid").expect("seal");

        let (parts, body) = encrypted_request.into_parts();
        let axum_request = AxumRequest::from_parts(parts, Body::from(body));

        let opened = open_axum_request_body(axum_request, recipient_priv.to_bytes(), 1024 * 1024)
            .await
            .expect("open");

        assert_eq!(opened.method(), "POST");
        assert_eq!(opened.uri().path(), "/axum");
        assert_eq!(opened.version(), Version::HTTP_11);
        assert_eq!(opened.headers()["x-app"], "axum");
        assert!(!opened.headers().contains_key(header::CONTENT_TYPE));
        assert_eq!(opened.body(), b"axum plaintext");
    }

    #[test]
    fn seal_axum_response_body_sets_content_type() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let response = Response::builder()
            .status(StatusCode::ACCEPTED)
            .version(Version::HTTP_2)
            .header("x-origin", "axum")
            .body(b"axum response body".to_vec())
            .expect("response");

        let sealed = seal_axum_response_body(response, recipient_pub, b"axum-kid").expect("seal");

        assert_eq!(sealed.status(), StatusCode::ACCEPTED);
        assert_eq!(sealed.version(), Version::HTTP_2);
        assert_eq!(sealed.headers()["x-origin"], "axum");
        assert_eq!(
            sealed.headers()[header::CONTENT_TYPE],
            header::HeaderValue::from_static(CONTENT_TYPE)
        );
        assert_eq!(sealed.headers()[SCOPE_HEADER], BODY_ONLY_SCOPE);
    }

    #[tokio::test]
    async fn open_axum_request_with_context_enforces_replay() {
        use crate::{ContextBinding, ContextCarrier, InMemoryReplayStore};

        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"axum-kid"));
        let opener = AxumOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()), 1024 * 1024);
        let store = InMemoryReplayStore::new();
        let binding = ContextBinding::default();
        let now = 5_000u64;

        let plain = Request::builder()
            .method("POST")
            .uri("https://example.com/axum/pay")
            .body(b"axum charge".to_vec())
            .expect("request");
        let carrier = ContextCarrier::generate(now, 300);
        let sealed = sealer
            .seal_request_with_context(plain, carrier, binding)
            .expect("seal");

        let make_axum = |req: &Request<Vec<u8>>| {
            let mut builder = Request::builder()
                .method(req.method().clone())
                .uri(req.uri().clone());
            for (name, value) in req.headers() {
                builder = builder.header(name, value);
            }
            let r = builder.body(req.body().clone()).expect("clone");
            let (parts, body) = r.into_parts();
            AxumRequest::from_parts(parts, Body::from(body))
        };

        let opened = opener
            .open_request_with_context(make_axum(&sealed), &store, now, 30, binding)
            .await
            .expect("first open");
        assert_eq!(opened.body(), b"axum charge");

        let err = opener
            .open_request_with_context(make_axum(&sealed), &store, now, 30, binding)
            .await
            .expect_err("replay rejected");
        assert!(matches!(err, AxumError::Http(HttpError::Replayed)));
    }

    #[test]
    fn sealer_wrapper_uses_http_core() {
        let sealer =
            AxumSealer::from_http_sealer(HttpSealer::new(HttpSealOptions::new([1u8; 32], b"kid")));
        assert_eq!(sealer.sealer().options().recipient_key_id(), b"kid");
    }

    struct TestAppState {
        opener: AxumOpener,
        store: crate::InMemoryReplayStore,
        now: std::sync::atomic::AtomicU64,
    }

    impl ProtectedHttpState for TestAppState {
        type Store = crate::InMemoryReplayStore;

        fn protected_opener(&self) -> &AxumOpener {
            &self.opener
        }

        fn protected_replay_store(&self) -> &Self::Store {
            &self.store
        }

        fn protected_now_secs(&self) -> u64 {
            self.now.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn protected_request_extractor_authenticates_and_rejects_replay() {
        use ::axum::extract::FromRequest;

        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();
        let now = 1_000_000u64;

        let state = TestAppState {
            opener: AxumOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()), 1024 * 1024),
            store: crate::InMemoryReplayStore::new(),
            now: std::sync::atomic::AtomicU64::new(now),
        };

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let plain = Request::builder()
            .method("POST")
            .uri("https://example.com/extractor")
            .body(b"via extractor".to_vec())
            .expect("request");
        let carrier = ContextCarrier::generate(now, 300);
        let sealed = sealer
            .seal_request_with_context(plain, carrier, ContextBinding::default())
            .expect("seal");

        let make_axum = |req: &Request<Vec<u8>>| {
            let mut builder = Request::builder()
                .method(req.method().clone())
                .uri(req.uri().clone());
            for (name, value) in req.headers() {
                builder = builder.header(name, value);
            }
            let r = builder.body(req.body().clone()).expect("clone");
            let (parts, body) = r.into_parts();
            AxumRequest::from_parts(parts, Body::from(body))
        };

        let ProtectedRequest(opened) = ProtectedRequest::from_request(make_axum(&sealed), &state)
            .await
            .expect("extractor authenticates first delivery");
        assert_eq!(opened.body(), b"via extractor");

        let err = ProtectedRequest::from_request(make_axum(&sealed), &state)
            .await
            .expect_err("extractor must reject replay");
        assert!(matches!(err, AxumError::Http(HttpError::Replayed)));
    }
}
