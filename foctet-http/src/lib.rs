#![cfg_attr(docsrs, feature(doc_cfg))]
//! High-level HTTP integration for `application/foctet` body envelopes.
//!
//! `foctet-http` encrypts HTTP body bytes. For production requests, prefer the
//! context-bound APIs:
//! [`HttpSealer::seal_request_with_context`] and
//! [`HttpOpener::open_request_with_context`]. They bind selected request
//! metadata into the AEAD and enforce single-use replay protection through a
//! [`ReplayStore`].
//!
//! The outer HTTP method, URI, status code, and headers remain visible to the
//! surrounding transport, so deployments should still use an authenticated
//! outer channel such as HTTPS.
//!
//! Main layers:
//!
//! - [`HttpSealer`] and [`HttpOpener`] for the primary API
//! - [`context`] and [`ReplayStore`] for protected-context request binding
//! - `axum` and `workers` for framework adapters
//! - [`raw`] for lower-level helpers
//!

/// Re-export of the `http` crate used by this adapter.
pub use http;

mod config;
pub mod context;
mod error;
pub mod raw;
mod replay_store;
pub mod stream;

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(all(feature = "workers", target_arch = "wasm32"))]
pub mod workers;

use foctet_core::{open_body_with_context, seal_body_with_context};
use http::{
    Request, Response,
    header::{self},
};

pub use config::{
    HttpConfig, HttpOpenOptions, HttpOptionsError, HttpSealOptions, MAX_HTTP_RECIPIENT_KEYS,
};
#[cfg(not(target_arch = "wasm32"))]
pub use context::unix_now_secs;
pub use context::{
    ContextBinding, ContextCarrier, ContextDirection, DEFAULT_CONTEXT_TTL_SECS,
    DEFAULT_MAX_CLOCK_SKEW_SECS, MAX_BOUND_HEADER_NAME_BYTES, MAX_BOUND_HEADER_VALUE_BYTES,
    MAX_BOUND_HEADERS, MAX_PROTECTED_CONTEXT_BYTES, MESSAGE_ID_LEN, ProtectedContext,
};
pub use error::{HttpError, HttpErrorDisposition, HttpSecurityMetric};
// Re-exported because it appears in public signatures (`HttpSealOptions`,
// `open_request_stream`, `HttpStreamSealer::for_request`, …), so callers do not
// need a direct `foctet-core` dependency to name it.
pub use foctet_core::BodyEnvelopeLimits;
#[cfg(feature = "redis")]
pub use replay_store::RedisReplayStore;
pub use replay_store::{
    AsyncReplayStore, DEFAULT_MAX_REPLAY_ENTRIES, InMemoryReplayStore, ReplayCheck, ReplayStore,
    ReplayStoreError,
};
pub use stream::{
    HttpRequestStreamReader, HttpResponseStreamReader, HttpStreamOpener, HttpStreamSealer,
};

/// Foctet HTTP media type.
pub const CONTENT_TYPE: &str = "application/foctet";
/// Advisory header name describing the Foctet protection scope.
pub const SCOPE_HEADER: &str = "x-foctet-scope";
/// Advisory header value indicating that only the HTTP body is protected.
pub const BODY_ONLY_SCOPE: &str = "body-only";

/// High-level helper for sealing HTTP bodies, requests, and responses.
#[derive(Clone, Debug)]
pub struct HttpSealer {
    options: HttpSealOptions,
    config: HttpConfig,
}

/// High-level helper for opening HTTP bodies, requests, and responses.
#[derive(Clone, Debug)]
pub struct HttpOpener {
    options: HttpOpenOptions,
    config: HttpConfig,
}

impl HttpSealer {
    /// Creates a sealer with default HTTP behavior.
    pub fn new(options: HttpSealOptions) -> Self {
        Self {
            options,
            config: HttpConfig::default(),
        }
    }

    /// Creates a sealer with explicit HTTP behavior.
    pub fn with_config(options: HttpSealOptions, config: HttpConfig) -> Self {
        Self { options, config }
    }

    /// Returns the sealing options.
    pub fn options(&self) -> &HttpSealOptions {
        &self.options
    }

    /// Returns the HTTP behavior config.
    pub fn config(&self) -> &HttpConfig {
        &self.config
    }

    /// Seals raw plaintext bytes into an `application/foctet` body.
    pub fn seal_body(&self, plaintext: &[u8]) -> Result<Vec<u8>, HttpError> {
        match self.options.limits() {
            Some(limits) => raw::seal_http_body_with_limits(
                plaintext,
                self.options.recipient_public_key(),
                self.options.recipient_key_id(),
                limits,
            ),
            None => raw::seal_http_body(
                plaintext,
                self.options.recipient_public_key(),
                self.options.recipient_key_id(),
            ),
        }
    }

    /// Seals the body and binds the supplied associated data into its AEAD.
    fn seal_body_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, HttpError> {
        let default_limits;
        let limits = match self.options.limits() {
            Some(limits) => limits,
            None => {
                default_limits = BodyEnvelopeLimits::default();
                &default_limits
            }
        };
        seal_body_with_context(
            plaintext,
            self.options.recipient_public_key(),
            self.options.recipient_key_id(),
            aad,
            limits,
        )
        .map_err(HttpError::SealFailed)
    }

    /// Seals a request and binds the full HTTP protected context (method, path,
    /// query, message ID, timestamp, expiry, …) into the envelope.
    ///
    /// This is the recommended path for production HTTP: it makes a captured
    /// envelope non-replayable onto a different route and, paired with
    /// [`HttpOpener::open_request_with_context`] and a [`ReplayStore`], enforces
    /// single use. The carrier values travel in `x-foctet-*` headers.
    pub fn seal_request_with_context(
        &self,
        request: Request<Vec<u8>>,
        carrier: ContextCarrier,
        binding: ContextBinding,
    ) -> Result<Request<Vec<u8>>, HttpError> {
        let (mut parts, body) = request.into_parts();
        let context = ProtectedContext::for_request(&parts, carrier.clone(), binding)?;
        let aad = context.to_aad_bytes();
        let sealed = self.seal_body_with_aad(&body, &aad)?;
        raw::set_foctet_content_type(&mut parts.headers);
        if self.config.set_scope_header_on_seal() {
            raw::set_foctet_scope_header(&mut parts.headers);
        }
        carrier.apply_to_headers(&mut parts.headers)?;
        Ok(Request::from_parts(parts, sealed))
    }

    /// Seals a response and binds the HTTP protected context (status, message
    /// ID, timestamp, expiry, and the answered request message ID).
    pub fn seal_response_with_context(
        &self,
        response: Response<Vec<u8>>,
        carrier: ContextCarrier,
    ) -> Result<Response<Vec<u8>>, HttpError> {
        let (mut parts, body) = response.into_parts();
        let context = ProtectedContext::for_response(&parts, carrier.clone())?;
        let aad = context.to_aad_bytes();
        let sealed = self.seal_body_with_aad(&body, &aad)?;
        raw::set_foctet_content_type(&mut parts.headers);
        if self.config.set_scope_header_on_seal() {
            raw::set_foctet_scope_header(&mut parts.headers);
        }
        carrier.apply_to_headers(&mut parts.headers)?;
        Ok(Response::from_parts(parts, sealed))
    }

    /// Seals a plaintext request and sets `Content-Type: application/foctet`.
    ///
    /// This protects the body only and provides **no** replay protection or
    /// HTTP-context binding; prefer [`HttpSealer::seal_request_with_context`]
    /// for production. By default this also adds the advisory
    /// `x-foctet-scope: body-only` header so downstream consumers do not mistake
    /// body protection for full HTTP message protection.
    #[cfg(feature = "dangerous-stateless-http")]
    #[deprecated(
        since = "0.3.0",
        note = "stateless full-request protection has no replay defense or HTTP-context \
                binding and is replayable by design; use seal_request_with_context with a \
                ReplayStore for production (see module docs)"
    )]
    pub fn seal_request(&self, request: Request<Vec<u8>>) -> Result<Request<Vec<u8>>, HttpError> {
        let (mut parts, body) = request.into_parts();
        let sealed = self.seal_body(&body)?;
        raw::set_foctet_content_type(&mut parts.headers);
        if self.config.set_scope_header_on_seal() {
            raw::set_foctet_scope_header(&mut parts.headers);
        }
        Ok(Request::from_parts(parts, sealed))
    }

    /// Seals a plaintext response and sets `Content-Type: application/foctet`.
    ///
    /// By default this also adds the advisory `x-foctet-scope: body-only`
    /// header so downstream consumers do not mistake body protection for
    /// full HTTP message protection.
    pub fn seal_response(
        &self,
        response: Response<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, HttpError> {
        let (mut parts, body) = response.into_parts();
        let sealed = self.seal_body(&body)?;
        raw::set_foctet_content_type(&mut parts.headers);
        if self.config.set_scope_header_on_seal() {
            raw::set_foctet_scope_header(&mut parts.headers);
        }
        Ok(Response::from_parts(parts, sealed))
    }
}

impl HttpOpener {
    /// Creates an opener with default HTTP behavior.
    pub fn new(options: HttpOpenOptions) -> Self {
        Self {
            options,
            config: HttpConfig::default(),
        }
    }

    /// Creates an opener with explicit HTTP behavior.
    pub fn with_config(options: HttpOpenOptions, config: HttpConfig) -> Self {
        Self { options, config }
    }

    /// Returns the opening options.
    pub fn options(&self) -> &HttpOpenOptions {
        &self.options
    }

    /// Returns the HTTP behavior config.
    pub fn config(&self) -> &HttpConfig {
        &self.config
    }

    /// Tries each recipient key in the keyring, returning the plaintext from the
    /// first key that authenticates.
    ///
    /// Because every keyring entry is one of the recipient's own secret keys and
    /// each attempt is on context-bound, authenticated ciphertext, a
    /// non-matching key simply fails to open (no decryption oracle). If no key
    /// succeeds, the first attempt's error is returned. The keyring is
    /// guaranteed non-empty by [`HttpOpenOptions`].
    fn open_with_keyring<F>(&self, mut attempt: F) -> Result<Vec<u8>, HttpError>
    where
        F: FnMut([u8; 32]) -> Result<Vec<u8>, HttpError>,
    {
        let mut first_err = None;
        for key in self.options.expose_recipient_secret_keys() {
            match attempt(*key) {
                Ok(plain) => return Ok(plain),
                Err(err) => {
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }
        Err(first_err.expect("HttpOpenOptions guarantees a non-empty keyring"))
    }

    /// Opens an `application/foctet` body into plaintext bytes.
    pub fn open_body(&self, envelope: &[u8]) -> Result<Vec<u8>, HttpError> {
        self.open_with_keyring(|key| match self.options.limits() {
            Some(limits) => raw::open_http_body_with_limits(envelope, key, limits),
            None => raw::open_http_body(envelope, key),
        })
    }

    /// Opens the body using the supplied associated data.
    fn open_body_with_aad(&self, envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>, HttpError> {
        let default_limits;
        let limits = match self.options.limits() {
            Some(limits) => limits,
            None => {
                default_limits = BodyEnvelopeLimits::default();
                &default_limits
            }
        };
        self.open_with_keyring(|key| {
            open_body_with_context(envelope, key, aad, limits).map_err(HttpError::OpenFailed)
        })
    }

    /// Opens a request sealed with [`HttpSealer::seal_request_with_context`],
    /// validating the bound HTTP context, freshness, and single use.
    ///
    /// The order is deliberate and matters for security:
    /// 1. parse the carrier headers and reconstruct the bound context,
    /// 2. validate timestamp/expiry against `now_secs` (± `max_skew_secs`),
    /// 3. **authenticate** the body via the context-bound AEAD,
    /// 4. only then consult the [`ReplayStore`] for single-use enforcement.
    ///
    /// Recording replay state only after authentication prevents an
    /// unauthenticated request from populating the store.
    pub fn open_request_with_context<S>(
        &self,
        request: Request<Vec<u8>>,
        store: &S,
        now_secs: u64,
        max_skew_secs: u64,
        binding: ContextBinding,
    ) -> Result<Request<Vec<u8>>, HttpError>
    where
        S: ReplayStore + ?Sized,
    {
        let (parts, plain, carrier) =
            self.open_request_prepare(request, now_secs, max_skew_secs, binding)?;

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

        Ok(self.open_request_finalize(parts, plain))
    }

    /// Opens a context-bound request using a durable [`AsyncReplayStore`].
    ///
    /// Identical to [`HttpOpener::open_request_with_context`] but awaits the
    /// store, so it works with atomic networked/durable backends (Redis
    /// `SET NX`, a Durable Object, or a transactional SQL table) needed once
    /// more than one instance serves traffic. Cloudflare KV is not atomic enough
    /// for this contract. Authentication still happens before the store is
    /// consulted.
    pub async fn open_request_with_async_store<S>(
        &self,
        request: Request<Vec<u8>>,
        store: &S,
        now_secs: u64,
        max_skew_secs: u64,
        binding: ContextBinding,
    ) -> Result<Request<Vec<u8>>, HttpError>
    where
        S: AsyncReplayStore + ?Sized,
    {
        let (parts, plain, carrier) =
            self.open_request_prepare(request, now_secs, max_skew_secs, binding)?;

        match AsyncReplayStore::check_and_insert(
            store,
            &carrier.message_id,
            carrier.expiry_secs,
            now_secs,
        )
        .await
        .map_err(HttpError::ReplayStore)?
        {
            ReplayCheck::Accepted => {}
            ReplayCheck::Replay => return Err(HttpError::Replayed),
        }

        Ok(self.open_request_finalize(parts, plain))
    }

    /// Shared request-open logic up to (but excluding) the replay-store check:
    /// validates content type, parses the carrier, reconstructs and freshness-
    /// checks the context, and authenticates the body.
    fn open_request_prepare(
        &self,
        request: Request<Vec<u8>>,
        now_secs: u64,
        max_skew_secs: u64,
        binding: ContextBinding,
    ) -> Result<(http::request::Parts, Vec<u8>, ContextCarrier), HttpError> {
        let (parts, body) = request.into_parts();
        raw::ensure_foctet_content_type(&parts.headers)?;
        let carrier = ContextCarrier::from_headers(&parts.headers)?;
        let context = ProtectedContext::for_request(&parts, carrier.clone(), binding)?;
        context.validate_freshness(now_secs, max_skew_secs)?;
        let aad = context.to_aad_bytes();
        let plain = self.open_body_with_aad(&body, &aad)?;
        Ok((parts, plain, carrier))
    }

    fn open_request_finalize(
        &self,
        mut parts: http::request::Parts,
        plain: Vec<u8>,
    ) -> Request<Vec<u8>> {
        if self.config.strip_content_type_on_open() {
            parts.headers.remove(header::CONTENT_TYPE);
        }
        Request::from_parts(parts, plain)
    }

    /// Opens a response sealed with [`HttpSealer::seal_response_with_context`],
    /// validating the bound context, freshness, and initiating request ID.
    ///
    /// `expected_request_message_id` MUST be the message ID from the request
    /// that initiated this exchange. A missing or different response
    /// `request_message_id` is rejected before returning plaintext.
    pub fn open_response_with_context(
        &self,
        response: Response<Vec<u8>>,
        expected_request_message_id: [u8; MESSAGE_ID_LEN],
        now_secs: u64,
        max_skew_secs: u64,
    ) -> Result<Response<Vec<u8>>, HttpError> {
        let (mut parts, body) = response.into_parts();
        raw::ensure_foctet_content_type(&parts.headers)?;
        let carrier = ContextCarrier::from_headers(&parts.headers)?;
        if carrier.request_message_id != Some(expected_request_message_id) {
            return Err(HttpError::ResponseRequestMismatch);
        }
        let context = ProtectedContext::for_response(&parts, carrier)?;
        context.validate_freshness(now_secs, max_skew_secs)?;

        let aad = context.to_aad_bytes();
        let plain = self.open_body_with_aad(&body, &aad)?;

        if self.config.strip_content_type_on_open() {
            parts.headers.remove(header::CONTENT_TYPE);
        }
        Ok(Response::from_parts(parts, plain))
    }

    /// Opens an encrypted request body into plaintext bytes.
    ///
    /// This provides **no** replay protection or HTTP-context binding; prefer
    /// [`HttpOpener::open_request_with_context`] for production.
    #[cfg(feature = "dangerous-stateless-http")]
    #[deprecated(
        since = "0.3.0",
        note = "stateless full-request protection has no replay defense or HTTP-context \
                binding and is replayable by design; use open_request_with_context with a \
                ReplayStore for production (see module docs)"
    )]
    pub fn open_request(&self, request: Request<Vec<u8>>) -> Result<Request<Vec<u8>>, HttpError> {
        let (mut parts, body) = request.into_parts();
        raw::ensure_foctet_content_type(&parts.headers)?;
        let plain = self.open_body(&body)?;
        if self.config.strip_content_type_on_open() {
            parts.headers.remove(header::CONTENT_TYPE);
        }
        Ok(Request::from_parts(parts, plain))
    }

    /// Opens an encrypted response body into plaintext bytes.
    pub fn open_response(
        &self,
        response: Response<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, HttpError> {
        let (mut parts, body) = response.into_parts();
        raw::ensure_foctet_content_type(&parts.headers)?;
        let plain = self.open_body(&body)?;
        if self.config.strip_content_type_on_open() {
            parts.headers.remove(header::CONTENT_TYPE);
        }
        Ok(Response::from_parts(parts, plain))
    }
}

#[cfg(test)]
mod tests {
    use foctet_core::BodyEnvelopeLimits;
    use getrandom::SysRng;
    #[cfg(feature = "dangerous-stateless-http")]
    use http::Version;
    use http::{Request, Response, StatusCode, header};
    use rand_core::UnwrapErr;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;

    #[test]
    #[cfg(feature = "dangerous-stateless-http")]
    #[allow(deprecated)] // exercises the deprecated stateless request path on purpose
    fn sealer_and_opener_roundtrip_request_and_response() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let opener = HttpOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()));

        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/submit")
            .version(Version::HTTP_11)
            .header("x-trace-id", "abc123")
            .body(b"request payload".to_vec())
            .expect("request");

        let sealed_request = sealer.seal_request(request).expect("seal request");
        assert_eq!(sealed_request.headers()[SCOPE_HEADER], BODY_ONLY_SCOPE);
        let opened_request = opener.open_request(sealed_request).expect("open request");

        assert_eq!(opened_request.method(), "POST");
        assert_eq!(opened_request.uri().path(), "/submit");
        assert_eq!(opened_request.headers()["x-trace-id"], "abc123");
        assert_eq!(opened_request.headers()[SCOPE_HEADER], BODY_ONLY_SCOPE);
        assert!(!opened_request.headers().contains_key(header::CONTENT_TYPE));
        assert_eq!(opened_request.body(), b"request payload");

        let response = Response::builder()
            .status(StatusCode::CREATED)
            .version(Version::HTTP_2)
            .header("x-server", "foctet")
            .body(b"response payload".to_vec())
            .expect("response");

        let sealed_response = sealer.seal_response(response).expect("seal response");
        assert_eq!(sealed_response.headers()[SCOPE_HEADER], BODY_ONLY_SCOPE);
        let opened_response = opener
            .open_response(sealed_response)
            .expect("open response");

        assert_eq!(opened_response.status(), StatusCode::CREATED);
        assert_eq!(opened_response.version(), Version::HTTP_2);
        assert_eq!(opened_response.headers()["x-server"], "foctet");
        assert_eq!(opened_response.headers()[SCOPE_HEADER], BODY_ONLY_SCOPE);
        assert_eq!(opened_response.body(), b"response payload");
    }

    #[test]
    fn opener_respects_explicit_config() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let opener = HttpOpener::with_config(
            HttpOpenOptions::new(recipient_priv.to_bytes()),
            HttpConfig::default().with_strip_content_type_on_open(false),
        );

        let response = Response::builder()
            .status(StatusCode::OK)
            .body(b"payload".to_vec())
            .expect("response");
        let sealed = sealer.seal_response(response).expect("seal");
        let opened = opener.open_response(sealed).expect("open");

        assert!(opened.headers().contains_key(header::CONTENT_TYPE));
        assert_eq!(opened.headers()[SCOPE_HEADER], BODY_ONLY_SCOPE);
    }

    #[test]
    fn scope_header_can_be_disabled() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::with_config(
            HttpSealOptions::new(recipient_pub, b"kid"),
            HttpConfig::default().with_scope_header_on_seal(false),
        );

        let response = Response::builder()
            .status(StatusCode::OK)
            .body(b"payload".to_vec())
            .expect("response");
        let sealed = sealer.seal_response(response).expect("seal");

        assert!(!sealed.headers().contains_key(SCOPE_HEADER));
    }

    #[test]
    fn context_bound_request_roundtrip_and_replay_rejected() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let opener = HttpOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()));
        let store = InMemoryReplayStore::new();
        let binding = ContextBinding::default();
        let now = 1_000_000u64;

        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/pay?amount=10")
            .body(b"charge".to_vec())
            .expect("request");

        let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS);
        let sealed = sealer
            .seal_request_with_context(request, carrier, binding)
            .expect("seal");

        // First delivery authenticates and is accepted.
        let opened = opener
            .open_request_with_context(clone_request(&sealed), &store, now, 30, binding)
            .expect("first open");
        assert_eq!(opened.method(), "POST");
        assert_eq!(opened.body(), b"charge");

        // Replaying the identical captured request is rejected.
        let err = opener
            .open_request_with_context(clone_request(&sealed), &store, now, 30, binding)
            .expect_err("replay must be rejected");
        assert!(matches!(err, HttpError::Replayed));
    }

    #[test]
    fn context_bound_request_with_bound_header_rejects_header_tamper() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let opener = HttpOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()));
        let store = InMemoryReplayStore::new();
        let binding = ContextBinding::default().with_bound_headers(&["x-tenant-id"]);
        let now = 1_000_000u64;

        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/pay")
            .header("x-tenant-id", "tenant-a")
            .body(b"charge".to_vec())
            .expect("request");
        let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS);
        let sealed = sealer
            .seal_request_with_context(request, carrier, binding)
            .expect("seal");

        // Genuine request opens fine.
        let opened = opener
            .open_request_with_context(clone_request(&sealed), &store, now, 30, binding)
            .expect("open with matching bound header");
        assert_eq!(opened.headers()["x-tenant-id"], "tenant-a");

        // An on-path party swapping the tenant header (but leaving the
        // ciphertext, route, and carrier headers untouched) must fail
        // authentication rather than silently reattributing the request.
        let (mut parts, body) = sealed.into_parts();
        parts
            .headers
            .insert("x-tenant-id", "tenant-b".parse().expect("header value"));
        let tampered = Request::from_parts(parts, body);

        let err = opener
            .open_request_with_context(tampered, &store, now, 30, binding)
            .expect_err("tampered bound header must fail authentication");
        assert!(matches!(err, HttpError::OpenFailed(_)));
    }

    #[tokio::test]
    async fn context_bound_request_async_store_roundtrip_and_replay() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let opener = HttpOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()));
        // InMemoryReplayStore is usable through the async path via the blanket impl.
        let store = InMemoryReplayStore::new();
        let binding = ContextBinding::default();
        let now = 1_000_000u64;

        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/pay")
            .body(b"charge".to_vec())
            .expect("request");
        let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS);
        let sealed = sealer
            .seal_request_with_context(request, carrier, binding)
            .expect("seal");

        let opened = opener
            .open_request_with_async_store(clone_request(&sealed), &store, now, 30, binding)
            .await
            .expect("first open");
        assert_eq!(opened.body(), b"charge");

        let err = opener
            .open_request_with_async_store(clone_request(&sealed), &store, now, 30, binding)
            .await
            .expect_err("replay must be rejected");
        assert!(matches!(err, HttpError::Replayed));
    }

    #[test]
    fn context_bound_request_rejects_route_substitution() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let opener = HttpOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()));
        let store = InMemoryReplayStore::new();
        let binding = ContextBinding::default();
        let now = 1_000_000u64;

        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/pay")
            .body(b"charge".to_vec())
            .expect("request");
        let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS);
        let sealed = sealer
            .seal_request_with_context(request, carrier, binding)
            .expect("seal");

        // Attacker moves the captured ciphertext + headers onto a different path.
        let (mut parts, body) = sealed.into_parts();
        parts.uri = "https://api.example.com/refund".parse().expect("uri");
        let moved = Request::from_parts(parts, body);

        let err = opener
            .open_request_with_context(moved, &store, now, 30, binding)
            .expect_err("route substitution must fail authentication");
        assert!(matches!(err, HttpError::OpenFailed(_)));
    }

    #[test]
    fn context_bound_request_rejects_expired() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let opener = HttpOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()));
        let store = InMemoryReplayStore::new();
        let binding = ContextBinding::default();

        let request = Request::builder()
            .method("GET")
            .uri("https://api.example.com/data")
            .body(Vec::new())
            .expect("request");
        let carrier = ContextCarrier::generate(1_000, 60);
        let sealed = sealer
            .seal_request_with_context(request, carrier, binding)
            .expect("seal");

        let err = opener
            .open_request_with_context(sealed, &store, 5_000, 30, binding)
            .expect_err("expired context must be rejected");
        assert!(matches!(err, HttpError::ContextExpired));
    }

    #[test]
    fn context_bound_response_roundtrip() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let opener = HttpOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()));
        let now = 2_000u64;

        let response = Response::builder()
            .status(StatusCode::OK)
            .body(b"result".to_vec())
            .expect("response");
        let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS).answering([3u8; 16]);
        let sealed = sealer
            .seal_response_with_context(response, carrier)
            .expect("seal");

        let opened = opener
            .open_response_with_context(sealed, [3u8; 16], now, 30)
            .expect("open");
        assert_eq!(opened.status(), StatusCode::OK);
        assert_eq!(opened.body(), b"result");
    }

    #[test]
    fn context_bound_response_rejects_wrong_or_missing_request_id() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();
        let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, b"kid"));
        let opener = HttpOpener::new(HttpOpenOptions::new(recipient_priv.to_bytes()));
        let now = 2_000u64;

        let response = Response::builder()
            .status(StatusCode::OK)
            .body(b"result".to_vec())
            .expect("response");
        let sealed = sealer
            .seal_response_with_context(
                response,
                ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS).answering([3u8; 16]),
            )
            .expect("seal");
        let err = opener
            .open_response_with_context(sealed, [4u8; 16], now, 30)
            .expect_err("wrong request id");
        assert!(matches!(err, HttpError::ResponseRequestMismatch));
    }

    fn clone_request(request: &Request<Vec<u8>>) -> Request<Vec<u8>> {
        let mut builder = Request::builder()
            .method(request.method().clone())
            .uri(request.uri().clone())
            .version(request.version());
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        builder.body(request.body().clone()).expect("clone request")
    }

    #[test]
    fn options_support_explicit_limits() {
        let limits = BodyEnvelopeLimits {
            max_payload_len: 1024,
            ..BodyEnvelopeLimits::default()
        };
        let options = HttpSealOptions::new([1u8; 32], b"kid").with_limits(limits.clone());
        assert_eq!(options.limits(), Some(&limits));
    }

    #[test]
    fn key_rotation_overlap_accepts_current_and_previous_key() {
        let old_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let old_pub = PublicKey::from(&old_priv).to_bytes();
        let new_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let new_pub = PublicKey::from(&new_priv).to_bytes();

        // During the overlap window the recipient accepts both the current
        // (v2) key and the retiring (v1) key.
        let opener = HttpOpener::new(
            HttpOpenOptions::new(new_priv.to_bytes())
                .with_recipient_key(old_priv.to_bytes())
                .expect("two keys fit"),
        );
        assert_eq!(opener.options().recipient_key_count(), 2);

        let binding = ContextBinding::default();
        let now = 1_000_000u64;

        for (recipient_pub, kid, body) in [
            (old_pub, &b"server-v1"[..], &b"pre-rotation"[..]),
            (new_pub, &b"server-v2"[..], &b"post-rotation"[..]),
        ] {
            let sealer = HttpSealer::new(HttpSealOptions::new(recipient_pub, kid));
            let store = InMemoryReplayStore::new();
            let request = Request::builder()
                .method("POST")
                .uri("https://api.example.com/pay")
                .body(body.to_vec())
                .expect("request");
            let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS);
            let sealed = sealer
                .seal_request_with_context(request, carrier, binding)
                .expect("seal");
            let opened = opener
                .open_request_with_context(sealed, &store, now, 30, binding)
                .expect("keyring opens an envelope sealed to either key");
            assert_eq!(opened.body(), body);
        }
    }

    #[test]
    fn key_rotation_rejects_key_after_it_is_retired() {
        let old_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let old_pub = PublicKey::from(&old_priv).to_bytes();
        let new_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));

        // Overlap window is over: the recipient holds only the current key.
        let opener = HttpOpener::new(HttpOpenOptions::new(new_priv.to_bytes()));
        let sealer_old = HttpSealer::new(HttpSealOptions::new(old_pub, b"server-v1"));
        let store = InMemoryReplayStore::new();
        let binding = ContextBinding::default();
        let now = 1_000_000u64;

        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/pay")
            .body(b"charge".to_vec())
            .expect("request");
        let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS);
        let sealed = sealer_old
            .seal_request_with_context(request, carrier, binding)
            .expect("seal");

        let err = opener
            .open_request_with_context(sealed, &store, now, 30, binding)
            .expect_err("a request sealed to a retired key must be rejected");
        assert!(matches!(err, HttpError::OpenFailed(_)));
    }

    #[tokio::test]
    async fn key_rotation_trial_decryption_does_not_consume_replay_slot() {
        let old_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let new_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let new_pub = PublicKey::from(&new_priv).to_bytes();

        // The non-matching old key is tried FIRST and fails authentication
        // before the matching new key succeeds.
        let opener = HttpOpener::new(
            HttpOpenOptions::new(old_priv.to_bytes())
                .with_recipient_key(new_priv.to_bytes())
                .expect("two keys fit"),
        );
        let sealer = HttpSealer::new(HttpSealOptions::new(new_pub, b"server-v2"));
        let store = InMemoryReplayStore::new();
        let binding = ContextBinding::default();
        let now = 1_000_000u64;

        let request = Request::builder()
            .method("POST")
            .uri("https://api.example.com/pay")
            .body(b"charge".to_vec())
            .expect("request");
        let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS);
        let sealed = sealer
            .seal_request_with_context(request, carrier, binding)
            .expect("seal");

        // First delivery: the failing old-key attempt must not populate the
        // replay store, so authentication (before the store) still succeeds.
        let opened = opener
            .open_request_with_async_store(clone_request(&sealed), &store, now, 30, binding)
            .await
            .expect("the second key in the ring opens the envelope");
        assert_eq!(opened.body(), b"charge");

        // The genuine replay is still detected exactly once.
        let err = opener
            .open_request_with_async_store(sealed, &store, now, 30, binding)
            .await
            .expect_err("replay must be rejected");
        assert!(matches!(err, HttpError::Replayed));
    }
}
