//! Cloudflare Workers adapters built on top of the high-level Foctet HTTP API.
//!
//! These adapters protect the request or response body bytes while leaving the
//! surrounding Worker routing metadata, headers, and method visible to the
//! outer HTTPS channel and Worker runtime.

use foctet_core::BodyEnvelopeLimits;
use thiserror::Error;

use crate::{
    AsyncReplayStore, BODY_ONLY_SCOPE, CONTENT_TYPE, ContextBinding, ContextCarrier, HttpError,
    HttpErrorDisposition, HttpOpenOptions, HttpOpener, HttpSealOptions, HttpSealer, ReplayCheck,
    ReplayStore, ReplayStoreError, SCOPE_HEADER,
};

/// Durable Object path used by [`DurableObjectReplayStore`] and
/// [`check_and_insert_in_durable_object`]. This endpoint is internal to a
/// Worker-to-Durable-Object binding and must not be exposed by the public fetch
/// handler.
pub const DURABLE_REPLAY_PATH: &str = "/foctet/replay/v1";
const DURABLE_REPLAY_URL: &str = "https://foctet.internal/foctet/replay/v1";

/// Atomic Durable Object-backed replay store for production Workers deployments.
///
/// Each message ID is routed to its own deterministically named Durable Object,
/// whose strongly consistent storage makes the check-and-insert operation
/// atomic. Its alarm deletes the one retained entry at expiry. The Durable
/// Object class must delegate its fetch and alarm handlers to
/// [`check_and_insert_in_durable_object`] and
/// [`expire_durable_object_replay_entry`].
#[derive(Clone, Debug)]
pub struct DurableObjectReplayStore {
    namespace: worker::ObjectNamespace,
    object_name: String,
}

impl DurableObjectReplayStore {
    /// Creates a replay store backed by the named Durable Object instance.
    pub fn new(namespace: worker::ObjectNamespace, object_name: impl Into<String>) -> Self {
        Self {
            namespace,
            object_name: object_name.into(),
        }
    }
}

impl AsyncReplayStore for DurableObjectReplayStore {
    async fn check_and_insert(
        &self,
        message_id: &[u8; crate::MESSAGE_ID_LEN],
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<ReplayCheck, ReplayStoreError> {
        let mut payload = [0u8; crate::MESSAGE_ID_LEN + 16];
        payload[..crate::MESSAGE_ID_LEN].copy_from_slice(message_id);
        payload[crate::MESSAGE_ID_LEN..crate::MESSAGE_ID_LEN + 8]
            .copy_from_slice(&expires_at_secs.to_be_bytes());
        payload[crate::MESSAGE_ID_LEN + 8..].copy_from_slice(&now_secs.to_be_bytes());
        let bytes = worker::js_sys::Uint8Array::new_with_length(payload.len() as u32);
        bytes.copy_from(&payload);
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post)
            .with_body(Some(bytes.into()));
        let request = worker::Request::new_with_init(DURABLE_REPLAY_URL, &init)
            .map_err(|error| ReplayStoreError::Backend(error.to_string()))?;
        let response = self
            .namespace
            .get_by_name(&format!("{}:{}", self.object_name, hex_id(message_id)))
            .map_err(|error| ReplayStoreError::Backend(error.to_string()))?
            .fetch_with_request(request)
            .await
            .map_err(|error| ReplayStoreError::Backend(error.to_string()))?;
        match response.status_code() {
            201 => Ok(ReplayCheck::Accepted),
            409 => Ok(ReplayCheck::Replay),
            status => Err(ReplayStoreError::Backend(format!(
                "Durable Object replay endpoint returned HTTP {status}"
            ))),
        }
    }
}

/// Handles one internal Durable Object replay-store request.
///
/// Call this from a `worker::DurableObject` fetch method. Durable Object
/// storage input gates serialize the read-then-write sequence, so exactly one
/// concurrent request for a message ID can receive `201 Created`; later calls
/// receive `409 Conflict`.
pub async fn check_and_insert_in_durable_object(
    storage: &worker::Storage,
    mut request: worker::Request,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post || request.path() != DURABLE_REPLAY_PATH {
        return worker::Response::error("Not Found", 404);
    }
    let payload = request.bytes().await?;
    if payload.len() != crate::MESSAGE_ID_LEN + 16 {
        return worker::Response::error("Bad Request", 400);
    }
    let mut id = [0u8; crate::MESSAGE_ID_LEN];
    id.copy_from_slice(&payload[..crate::MESSAGE_ID_LEN]);
    let mut expiry = [0u8; 8];
    expiry.copy_from_slice(&payload[crate::MESSAGE_ID_LEN..crate::MESSAGE_ID_LEN + 8]);
    let expires_at_secs = u64::from_be_bytes(expiry);
    let mut now = [0u8; 8];
    now.copy_from_slice(&payload[crate::MESSAGE_ID_LEN + 8..]);
    let now_secs = u64::from_be_bytes(now);
    if expires_at_secs <= now_secs {
        return worker::Response::error("Bad Request", 400);
    }
    // The client deterministically routes a message ID to this one object. The
    // ID is retained in the request format as defense in depth and to make the
    // internal protocol self-describing.
    let key = "foctet-replay-expiry";
    if let Some(existing_expiry) = storage.get::<String>(key).await? {
        let existing_expiry = existing_expiry
            .parse::<u64>()
            .map_err(|_| worker::Error::RustError("invalid Durable Object replay expiry".into()))?;
        if existing_expiry > now_secs {
            return worker::Response::empty().map(|response| response.with_status(409));
        }
    }
    storage.put(key, expires_at_secs.to_string()).await?;
    storage
        .set_alarm(expires_at_secs.saturating_mul(1_000).min(i64::MAX as u64) as i64)
        .await?;
    worker::Response::empty().map(|response| response.with_status(201))
}

/// Removes the one replay entry held by a per-message Durable Object.
///
/// Call this from the Durable Object's `alarm` handler. An alarm is at-least
/// once, so deleting all state is intentionally idempotent.
pub async fn expire_durable_object_replay_entry(
    storage: &worker::Storage,
) -> worker::Result<worker::Response> {
    storage.delete_all().await?;
    worker::Response::empty()
}

fn hex_id(message_id: &[u8; crate::MESSAGE_ID_LEN]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(crate::MESSAGE_ID_LEN * 2);
    for byte in message_id {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Lightweight request metadata extracted before body decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRequestMetadata {
    /// HTTP method name (for example, `POST`).
    pub method: String,
    /// URL path from the incoming request.
    pub path: String,
    /// Full URL string from the incoming request.
    pub url: String,
    /// Request headers as owned `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
}

/// Result shape for metadata-aware workers request opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedWorkerRequest {
    /// Convenience request metadata captured before opening the body.
    pub metadata: WorkerRequestMetadata,
    /// Decrypted plaintext request body bytes.
    pub plaintext: Vec<u8>,
}

/// Error type for workers-rs adapter operations.
#[derive(Debug, Error)]
pub enum WorkersError {
    /// workers-rs operation failed.
    #[error("workers operation failed")]
    Worker(#[from] worker::Error),
    /// Foctet HTTP-layer operation failed.
    #[error("foctet http operation failed")]
    Http(#[from] HttpError),
}

impl WorkersError {
    /// Classifies the required handling of this request-scoped adapter error.
    ///
    /// A Workers runtime failure has an unknown request-delivery outcome. Do
    /// not retry the same protected payload; create a new request only under
    /// application idempotency policy.
    pub const fn disposition(&self) -> HttpErrorDisposition {
        match self {
            Self::Worker(_) => HttpErrorDisposition::Reject,
            Self::Http(error) => error.disposition(),
        }
    }

    /// Maps this error to the HTTP status code a Worker should return.
    ///
    /// The mapping mirrors the axum adapter (`AxumError::into_response`) so both
    /// integrations answer a given failure identically: replays are `409`,
    /// expired or unopenable contexts are `401`, malformed requests are `400`,
    /// and only genuine server-side faults are `500`.
    ///
    /// Return *only* this status, with no error detail in the response body, so
    /// an opening or replay failure cannot leak ciphertext, key, or
    /// internal-state information to the caller.
    pub fn status_code(&self) -> u16 {
        match self {
            WorkersError::Http(
                HttpError::MissingContentType
                | HttpError::InvalidContentType
                | HttpError::MissingContext(_)
                | HttpError::InvalidContext(_)
                | HttpError::ContextTimestampInFuture
                | HttpError::StreamIncomplete,
            ) => 400,
            WorkersError::Http(HttpError::ContextExpired | HttpError::OpenFailed(_)) => 401,
            WorkersError::Http(HttpError::Replayed) => 409,
            WorkersError::Http(HttpError::SealFailed(_) | HttpError::ReplayStore(_)) => 500,
            WorkersError::Worker(_) => 500,
        }
    }
}

/// High-level Workers request opener.
#[derive(Clone, Debug)]
pub struct WorkersOpener {
    opener: HttpOpener,
}

/// High-level Workers response sealer.
#[derive(Clone, Debug)]
pub struct WorkersSealer {
    sealer: HttpSealer,
}

impl WorkersOpener {
    /// Creates a Workers opener from Foctet open options.
    pub fn new(options: HttpOpenOptions) -> Self {
        Self {
            opener: HttpOpener::new(options),
        }
    }

    /// Creates a Workers opener from an already-configured HTTP opener.
    pub fn from_http_opener(opener: HttpOpener) -> Self {
        Self { opener }
    }

    /// Returns the inner HTTP opener.
    pub fn opener(&self) -> &HttpOpener {
        &self.opener
    }

    /// Opens an encrypted Workers request body into plaintext bytes.
    pub async fn open_request_body(
        &self,
        mut request: worker::Request,
    ) -> Result<Vec<u8>, WorkersError> {
        crate::raw::ensure_foctet_content_type(&worker_headers_to_http(&request)?)?;
        let body = request.bytes().await?;
        self.opener.open_body(&body).map_err(WorkersError::Http)
    }

    /// Opens an encrypted Workers request into convenience metadata and plaintext bytes.
    ///
    /// Body-only; no replay protection or HTTP-context binding. Prefer
    /// [`WorkersOpener::open_request_with_context`] for production.
    #[deprecated(
        since = "0.3.0",
        note = "stateless full-request protection has no replay defense or HTTP-context \
                binding and is replayable by design; use open_request_with_context (or \
                open_request_with_async_store) with a ReplayStore for production"
    )]
    pub async fn open_request(
        &self,
        request: worker::Request,
    ) -> Result<OpenedWorkerRequest, WorkersError> {
        let metadata = extract_worker_request_metadata(&request)?;
        let plaintext = self.open_request_body(request).await?;
        Ok(OpenedWorkerRequest {
            metadata,
            plaintext,
        })
    }

    /// Opens an encrypted Workers request, enforcing the bound HTTP protected
    /// context, freshness, and single use against `store`.
    ///
    /// This is the recommended path for production Workers deployments: pair
    /// it with a durable [`AsyncReplayStore`] (e.g. Cloudflare KV) when more
    /// than one Worker instance may see the same request.
    pub async fn open_request_with_context<S>(
        &self,
        mut request: worker::Request,
        store: &S,
        now_secs: u64,
        max_skew_secs: u64,
        binding: ContextBinding,
    ) -> Result<http::Request<Vec<u8>>, WorkersError>
    where
        S: ReplayStore + ?Sized,
    {
        let parts = worker_request_to_http_parts(&request)?;
        let body = request.bytes().await?;
        let http_request = http::Request::from_parts(parts, body);
        self.opener
            .open_request_with_context(http_request, store, now_secs, max_skew_secs, binding)
            .map_err(WorkersError::Http)
    }

    /// Opens an encrypted Workers request using a durable [`AsyncReplayStore`]
    /// (Cloudflare KV, a Durable Object, or any other shared backend).
    pub async fn open_request_with_async_store<S>(
        &self,
        mut request: worker::Request,
        store: &S,
        now_secs: u64,
        max_skew_secs: u64,
        binding: ContextBinding,
    ) -> Result<http::Request<Vec<u8>>, WorkersError>
    where
        S: AsyncReplayStore + ?Sized,
    {
        let parts = worker_request_to_http_parts(&request)?;
        let body = request.bytes().await?;
        let http_request = http::Request::from_parts(parts, body);
        self.opener
            .open_request_with_async_store(http_request, store, now_secs, max_skew_secs, binding)
            .await
            .map_err(WorkersError::Http)
    }
}

impl WorkersSealer {
    /// Creates a Workers sealer from Foctet seal options.
    pub fn new(options: HttpSealOptions) -> Self {
        Self {
            sealer: HttpSealer::new(options),
        }
    }

    /// Creates a Workers sealer from an already-configured HTTP sealer.
    pub fn from_http_sealer(sealer: HttpSealer) -> Self {
        Self { sealer }
    }

    /// Returns the inner HTTP sealer.
    pub fn sealer(&self) -> &HttpSealer {
        &self.sealer
    }

    /// Seals plaintext bytes into a Workers response body.
    pub fn seal_response_body(&self, plaintext: &[u8]) -> Result<worker::Response, WorkersError> {
        let sealed = self.sealer.seal_body(plaintext)?;
        let mut response = worker::Response::from_bytes(sealed)?;
        response.headers_mut().set("content-type", CONTENT_TYPE)?;
        response.headers_mut().set(SCOPE_HEADER, BODY_ONLY_SCOPE)?;
        Ok(response)
    }

    /// Seals a plaintext response with bound protected context (status,
    /// message ID, timestamp, expiry, answered request message ID) into a
    /// Workers response.
    pub fn seal_response_with_context(
        &self,
        status: u16,
        plaintext: Vec<u8>,
        carrier: ContextCarrier,
    ) -> Result<worker::Response, WorkersError> {
        let response = http::Response::builder()
            .status(status)
            .body(plaintext)
            .expect("status and empty header map always build a valid response");
        let sealed = self.sealer.seal_response_with_context(response, carrier)?;
        let (parts, body) = sealed.into_parts();
        let mut response = worker::Response::from_bytes(body)?;
        response = response.with_status(parts.status.as_u16());
        for (name, value) in parts.headers.iter() {
            response
                .headers_mut()
                .set(name.as_str(), value.to_str().unwrap_or_default())?;
        }
        Ok(response)
    }
}

/// Opens an encrypted Workers request body into plaintext bytes.
pub async fn open_worker_request_body(
    request: worker::Request,
    recipient_secret_key: [u8; 32],
) -> Result<Vec<u8>, WorkersError> {
    WorkersOpener::new(HttpOpenOptions::new(recipient_secret_key))
        .open_request_body(request)
        .await
}

/// Opens an encrypted Workers request body into plaintext bytes with explicit envelope limits.
pub async fn open_worker_request_body_with_limits(
    request: worker::Request,
    recipient_secret_key: [u8; 32],
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, WorkersError> {
    WorkersOpener::new(HttpOpenOptions::new(recipient_secret_key).with_limits(limits.clone()))
        .open_request_body(request)
        .await
}

/// Opens an encrypted Workers request into metadata and plaintext body bytes.
#[deprecated(
    since = "0.3.0",
    note = "stateless full-request protection has no replay defense or HTTP-context binding \
            and is replayable by design; use WorkersOpener::open_request_with_context with a \
            ReplayStore for production"
)]
#[allow(deprecated)]
pub async fn open_worker_request(
    request: worker::Request,
    recipient_secret_key: [u8; 32],
) -> Result<OpenedWorkerRequest, WorkersError> {
    WorkersOpener::new(HttpOpenOptions::new(recipient_secret_key))
        .open_request(request)
        .await
}

/// Opens an encrypted Workers request into metadata and plaintext bytes with explicit limits.
#[deprecated(
    since = "0.3.0",
    note = "stateless full-request protection has no replay defense or HTTP-context binding \
            and is replayable by design; use WorkersOpener::open_request_with_context with a \
            ReplayStore for production"
)]
#[allow(deprecated)]
pub async fn open_worker_request_with_limits(
    request: worker::Request,
    recipient_secret_key: [u8; 32],
    limits: &BodyEnvelopeLimits,
) -> Result<OpenedWorkerRequest, WorkersError> {
    WorkersOpener::new(HttpOpenOptions::new(recipient_secret_key).with_limits(limits.clone()))
        .open_request(request)
        .await
}

/// Seals plaintext bytes into a Workers response body.
pub fn seal_worker_response_body(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
) -> Result<worker::Response, WorkersError> {
    WorkersSealer::new(HttpSealOptions::new(recipient_public_key, recipient_key_id))
        .seal_response_body(plaintext)
}

fn extract_worker_request_metadata(
    request: &worker::Request,
) -> Result<WorkerRequestMetadata, WorkersError> {
    let method = request.method().to_string();
    let path = request.path();
    let url = request.url()?.to_string();
    let headers = request.headers().entries().collect();

    Ok(WorkerRequestMetadata {
        method,
        path,
        url,
        headers,
    })
}

/// Builds `http::request::Parts` (method, URI, headers) from a `worker::Request`
/// so the protected-context binding sees the same routing metadata the Worker
/// runtime dispatched on.
fn worker_request_to_http_parts(
    request: &worker::Request,
) -> Result<http::request::Parts, WorkersError> {
    let method = http::Method::from_bytes(request.method().to_string().as_bytes())
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    let url = request.url()?;
    let uri = url
        .as_str()
        .parse::<http::Uri>()
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    let headers = worker_headers_to_http(request)?;

    let mut builder = http::Request::builder().method(method).uri(uri);
    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }
    let (parts, _) = builder
        .body(())
        .map_err(|err| worker::Error::RustError(err.to_string()))?
        .into_parts();
    Ok(parts)
}

fn worker_headers_to_http(request: &worker::Request) -> Result<http::HeaderMap, worker::Error> {
    let mut out = http::HeaderMap::new();
    for (name, value) in request.headers().entries() {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| worker::Error::RustError(err.to_string()))?;
        let value = http::header::HeaderValue::from_str(&value)
            .map_err(|err| worker::Error::RustError(err.to_string()))?;
        out.append(name, value);
    }
    Ok(out)
}
