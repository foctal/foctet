//! Cloudflare Workers adapters built on top of the high-level Foctet HTTP API.
//!
//! These adapters protect the request or response body bytes while leaving the
//! surrounding Worker routing metadata, headers, and method visible to the
//! outer HTTPS channel and Worker runtime.

use foctet_core::BodyEnvelopeLimits;
use thiserror::Error;

use crate::{
    AsyncReplayStore, BODY_ONLY_SCOPE, CONTENT_TYPE, ContextBinding, ContextCarrier, HttpError,
    HttpOpenOptions, HttpOpener, HttpSealOptions, HttpSealer, ReplayStore, SCOPE_HEADER,
};

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
pub async fn open_worker_request(
    request: worker::Request,
    recipient_secret_key: [u8; 32],
) -> Result<OpenedWorkerRequest, WorkersError> {
    WorkersOpener::new(HttpOpenOptions::new(recipient_secret_key))
        .open_request(request)
        .await
}

/// Opens an encrypted Workers request into metadata and plaintext bytes with explicit limits.
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
