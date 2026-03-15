//! Cloudflare Workers adapters built on top of the high-level Foctet HTTP API.

use foctet_core::BodyEnvelopeLimits;
use thiserror::Error;

use crate::{CONTENT_TYPE, HttpError, HttpOpenOptions, HttpOpener, HttpSealOptions, HttpSealer};

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
