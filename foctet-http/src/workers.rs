//! workers-rs adapter helpers for `application/foctet` bodies.
//!
//! This module bridges workers request/response body handling with `foctet-http` helpers.

use foctet_core::BodyEnvelopeLimits;
use thiserror::Error;

use crate::{
    CONTENT_TYPE, HttpError, is_foctet_content_type_value, open_http_body,
    open_http_body_with_limits, seal_http_body,
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

/// Opens an encrypted workers request body into plaintext bytes.
///
/// This validates `Content-Type: application/foctet` before decryption.
pub async fn open_worker_request_body(
    mut request: worker::Request,
    recipient_secret_key: [u8; 32],
) -> Result<Vec<u8>, WorkersError> {
    ensure_worker_request_content_type(&request)?;

    let body = request.bytes().await?;
    open_http_body(&body, recipient_secret_key).map_err(WorkersError::Http)
}

/// Opens an encrypted workers request body into plaintext bytes with explicit envelope limits.
///
/// This validates `Content-Type: application/foctet` before decryption.
pub async fn open_worker_request_body_with_limits(
    mut request: worker::Request,
    recipient_secret_key: [u8; 32],
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, WorkersError> {
    ensure_worker_request_content_type(&request)?;

    let body = request.bytes().await?;
    open_http_body_with_limits(&body, recipient_secret_key, limits).map_err(WorkersError::Http)
}

/// Opens an encrypted workers request into metadata and plaintext body bytes.
///
/// Metadata is extracted before body consumption so callers can retain request context
/// while using the same body-complete decryption path.
pub async fn open_worker_request(
    request: worker::Request,
    recipient_secret_key: [u8; 32],
) -> Result<OpenedWorkerRequest, WorkersError> {
    let metadata = extract_worker_request_metadata(&request)?;
    let plaintext = open_worker_request_body(request, recipient_secret_key).await?;
    Ok(OpenedWorkerRequest {
        metadata,
        plaintext,
    })
}

/// Opens an encrypted workers request into metadata and plaintext bytes with explicit limits.
pub async fn open_worker_request_with_limits(
    request: worker::Request,
    recipient_secret_key: [u8; 32],
    limits: &BodyEnvelopeLimits,
) -> Result<OpenedWorkerRequest, WorkersError> {
    let metadata = extract_worker_request_metadata(&request)?;
    let plaintext =
        open_worker_request_body_with_limits(request, recipient_secret_key, limits).await?;
    Ok(OpenedWorkerRequest {
        metadata,
        plaintext,
    })
}

/// Seals plaintext bytes into a workers response body.
///
/// `Content-Type: application/foctet` is set on the returned response.
pub fn seal_worker_response_body(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
) -> Result<worker::Response, WorkersError> {
    let sealed = seal_http_body(plaintext, recipient_public_key, recipient_key_id)?;

    let mut response = worker::Response::from_bytes(sealed)?;
    response.headers_mut().set("content-type", CONTENT_TYPE)?;
    Ok(response)
}

fn ensure_worker_request_content_type(request: &worker::Request) -> Result<(), WorkersError> {
    let content_type = request
        .headers()
        .get("content-type")?
        .ok_or(HttpError::MissingContentType)?;

    if is_foctet_content_type_value(&content_type) {
        return Ok(());
    }

    Err(HttpError::InvalidContentType.into())
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
