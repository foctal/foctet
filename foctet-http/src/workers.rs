//! workers-rs adapter helpers for `application/foctet` bodies.
//!
//! This module bridges workers request/response body handling with `foctet-http` helpers.

use thiserror::Error;

use crate::{
    CONTENT_TYPE, HttpError, is_foctet_content_type_value, open_http_body, seal_http_body,
};

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
    let content_type = request
        .headers()
        .get("content-type")?
        .ok_or(HttpError::MissingContentType)?;

    if !is_foctet_content_type_value(&content_type) {
        return Err(HttpError::InvalidContentType.into());
    }

    let body = request.bytes().await?;
    open_http_body(&body, recipient_secret_key).map_err(WorkersError::Http)
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
