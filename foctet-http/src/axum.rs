//! Axum adapter helpers for `application/foctet` bodies.
//!
//! This module only bridges Axum body types with `foctet-http` raw HTTP helpers.

use ::axum::body::{Body, to_bytes};
use ::axum::extract::Request as AxumRequest;
use ::axum::response::Response as AxumResponse;
use thiserror::Error;

use crate::{
    HttpError, open_http_request, open_http_request_with_limits, seal_http_response,
    seal_http_response_with_limits,
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

/// Opens an encrypted Axum request body into plaintext bytes.
///
/// This validates `Content-Type: application/foctet`, decrypts via `foctet-core`,
/// and returns a request with `Vec<u8>` plaintext body.
pub async fn open_axum_request(
    request: AxumRequest,
    recipient_secret_key: [u8; 32],
    max_body_bytes: usize,
) -> Result<http::Request<Vec<u8>>, AxumError> {
    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, max_body_bytes)
        .await
        .map_err(AxumError::BodyRead)?;
    let request = http::Request::from_parts(parts, body_bytes.to_vec());
    open_http_request(request, recipient_secret_key).map_err(AxumError::Http)
}

/// Opens an encrypted Axum request body into plaintext bytes with explicit envelope limits.
pub async fn open_axum_request_with_limits(
    request: AxumRequest,
    recipient_secret_key: [u8; 32],
    max_body_bytes: usize,
    limits: &foctet_core::BodyEnvelopeLimits,
) -> Result<http::Request<Vec<u8>>, AxumError> {
    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, max_body_bytes)
        .await
        .map_err(AxumError::BodyRead)?;
    let request = http::Request::from_parts(parts, body_bytes.to_vec());
    open_http_request_with_limits(request, recipient_secret_key, limits).map_err(AxumError::Http)
}

/// Seals a plaintext `http::Response<Vec<u8>>` and returns an Axum response.
///
/// `Content-Type: application/foctet` is set on the encrypted response.
pub fn seal_axum_response(
    response: http::Response<Vec<u8>>,
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
) -> Result<AxumResponse, AxumError> {
    let encrypted = seal_http_response(response, recipient_public_key, recipient_key_id)?;
    Ok(http_response_vec_to_axum(encrypted))
}

/// Seals a plaintext `http::Response<Vec<u8>>` with explicit envelope limits and returns an Axum response.
pub fn seal_axum_response_with_limits(
    response: http::Response<Vec<u8>>,
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
    limits: &foctet_core::BodyEnvelopeLimits,
) -> Result<AxumResponse, AxumError> {
    let encrypted =
        seal_http_response_with_limits(response, recipient_public_key, recipient_key_id, limits)?;
    Ok(http_response_vec_to_axum(encrypted))
}

fn http_response_vec_to_axum(response: http::Response<Vec<u8>>) -> AxumResponse {
    let (parts, body) = response.into_parts();
    AxumResponse::from_parts(parts, Body::from(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CONTENT_TYPE, seal_http_request};
    use http::{Request, Response, StatusCode, Version, header};
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[tokio::test]
    async fn open_axum_request_roundtrip() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
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

        let opened = open_axum_request(axum_request, recipient_priv.to_bytes(), 1024 * 1024)
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
    fn seal_axum_response_sets_content_type() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let response = Response::builder()
            .status(StatusCode::ACCEPTED)
            .version(Version::HTTP_2)
            .header("x-origin", "axum")
            .body(b"axum response body".to_vec())
            .expect("response");

        let sealed = seal_axum_response(response, recipient_pub, b"axum-kid").expect("seal");

        assert_eq!(sealed.status(), StatusCode::ACCEPTED);
        assert_eq!(sealed.version(), Version::HTTP_2);
        assert_eq!(sealed.headers()["x-origin"], "axum");
        assert_eq!(
            sealed.headers()[header::CONTENT_TYPE],
            header::HeaderValue::from_static(CONTENT_TYPE)
        );
    }
}
