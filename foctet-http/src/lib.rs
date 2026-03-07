//! Thin HTTP adapter for `application/foctet` body envelopes.
//!
//! # Features
//!
//! - default: raw `http` request/response helpers over `Vec<u8>` bodies.
//! - `axum`: optional helpers for Axum request body extraction and response creation.
//! - `workers`: optional helpers for `workers-rs` request/response body conversion (wasm32).

/// Re-export of the `http` crate used by this adapter.
pub use http;

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(all(feature = "workers", target_arch = "wasm32"))]
pub mod workers;

use foctet_core::{
    BodyEnvelopeError, BodyEnvelopeLimits, open_body, open_body_with_limits, seal_body,
    seal_body_with_limits,
};
use http::{
    HeaderMap, Request, Response,
    header::{self, HeaderValue},
};
use thiserror::Error;

/// Foctet HTTP media type.
pub const CONTENT_TYPE: &str = "application/foctet";

/// Error type for thin HTTP integration over `foctet-core` body envelopes.
#[derive(Debug, Error)]
pub enum HttpError {
    /// Missing `Content-Type` header.
    #[error("missing content-type header")]
    MissingContentType,
    /// `Content-Type` is present but not `application/foctet`.
    #[error("invalid content-type: expected application/foctet")]
    InvalidContentType,
    /// Body sealing failed.
    #[error("failed to seal HTTP body")]
    SealFailed(#[source] BodyEnvelopeError),
    /// Body opening failed.
    #[error("failed to open HTTP body")]
    OpenFailed(#[source] BodyEnvelopeError),
}

/// Sets `Content-Type: application/foctet`.
pub fn set_foctet_content_type(headers: &mut HeaderMap) {
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
}

/// Returns `true` if headers contain `Content-Type: application/foctet`.
///
/// Parameters after `;` are tolerated.
pub fn is_foctet_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_foctet_content_type_value)
}

/// Validates that headers contain `Content-Type: application/foctet`.
pub fn ensure_foctet_content_type(headers: &HeaderMap) -> Result<(), HttpError> {
    let value = headers
        .get(header::CONTENT_TYPE)
        .ok_or(HttpError::MissingContentType)?;

    let value = value.to_str().map_err(|_| HttpError::InvalidContentType)?;
    if is_foctet_content_type_value(value) {
        return Ok(());
    }

    Err(HttpError::InvalidContentType)
}

/// Seals raw plaintext bytes to an `application/foctet` body.
pub fn seal_http_body(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
) -> Result<Vec<u8>, HttpError> {
    seal_body(plaintext, recipient_public_key, recipient_key_id).map_err(HttpError::SealFailed)
}

/// Seals raw plaintext bytes to an `application/foctet` body with explicit limits.
pub fn seal_http_body_with_limits(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, HttpError> {
    seal_body_with_limits(plaintext, recipient_public_key, recipient_key_id, limits)
        .map_err(HttpError::SealFailed)
}

/// Opens an `application/foctet` body to plaintext bytes.
pub fn open_http_body(
    envelope: &[u8],
    recipient_secret_key: [u8; 32],
) -> Result<Vec<u8>, HttpError> {
    open_body(envelope, recipient_secret_key).map_err(HttpError::OpenFailed)
}

/// Opens an `application/foctet` body to plaintext bytes with explicit limits.
pub fn open_http_body_with_limits(
    envelope: &[u8],
    recipient_secret_key: [u8; 32],
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, HttpError> {
    open_body_with_limits(envelope, recipient_secret_key, limits).map_err(HttpError::OpenFailed)
}

/// Seals request body and sets `Content-Type: application/foctet`.
pub fn seal_http_request(
    request: Request<Vec<u8>>,
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
) -> Result<Request<Vec<u8>>, HttpError> {
    let (mut parts, body) = request.into_parts();
    let sealed = seal_http_body(&body, recipient_public_key, recipient_key_id)?;
    set_foctet_content_type(&mut parts.headers);
    Ok(Request::from_parts(parts, sealed))
}

/// Seals request body with explicit limits and sets `Content-Type: application/foctet`.
pub fn seal_http_request_with_limits(
    request: Request<Vec<u8>>,
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
    limits: &BodyEnvelopeLimits,
) -> Result<Request<Vec<u8>>, HttpError> {
    let (mut parts, body) = request.into_parts();
    let sealed = seal_http_body_with_limits(&body, recipient_public_key, recipient_key_id, limits)?;
    set_foctet_content_type(&mut parts.headers);
    Ok(Request::from_parts(parts, sealed))
}

/// Validates foctet content type and opens request body.
///
/// The `Content-Type` header is removed from the returned request because the body is now plaintext.
pub fn open_http_request(
    request: Request<Vec<u8>>,
    recipient_secret_key: [u8; 32],
) -> Result<Request<Vec<u8>>, HttpError> {
    let (mut parts, body) = request.into_parts();
    ensure_foctet_content_type(&parts.headers)?;
    let plain = open_http_body(&body, recipient_secret_key)?;
    parts.headers.remove(header::CONTENT_TYPE);
    Ok(Request::from_parts(parts, plain))
}

/// Validates foctet content type and opens request body with explicit limits.
pub fn open_http_request_with_limits(
    request: Request<Vec<u8>>,
    recipient_secret_key: [u8; 32],
    limits: &BodyEnvelopeLimits,
) -> Result<Request<Vec<u8>>, HttpError> {
    let (mut parts, body) = request.into_parts();
    ensure_foctet_content_type(&parts.headers)?;
    let plain = open_http_body_with_limits(&body, recipient_secret_key, limits)?;
    parts.headers.remove(header::CONTENT_TYPE);
    Ok(Request::from_parts(parts, plain))
}

/// Seals response body and sets `Content-Type: application/foctet`.
pub fn seal_http_response(
    response: Response<Vec<u8>>,
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
) -> Result<Response<Vec<u8>>, HttpError> {
    let (mut parts, body) = response.into_parts();
    let sealed = seal_http_body(&body, recipient_public_key, recipient_key_id)?;
    set_foctet_content_type(&mut parts.headers);
    Ok(Response::from_parts(parts, sealed))
}

/// Seals response body with explicit limits and sets `Content-Type: application/foctet`.
pub fn seal_http_response_with_limits(
    response: Response<Vec<u8>>,
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
    limits: &BodyEnvelopeLimits,
) -> Result<Response<Vec<u8>>, HttpError> {
    let (mut parts, body) = response.into_parts();
    let sealed = seal_http_body_with_limits(&body, recipient_public_key, recipient_key_id, limits)?;
    set_foctet_content_type(&mut parts.headers);
    Ok(Response::from_parts(parts, sealed))
}

/// Validates foctet content type and opens response body.
///
/// The `Content-Type` header is removed from the returned response because the body is now plaintext.
pub fn open_http_response(
    response: Response<Vec<u8>>,
    recipient_secret_key: [u8; 32],
) -> Result<Response<Vec<u8>>, HttpError> {
    let (mut parts, body) = response.into_parts();
    ensure_foctet_content_type(&parts.headers)?;
    let plain = open_http_body(&body, recipient_secret_key)?;
    parts.headers.remove(header::CONTENT_TYPE);
    Ok(Response::from_parts(parts, plain))
}

/// Validates foctet content type and opens response body with explicit limits.
pub fn open_http_response_with_limits(
    response: Response<Vec<u8>>,
    recipient_secret_key: [u8; 32],
    limits: &BodyEnvelopeLimits,
) -> Result<Response<Vec<u8>>, HttpError> {
    let (mut parts, body) = response.into_parts();
    ensure_foctet_content_type(&parts.headers)?;
    let plain = open_http_body_with_limits(&body, recipient_secret_key, limits)?;
    parts.headers.remove(header::CONTENT_TYPE);
    Ok(Response::from_parts(parts, plain))
}

pub(crate) fn is_foctet_content_type_value(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or_default().trim();
    media_type.eq_ignore_ascii_case(CONTENT_TYPE)
}

#[cfg(test)]
mod tests {
    use http::{Request, Response, StatusCode, Version, header};
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;

    #[test]
    fn content_type_helpers_set_and_check() {
        let mut headers = HeaderMap::new();
        assert!(!is_foctet_content_type(&headers));

        set_foctet_content_type(&mut headers);
        assert!(is_foctet_content_type(&headers));
        assert!(ensure_foctet_content_type(&headers).is_ok());
    }

    #[test]
    fn content_type_helper_accepts_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/foctet; charset=binary"),
        );
        assert!(is_foctet_content_type(&headers));
    }

    #[test]
    fn seal_open_http_body_roundtrip() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let plain = b"http body bytes";
        let sealed = seal_http_body(plain, recipient_pub, b"http-kid").expect("seal");
        let out = open_http_body(&sealed, recipient_priv.to_bytes()).expect("open");

        assert_eq!(out, plain);
    }

    #[test]
    fn wrong_content_type_rejected_on_request_open() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);

        let req = Request::builder()
            .uri("https://example.com/upload")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Vec::new())
            .expect("request");

        let err = open_http_request(req, recipient_priv.to_bytes()).expect_err("must fail");
        assert!(matches!(err, HttpError::InvalidContentType));
    }

    #[test]
    fn request_and_response_helpers_roundtrip() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let request = Request::builder()
            .method("POST")
            .uri("https://example.com/submit")
            .version(Version::HTTP_11)
            .header("x-trace-id", "abc123")
            .body(b"request payload".to_vec())
            .expect("request");

        let sealed_request =
            seal_http_request(request, recipient_pub, b"kid-rq").expect("seal request");
        assert!(is_foctet_content_type(sealed_request.headers()));

        let opened_request =
            open_http_request(sealed_request, recipient_priv.to_bytes()).expect("open request");

        assert_eq!(opened_request.method(), "POST");
        assert_eq!(opened_request.uri().path(), "/submit");
        assert_eq!(opened_request.version(), Version::HTTP_11);
        assert_eq!(opened_request.headers()["x-trace-id"], "abc123");
        assert!(!opened_request.headers().contains_key(header::CONTENT_TYPE));
        assert_eq!(opened_request.body(), b"request payload");

        let response = Response::builder()
            .status(StatusCode::CREATED)
            .version(Version::HTTP_2)
            .header("x-server", "foctet")
            .body(b"response payload".to_vec())
            .expect("response");

        let sealed_response =
            seal_http_response(response, recipient_pub, b"kid-rs").expect("seal response");
        assert!(is_foctet_content_type(sealed_response.headers()));

        let opened_response =
            open_http_response(sealed_response, recipient_priv.to_bytes()).expect("open response");

        assert_eq!(opened_response.status(), StatusCode::CREATED);
        assert_eq!(opened_response.version(), Version::HTTP_2);
        assert_eq!(opened_response.headers()["x-server"], "foctet");
        assert!(!opened_response.headers().contains_key(header::CONTENT_TYPE));
        assert_eq!(opened_response.body(), b"response payload");
    }

    #[test]
    fn with_limits_passthrough_behaves_as_expected() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let plain = b"limits check";
        let sealed = seal_http_body(plain, recipient_pub, b"kid").expect("seal");

        let limits = BodyEnvelopeLimits {
            max_header_bytes: 16,
            ..BodyEnvelopeLimits::default()
        };

        let err = open_http_body_with_limits(&sealed, recipient_priv.to_bytes(), &limits)
            .expect_err("must fail");

        assert!(matches!(
            err,
            HttpError::OpenFailed(BodyEnvelopeError::LimitExceeded("header_len"))
        ));
    }
}
