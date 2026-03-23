//! Axum adapters built on top of the high-level Foctet HTTP API.
//!
//! These adapters preserve the surrounding HTTP request and response metadata.
//! Only the body bytes are protected by the Foctet envelope.

use ::axum::body::{Body, to_bytes};
use ::axum::extract::Request as AxumRequest;
use ::axum::response::Response as AxumResponse;
use thiserror::Error;

use crate::{HttpError, HttpOpenOptions, HttpOpener, HttpSealOptions, HttpSealer};

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
}

/// Opens an encrypted Axum request body into plaintext bytes.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BODY_ONLY_SCOPE, CONTENT_TYPE, HttpSealer, SCOPE_HEADER, raw::seal_http_request};
    use http::{Request, Response, StatusCode, Version, header};
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[tokio::test]
    async fn open_axum_request_body_roundtrip() {
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
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
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

    #[test]
    fn sealer_wrapper_uses_http_core() {
        let sealer =
            AxumSealer::from_http_sealer(HttpSealer::new(HttpSealOptions::new([1u8; 32], b"kid")));
        assert_eq!(sealer.sealer().options().recipient_key_id(), b"kid");
    }
}
