//! High-level HTTP integration for `application/foctet` body envelopes.
//!
//! `foctet-http` adapts HTTP requests and responses onto the body-complete
//! envelope format.
//!
//! # Layers
//!
//! - Recommended high-level API:
//!   [`HttpSealer`] and [`HttpOpener`]
//! - Framework adapters:
//!   [`axum`] and [`workers`]
//! - Lower-level helpers:
//!   [`raw`]
//!

/// Re-export of the `http` crate used by this adapter.
pub use http;

mod config;
mod error;
pub mod raw;

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(all(feature = "workers", target_arch = "wasm32"))]
pub mod workers;

use http::{
    Request, Response,
    header::{self},
};

pub use config::{HttpConfig, HttpOpenOptions, HttpSealOptions};
pub use error::HttpError;

/// Foctet HTTP media type.
pub const CONTENT_TYPE: &str = "application/foctet";

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

    /// Seals a plaintext request and sets `Content-Type: application/foctet`.
    pub fn seal_request(&self, request: Request<Vec<u8>>) -> Result<Request<Vec<u8>>, HttpError> {
        let (mut parts, body) = request.into_parts();
        let sealed = self.seal_body(&body)?;
        raw::set_foctet_content_type(&mut parts.headers);
        Ok(Request::from_parts(parts, sealed))
    }

    /// Seals a plaintext response and sets `Content-Type: application/foctet`.
    pub fn seal_response(
        &self,
        response: Response<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, HttpError> {
        let (mut parts, body) = response.into_parts();
        let sealed = self.seal_body(&body)?;
        raw::set_foctet_content_type(&mut parts.headers);
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

    /// Opens an `application/foctet` body into plaintext bytes.
    pub fn open_body(&self, envelope: &[u8]) -> Result<Vec<u8>, HttpError> {
        match self.options.limits() {
            Some(limits) => raw::open_http_body_with_limits(
                envelope,
                self.options.recipient_secret_key(),
                limits,
            ),
            None => raw::open_http_body(envelope, self.options.recipient_secret_key()),
        }
    }

    /// Opens an encrypted request body into plaintext bytes.
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
    use http::{Request, Response, StatusCode, Version, header};
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;

    #[test]
    fn sealer_and_opener_roundtrip_request_and_response() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
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
        let opened_request = opener.open_request(sealed_request).expect("open request");

        assert_eq!(opened_request.method(), "POST");
        assert_eq!(opened_request.uri().path(), "/submit");
        assert_eq!(opened_request.headers()["x-trace-id"], "abc123");
        assert!(!opened_request.headers().contains_key(header::CONTENT_TYPE));
        assert_eq!(opened_request.body(), b"request payload");

        let response = Response::builder()
            .status(StatusCode::CREATED)
            .version(Version::HTTP_2)
            .header("x-server", "foctet")
            .body(b"response payload".to_vec())
            .expect("response");

        let sealed_response = sealer.seal_response(response).expect("seal response");
        let opened_response = opener
            .open_response(sealed_response)
            .expect("open response");

        assert_eq!(opened_response.status(), StatusCode::CREATED);
        assert_eq!(opened_response.version(), Version::HTTP_2);
        assert_eq!(opened_response.headers()["x-server"], "foctet");
        assert_eq!(opened_response.body(), b"response payload");
    }

    #[test]
    fn opener_respects_explicit_config() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
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
}
