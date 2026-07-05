//! WebAssembly bindings for Foctet end-to-end encryption.
//!
//! This crate exposes a small JavaScript/TypeScript API for the
//! `application/foctet` body envelope and the framed `FoctetSession`, so
//! browsers and JS runtimes can interoperate with the Rust implementation.
//!
//! Byte values cross the boundary as `Uint8Array`, and fallible operations
//! throw a JavaScript `Error` rather than aborting the WASM instance.
//!
//! [`KeyPair`] exposes raw X25519 key bytes, so callers are responsible for
//! storing secret keys safely.
//!
//! The body-envelope APIs protect payload bytes and optional associated context,
//! not outer HTTP metadata. Pair them with an authenticated outer channel when
//! used over HTTP.

use std::fmt;

use foctet_core::{
    BodyEnvelopeError, BodyEnvelopeLimits, open_body, open_body_with_context, seal_body,
    seal_body_with_context,
};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

mod http_context;
mod session;
pub use http_context::{WasmHttpContextCarrier, WasmHttpRequestContext, WasmHttpResponseContext};
pub use session::{FoctetSession, WasmAuthConfig, WasmDecodedMessage, WasmIdentityKeyPair};

/// X25519 public/secret key length in bytes.
pub const KEY_LEN: usize = 32;

/// Error returned by the inner (native-testable) functions.
#[derive(Debug)]
enum WasmError {
    /// A key argument was not exactly [`KEY_LEN`] bytes.
    BadKeyLength,
    /// A body-envelope seal/open operation failed.
    Envelope(BodyEnvelopeError),
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmError::BadKeyLength => write!(f, "expected a 32-byte X25519 key"),
            WasmError::Envelope(err) => write!(f, "{err}"),
        }
    }
}

impl From<BodyEnvelopeError> for WasmError {
    fn from(err: BodyEnvelopeError) -> Self {
        WasmError::Envelope(err)
    }
}

fn to_key(bytes: &[u8]) -> Result<[u8; KEY_LEN], WasmError> {
    <[u8; KEY_LEN]>::try_from(bytes).map_err(|_| WasmError::BadKeyLength)
}

fn seal_inner(
    plaintext: &[u8],
    recipient_public_key: &[u8],
    recipient_key_id: &[u8],
) -> Result<Vec<u8>, WasmError> {
    let rpk = to_key(recipient_public_key)?;
    Ok(seal_body(plaintext, rpk, recipient_key_id)?)
}

fn open_inner(envelope: &[u8], recipient_secret_key: &[u8]) -> Result<Vec<u8>, WasmError> {
    let rsk = to_key(recipient_secret_key)?;
    Ok(open_body(envelope, rsk)?)
}

fn seal_ctx_inner(
    plaintext: &[u8],
    recipient_public_key: &[u8],
    recipient_key_id: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, WasmError> {
    let rpk = to_key(recipient_public_key)?;
    Ok(seal_body_with_context(
        plaintext,
        rpk,
        recipient_key_id,
        context,
        &BodyEnvelopeLimits::default(),
    )?)
}

fn open_ctx_inner(
    envelope: &[u8],
    recipient_secret_key: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, WasmError> {
    let rsk = to_key(recipient_secret_key)?;
    Ok(open_body_with_context(
        envelope,
        rsk,
        context,
        &BodyEnvelopeLimits::default(),
    )?)
}

fn to_js(err: WasmError) -> JsError {
    JsError::new(&err.to_string())
}

/// Returns the SDK version string (the crate version).
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// An X25519 recipient key pair.
#[wasm_bindgen]
pub struct KeyPair {
    secret: StaticSecret,
    public: [u8; KEY_LEN],
}

#[wasm_bindgen]
impl KeyPair {
    /// Generates a fresh random X25519 key pair.
    #[wasm_bindgen(constructor)]
    pub fn generate() -> KeyPair {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        KeyPair { secret, public }
    }

    /// Reconstructs a key pair from 32 secret-key bytes.
    #[wasm_bindgen(js_name = fromSecretKey)]
    pub fn from_secret_key(secret_key: &[u8]) -> Result<KeyPair, JsError> {
        let bytes = to_key(secret_key).map_err(to_js)?;
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(KeyPair { secret, public })
    }

    /// The 32-byte public key.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public.to_vec()
    }

    /// The 32-byte secret key. Handle with care.
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.secret.to_bytes().to_vec()
    }
}

/// Seals `plaintext` into an `application/foctet` body envelope for the holder
/// of the secret key matching `recipient_public_key`.
#[wasm_bindgen(js_name = sealBody)]
pub fn seal_body_js(
    plaintext: &[u8],
    recipient_public_key: &[u8],
    recipient_key_id: &[u8],
) -> Result<Vec<u8>, JsError> {
    seal_inner(plaintext, recipient_public_key, recipient_key_id).map_err(to_js)
}

/// Opens an `application/foctet` body envelope using `recipient_secret_key`.
#[wasm_bindgen(js_name = openBody)]
pub fn open_body_js(envelope: &[u8], recipient_secret_key: &[u8]) -> Result<Vec<u8>, JsError> {
    open_inner(envelope, recipient_secret_key).map_err(to_js)
}

/// Seals `plaintext`, additionally authenticating `context` as associated data.
///
/// The opener must supply byte-identical `context` or the open fails. An empty
/// `context` is byte-identical to [`seal_body_js`].
#[wasm_bindgen(js_name = sealBodyWithContext)]
pub fn seal_body_with_context_js(
    plaintext: &[u8],
    recipient_public_key: &[u8],
    recipient_key_id: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsError> {
    seal_ctx_inner(plaintext, recipient_public_key, recipient_key_id, context).map_err(to_js)
}

/// Opens a context-bound envelope, requiring the same `context` used to seal it.
#[wasm_bindgen(js_name = openBodyWithContext)]
pub fn open_body_with_context_js(
    envelope: &[u8],
    recipient_secret_key: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, JsError> {
    open_ctx_inner(envelope, recipient_secret_key, context).map_err(to_js)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair_bytes() -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
        let kp = KeyPair::generate();
        let public = <[u8; KEY_LEN]>::try_from(kp.public_key().as_slice()).expect("public");
        let secret = <[u8; KEY_LEN]>::try_from(kp.secret_key().as_slice()).expect("secret");
        (public, secret)
    }

    #[test]
    fn body_roundtrip() {
        let (public, secret) = keypair_bytes();
        let plaintext = b"wasm body payload";
        let envelope = seal_inner(plaintext, &public, b"kid").expect("seal");
        let opened = open_inner(&envelope, &secret).expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn wrong_key_length_is_error_not_panic() {
        assert!(matches!(
            seal_inner(b"x", &[0u8; 31], b"kid"),
            Err(WasmError::BadKeyLength)
        ));
        assert!(matches!(
            open_inner(&[0u8; 10], &[0u8; 33]),
            Err(WasmError::BadKeyLength)
        ));
    }

    #[test]
    fn context_binding_roundtrip_and_mismatch() {
        let (public, secret) = keypair_bytes();
        let plaintext = b"context payload";
        let ctx = b"foctet-http-ctx-v1|POST|/pay";
        let envelope = seal_ctx_inner(plaintext, &public, b"kid", ctx).expect("seal");

        let opened = open_ctx_inner(&envelope, &secret, ctx).expect("open");
        assert_eq!(opened, plaintext);

        assert!(open_ctx_inner(&envelope, &secret, b"other").is_err());
        // Opening a context-bound envelope without context must also fail.
        assert!(open_inner(&envelope, &secret).is_err());
    }

    #[test]
    fn from_secret_key_recovers_public() {
        let kp = KeyPair::generate();
        let rebuilt =
            KeyPair::from_secret_key(&kp.secret_key()).unwrap_or_else(|_| panic!("from secret"));
        assert_eq!(rebuilt.public_key(), kp.public_key());
    }
}
