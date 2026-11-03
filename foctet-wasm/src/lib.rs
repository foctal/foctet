#![cfg_attr(docsrs, feature(doc_cfg))]
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
use getrandom::SysRng;
use rand_core::UnwrapErr;
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
        let secret = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
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

/// Verifies a detached signature against an independently trusted writer pin.
/// Call before opening a body or archive; throws on missing/malformed signatures.
#[wasm_bindgen(js_name = verifyCiphertext)]
pub fn verify_ciphertext_js(
    ciphertext: &[u8],
    context: &[u8],
    signature: &[u8],
    writer: &[u8],
) -> Result<(), JsError> {
    let signature =
        <[u8; 64]>::try_from(signature).map_err(|_| JsError::new("expected 64 signature bytes"))?;
    let writer =
        <[u8; 32]>::try_from(writer).map_err(|_| JsError::new("expected 32 writer key bytes"))?;
    foctet_core::verify_ciphertext(
        ciphertext,
        context,
        signature,
        foctet_core::PeerIdentity::new(writer),
    )
    .map_err(|_| JsError::new("writer authentication failed"))
}

/// Verifies a pinned writer and then opens a context-bound body.
#[wasm_bindgen(js_name = openSignedBodyWithContext)]
pub fn open_signed_body_js(
    envelope: &[u8],
    secret: &[u8],
    context: &[u8],
    signature: &[u8],
    writer: &[u8],
) -> Result<Vec<u8>, JsError> {
    let limits = BodyEnvelopeLimits::default();
    if envelope.len()
        > limits
            .max_header_bytes
            .saturating_add(limits.max_payload_len)
        || context.len() > limits.max_context_len
    {
        return Err(JsError::new("signed body exceeds limits"));
    }
    verify_ciphertext_js(envelope, context, signature, writer)?;
    open_body_with_context_js(envelope, secret, context)
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

/// Encrypted object and detached writer signature. Neither getter reveals a key.
#[wasm_bindgen(js_name = SignedObject)]
pub struct WasmSignedObject {
    ciphertext: Vec<u8>,
    signature: [u8; 64],
}
#[wasm_bindgen(js_class = SignedObject)]
impl WasmSignedObject {
    /// Exact ciphertext bytes to store or forward.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    /// Canonical ASCII record for Worker TEXT storage; ciphertext and signature
    /// travel together. Rejects records above the portable 1 MiB text budget.
    #[wasm_bindgen(js_name = toStorageText)]
    pub fn to_storage_text(&self) -> Result<String, JsError> {
        foctet_storage_wire::TextRecord::from_parts(&self.ciphertext, &self.signature)
            .map(|record| record.as_str().to_owned())
            .map_err(|e| JsError::new(&e.to_string()))
    }
    /// Detached writer signature, to persist atomically with the ciphertext.
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.to_vec()
    }
}
/// Seals and signs a storage record using namespace, identity and expected version.
#[wasm_bindgen(js_name = sealSignedStorageRecord)]
#[allow(clippy::too_many_arguments)]
pub fn seal_signed_storage_record_js(
    plaintext: &[u8],
    recipient: &[u8],
    key_id: &[u8],
    namespace: &[u8],
    record_id: &[u8],
    version: u64,
    writer: &WasmIdentityKeyPair,
) -> Result<WasmSignedObject, JsError> {
    let recipient = to_key(recipient).map_err(to_js)?;
    let (ciphertext, signature) = foctet_core::seal_signed_storage_record(
        plaintext,
        recipient,
        key_id,
        foctet_core::StorageRecord::new(namespace, record_id, version),
        &writer.inner,
        &BodyEnvelopeLimits::default(),
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(WasmSignedObject {
        ciphertext,
        signature,
    })
}
/// Verifies a trusted writer and expected storage version before decryption.
#[wasm_bindgen(js_name = openSignedStorageRecord)]
#[allow(clippy::too_many_arguments)]
pub fn open_signed_storage_record_js(
    ciphertext: &[u8],
    signature: &[u8],
    secret: &[u8],
    namespace: &[u8],
    record_id: &[u8],
    version: u64,
    writer: &[u8],
) -> Result<Vec<u8>, JsError> {
    let signature = signature
        .try_into()
        .map_err(|_| JsError::new("expected 64 signature bytes"))?;
    let pin = foctet_core::PeerIdentity::new(
        writer
            .try_into()
            .map_err(|_| JsError::new("expected 32 writer key bytes"))?,
    );
    foctet_core::open_signed_storage_record(
        ciphertext,
        signature,
        to_key(secret).map_err(to_js)?,
        foctet_core::StorageRecord::new(namespace, record_id, version),
        pin,
        &BodyEnvelopeLimits::default(),
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Opens canonical signed TEXT storage with an independently trusted writer and
/// expected record identity/revision. No legacy unsigned fallback is attempted.
#[wasm_bindgen(js_name = openSignedTextStorageRecord)]
pub fn open_signed_text_storage_record_js(
    text: &str,
    secret: &[u8],
    namespace: &[u8],
    record_id: &[u8],
    version: u64,
    writer: &[u8],
) -> Result<Vec<u8>, JsError> {
    let pin = foctet_core::PeerIdentity::new(
        writer
            .try_into()
            .map_err(|_| JsError::new("expected 32 writer key bytes"))?,
    );
    foctet_storage_wire::TextRecord::parse(text, foctet_storage_wire::MAX_TEXT_BYTES)
        .and_then(|record| {
            record.open(
                secret
                    .try_into()
                    .map_err(|_| foctet_storage_wire::Error::Invalid)?,
                foctet_core::StorageRecord::new(namespace, record_id, version),
                pin,
                &BodyEnvelopeLimits::default(),
            )
        })
        .map_err(|e| JsError::new(&e.to_string()))
}
