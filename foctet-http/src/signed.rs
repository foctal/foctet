//! Pinned writer authentication for complete HTTP bodies.
//!
//! Signatures cover exact ciphertext and the canonical protected HTTP context.
//! Configure both the sender and receiver. Pins must come from a trusted source.

use crate::HttpError;
use foctet_core::{HandshakeSigner, PeerIdentity, sign_ciphertext, verify_ciphertext};
use http::{HeaderMap, HeaderValue};
use std::sync::Arc;

/// Detached writer signature header, encoded as 128 lowercase hexadecimal bytes.
pub const WRITER_SIGNATURE_HEADER: &str = "x-foctet-writer-signature";

#[derive(Clone)]
pub(crate) struct Writer(pub Arc<dyn HandshakeSigner>);
impl core::fmt::Debug for Writer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Writer").field(&self.0.public_key()).finish()
    }
}

pub(crate) fn sign(headers: &mut HeaderMap, bytes: &[u8], context: &[u8], writer: &Writer) {
    use std::fmt::Write;
    let mut hex = String::with_capacity(128);
    for byte in sign_ciphertext(bytes, context, writer.0.as_ref()) {
        write!(hex, "{byte:02x}").expect("string write");
    }
    headers.insert(
        WRITER_SIGNATURE_HEADER,
        HeaderValue::from_str(&hex).expect("hex header"),
    );
}

pub(crate) fn verify(
    headers: &HeaderMap,
    bytes: &[u8],
    context: &[u8],
    pin: PeerIdentity,
) -> Result<(), HttpError> {
    let mut values = headers.get_all(WRITER_SIGNATURE_HEADER).iter();
    let hex = values
        .next()
        .ok_or(HttpError::MissingContext(WRITER_SIGNATURE_HEADER))?
        .as_bytes();
    if values.next().is_some() || hex.len() != 128 {
        return Err(HttpError::InvalidContext(WRITER_SIGNATURE_HEADER));
    }
    let digit = |b| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut signature = [0; 64];
    for (out, pair) in signature.iter_mut().zip(hex.as_chunks::<2>().0) {
        *out = digit(pair[0])
            .zip(digit(pair[1]))
            .map(|(a, b)| a * 16 + b)
            .ok_or(HttpError::InvalidContext(WRITER_SIGNATURE_HEADER))?;
    }
    verify_ciphertext(bytes, context, signature, pin)
        .map_err(|_| HttpError::OpenFailed(foctet_core::BodyEnvelopeError::DecryptFailed))
}
