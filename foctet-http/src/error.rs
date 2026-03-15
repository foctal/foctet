use foctet_core::BodyEnvelopeError;
use thiserror::Error;

/// Error type for HTTP integration over `foctet-core` body envelopes.
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
