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
    /// A required `x-foctet-*` protected-context header is missing.
    #[error("missing protected-context value: {0}")]
    MissingContext(&'static str),
    /// A protected-context value is malformed.
    #[error("invalid protected-context value: {0}")]
    InvalidContext(&'static str),
    /// The protected-context timestamp is too far in the future.
    #[error("protected-context timestamp is in the future")]
    ContextTimestampInFuture,
    /// The protected-context has expired.
    #[error("protected-context has expired")]
    ContextExpired,
    /// The message was already seen: a replay.
    #[error("replayed request rejected")]
    Replayed,
    /// The anti-replay store failed.
    #[error("replay store error")]
    ReplayStore(#[source] crate::ReplayStoreError),
    /// A streaming body ended before its authenticated final chunk (truncated or
    /// cancelled); the partial plaintext must be discarded.
    #[error("streaming body incomplete (no final chunk)")]
    StreamIncomplete,
}
