use foctet_core::BodyEnvelopeError;
use thiserror::Error;

/// Required caller action after an HTTP protection error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpErrorDisposition {
    /// Reject the current request/response without retrying its protected
    /// payload. A new request requires a new message ID and fresh context.
    Reject,
    /// The request was not cryptographically accepted; retry is possible only
    /// according to application idempotency and replay-store policy.
    Retryable,
}

/// Error type for HTTP integration over `foctet-core` body envelopes.
#[derive(Debug, Error)]
pub enum HttpError {
    /// A configured HTTP resource limit was exceeded.
    #[error("HTTP resource limit exceeded: {0}")]
    LimitExceeded(&'static str),
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
    /// A protected-context header occurred more than once.
    #[error("duplicate protected-context value: {0}")]
    DuplicateContext(&'static str),
    /// A protected response does not answer the initiating request.
    #[error("protected response does not answer the initiating request")]
    ResponseRequestMismatch,
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

impl HttpError {
    /// Classifies the required handling of this stateless HTTP operation.
    pub const fn disposition(&self) -> HttpErrorDisposition {
        match self {
            Self::ReplayStore(_) => HttpErrorDisposition::Retryable,
            Self::LimitExceeded(_)
            | Self::MissingContentType
            | Self::InvalidContentType
            | Self::SealFailed(_)
            | Self::OpenFailed(_)
            | Self::MissingContext(_)
            | Self::InvalidContext(_)
            | Self::DuplicateContext(_)
            | Self::ResponseRequestMismatch
            | Self::ContextTimestampInFuture
            | Self::ContextExpired
            | Self::Replayed
            | Self::StreamIncomplete => HttpErrorDisposition::Reject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpError, HttpErrorDisposition};

    #[test]
    fn classifies_expired_context_as_rejected() {
        assert_eq!(
            HttpError::ContextExpired.disposition(),
            HttpErrorDisposition::Reject
        );
    }
}
