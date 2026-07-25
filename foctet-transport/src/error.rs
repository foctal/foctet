use foctet_core::{CoreError, CoreErrorDisposition};
use thiserror::Error;

/// Required action after a transport-layer channel error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorDisposition {
    /// The operation was rejected before an ambiguous transport outcome.
    Recoverable,
    /// Discard the transport/session and establish a fresh authenticated
    /// channel; delivery or protocol state may be ambiguous.
    Terminal,
}

/// Error returned by transport-specific secure-channel helpers.
#[derive(Debug, Error)]
pub enum TransportChannelError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// The underlying transport failed while opening or accepting a stream.
    #[error("transport error: {0}")]
    Transport(E),
    /// Foctet channel construction failed.
    #[error(transparent)]
    Core(#[from] CoreError),
}

impl<E> TransportChannelError<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Wraps a transport-layer error.
    pub fn transport(error: E) -> Self {
        Self::Transport(error)
    }

    /// Wraps a Foctet core error.
    pub fn core(error: CoreError) -> Self {
        Self::Core(error)
    }

    /// Classifies whether the channel may safely continue after this error.
    pub const fn disposition(&self) -> TransportErrorDisposition {
        match self {
            Self::Transport(_) => TransportErrorDisposition::Terminal,
            Self::Core(error) => match error.disposition() {
                CoreErrorDisposition::Recoverable => TransportErrorDisposition::Recoverable,
                CoreErrorDisposition::Terminal => TransportErrorDisposition::Terminal,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TransportChannelError, TransportErrorDisposition};
    use foctet_core::CoreError;

    #[test]
    fn propagates_core_error_disposition() {
        let recoverable =
            TransportChannelError::<std::io::Error>::core(CoreError::OutboundBufferLimitExceeded);
        assert_eq!(
            recoverable.disposition(),
            TransportErrorDisposition::Recoverable
        );
    }
}
