use foctet_core::CoreError;
use thiserror::Error;

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
}
