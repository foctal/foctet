/// Common high-level transport defaults applied when constructing secure channels.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportConfig {
    app_stream_id: u32,
    app_flags: u8,
}

impl TransportConfig {
    /// Creates a config with Foctet defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the default application stream ID.
    pub fn app_stream_id(&self) -> u32 {
        self.app_stream_id
    }

    /// Returns the default application frame flags.
    pub fn app_flags(&self) -> u8 {
        self.app_flags
    }

    /// Sets the default application stream ID.
    pub fn with_app_stream_id(mut self, stream_id: u32) -> Self {
        self.app_stream_id = stream_id;
        self
    }

    /// Sets the default plaintext frame flags.
    pub fn with_app_flags(mut self, flags: u8) -> Self {
        self.app_flags = flags;
        self
    }
}
