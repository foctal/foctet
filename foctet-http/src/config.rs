use foctet_core::BodyEnvelopeLimits;

/// Shared HTTP behavior configuration for high-level opener/sealer helpers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpConfig {
    strip_content_type_on_open: bool,
    set_scope_header_on_seal: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            strip_content_type_on_open: true,
            set_scope_header_on_seal: true,
        }
    }
}

impl HttpConfig {
    /// Creates a config with default HTTP behavior.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether `Content-Type` is removed after opening.
    pub fn strip_content_type_on_open(&self) -> bool {
        self.strip_content_type_on_open
    }

    /// Returns whether the advisory Foctet scope header is added when sealing.
    pub fn set_scope_header_on_seal(&self) -> bool {
        self.set_scope_header_on_seal
    }

    /// Controls whether `Content-Type` is removed after opening.
    pub fn with_strip_content_type_on_open(mut self, value: bool) -> Self {
        self.strip_content_type_on_open = value;
        self
    }

    /// Controls whether sealed HTTP messages receive the advisory Foctet scope header.
    pub fn with_scope_header_on_seal(mut self, value: bool) -> Self {
        self.set_scope_header_on_seal = value;
        self
    }
}

/// High-level options used to construct an [`crate::HttpSealer`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpSealOptions {
    recipient_public_key: [u8; 32],
    recipient_key_id: Vec<u8>,
    limits: Option<BodyEnvelopeLimits>,
}

impl HttpSealOptions {
    /// Creates sealing options for a recipient public key and key identifier.
    pub fn new(recipient_public_key: [u8; 32], recipient_key_id: impl AsRef<[u8]>) -> Self {
        Self {
            recipient_public_key,
            recipient_key_id: recipient_key_id.as_ref().to_vec(),
            limits: None,
        }
    }

    /// Applies explicit body envelope limits.
    pub fn with_limits(mut self, limits: BodyEnvelopeLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Returns the recipient public key.
    pub fn recipient_public_key(&self) -> [u8; 32] {
        self.recipient_public_key
    }

    /// Returns the recipient key identifier.
    pub fn recipient_key_id(&self) -> &[u8] {
        &self.recipient_key_id
    }

    /// Returns explicit sealing limits, if configured.
    pub fn limits(&self) -> Option<&BodyEnvelopeLimits> {
        self.limits.as_ref()
    }
}

/// High-level options used to construct an [`crate::HttpOpener`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpOpenOptions {
    recipient_secret_key: [u8; 32],
    limits: Option<BodyEnvelopeLimits>,
}

impl HttpOpenOptions {
    /// Creates opening options for a recipient secret key.
    pub fn new(recipient_secret_key: [u8; 32]) -> Self {
        Self {
            recipient_secret_key,
            limits: None,
        }
    }

    /// Applies explicit body envelope limits.
    pub fn with_limits(mut self, limits: BodyEnvelopeLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Returns the recipient secret key.
    pub fn recipient_secret_key(&self) -> [u8; 32] {
        self.recipient_secret_key
    }

    /// Returns explicit opening limits, if configured.
    pub fn limits(&self) -> Option<&BodyEnvelopeLimits> {
        self.limits.as_ref()
    }
}
