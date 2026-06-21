use foctet_core::BodyEnvelopeLimits;
use zeroize::Zeroizing;

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
///
/// Holds the recipient X25519 secret key. The key is stored in a zeroizing
/// wrapper (wiped on drop), is **not** printed by [`Debug`] (which redacts it),
/// and is only retrievable through the explicitly named
/// [`HttpOpenOptions::expose_recipient_secret_key`].
#[derive(Clone)]
pub struct HttpOpenOptions {
    recipient_secret_key: Zeroizing<[u8; 32]>,
    limits: Option<BodyEnvelopeLimits>,
}

impl core::fmt::Debug for HttpOpenOptions {
    /// Redacts the recipient secret key so it cannot leak into logs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpOpenOptions")
            .field("recipient_secret_key", &"<redacted>")
            .field("limits", &self.limits)
            .finish()
    }
}

impl HttpOpenOptions {
    /// Creates opening options for a recipient secret key.
    pub fn new(recipient_secret_key: [u8; 32]) -> Self {
        Self {
            recipient_secret_key: Zeroizing::new(recipient_secret_key),
            limits: None,
        }
    }

    /// Applies explicit body envelope limits.
    pub fn with_limits(mut self, limits: BodyEnvelopeLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Exposes a zeroizing copy of the recipient secret key.
    ///
    /// Named with an `expose_` prefix so secret extraction is greppable and
    /// obvious at the call site. The returned [`Zeroizing`] wipes its copy on
    /// drop.
    #[must_use]
    pub fn expose_recipient_secret_key(&self) -> Zeroizing<[u8; 32]> {
        self.recipient_secret_key.clone()
    }

    /// Returns explicit opening limits, if configured.
    pub fn limits(&self) -> Option<&BodyEnvelopeLimits> {
        self.limits.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_options_debug_redacts_secret_key() {
        let options = HttpOpenOptions::new([0x4D; 32]);
        let rendered = format!("{options:?}");
        assert!(rendered.contains("<redacted>"));
        let leaked = format!("{:?}", [0x4D_u8; 32]);
        assert!(
            !rendered.contains(&leaked),
            "recipient secret leaked into Debug output: {rendered}"
        );
    }

    #[test]
    fn open_options_expose_round_trips() {
        let secret = [0x7E; 32];
        let options = HttpOpenOptions::new(secret);
        assert_eq!(*options.expose_recipient_secret_key(), secret);
    }
}
