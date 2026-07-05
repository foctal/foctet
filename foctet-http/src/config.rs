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
/// Holds an ordered, non-empty **keyring** of recipient X25519 secret keys.
/// Opening tries each key in order and succeeds on the first that
/// authenticates, which is what lets a recipient accept both the current and a
/// previous key during a rotation overlap window (see
/// [`HttpOpenOptions::with_recipient_key`]). Each key is stored in a zeroizing
/// wrapper (wiped on drop), is **not** printed by [`Debug`] (which redacts the
/// key material), and is only retrievable through the explicitly named
/// [`HttpOpenOptions::expose_recipient_secret_key`] /
/// [`HttpOpenOptions::expose_recipient_secret_keys`].
#[derive(Clone)]
pub struct HttpOpenOptions {
    // Invariant: always non-empty. Keys are tried in order; index 0 is the
    // primary key returned by `expose_recipient_secret_key`.
    recipient_secret_keys: Vec<Zeroizing<[u8; 32]>>,
    limits: Option<BodyEnvelopeLimits>,
}

impl core::fmt::Debug for HttpOpenOptions {
    /// Redacts the recipient secret keys so they cannot leak into logs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpOpenOptions")
            .field("recipient_secret_keys", &"<redacted>")
            .field("recipient_key_count", &self.recipient_secret_keys.len())
            .field("limits", &self.limits)
            .finish()
    }
}

impl HttpOpenOptions {
    /// Creates opening options for a single recipient secret key.
    pub fn new(recipient_secret_key: [u8; 32]) -> Self {
        Self {
            recipient_secret_keys: vec![Zeroizing::new(recipient_secret_key)],
            limits: None,
        }
    }

    /// Builds opening options from an ordered set of recipient secret keys.
    ///
    /// Keys are tried in iteration order. Returns `None` if the iterator is
    /// empty, since an opener with no key can never authenticate anything.
    pub fn from_recipient_keys(keys: impl IntoIterator<Item = [u8; 32]>) -> Option<Self> {
        let recipient_secret_keys: Vec<Zeroizing<[u8; 32]>> =
            keys.into_iter().map(Zeroizing::new).collect();
        if recipient_secret_keys.is_empty() {
            return None;
        }
        Some(Self {
            recipient_secret_keys,
            limits: None,
        })
    }

    /// Appends an additional recipient secret key to the keyring.
    ///
    /// During a key-rotation overlap window, add the retiring key(s) so the
    /// opener accepts envelopes sealed to either the current or a previous
    /// recipient key. Keys are tried in insertion order, so place the key that
    /// serves the most traffic first. Trial decryption is safe: a non-matching
    /// key fails authentication and, on the context-bound path, is rejected
    /// before the replay store is consulted, so it cannot consume a replay slot.
    #[must_use]
    pub fn with_recipient_key(mut self, recipient_secret_key: [u8; 32]) -> Self {
        self.recipient_secret_keys
            .push(Zeroizing::new(recipient_secret_key));
        self
    }

    /// Applies explicit body envelope limits.
    pub fn with_limits(mut self, limits: BodyEnvelopeLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Exposes a zeroizing copy of the primary (first) recipient secret key.
    ///
    /// Named with an `expose_` prefix so secret extraction is greppable and
    /// obvious at the call site. The returned [`Zeroizing`] wipes its copy on
    /// drop.
    #[must_use]
    pub fn expose_recipient_secret_key(&self) -> Zeroizing<[u8; 32]> {
        self.recipient_secret_keys[0].clone()
    }

    /// Exposes zeroizing copies of every recipient secret key, in try order.
    #[must_use]
    pub fn expose_recipient_secret_keys(&self) -> Vec<Zeroizing<[u8; 32]>> {
        self.recipient_secret_keys.clone()
    }

    /// Returns the number of recipient keys in the keyring (always at least 1).
    pub fn recipient_key_count(&self) -> usize {
        self.recipient_secret_keys.len()
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
        assert_eq!(options.recipient_key_count(), 1);
    }

    #[test]
    fn keyring_tracks_all_keys_in_insertion_order() {
        let options = HttpOpenOptions::new([0x01; 32]).with_recipient_key([0x02; 32]);
        assert_eq!(options.recipient_key_count(), 2);
        // The primary key is the first one; try order is insertion order.
        assert_eq!(*options.expose_recipient_secret_key(), [0x01; 32]);
        let keys = options.expose_recipient_secret_keys();
        assert_eq!(*keys[0], [0x01; 32]);
        assert_eq!(*keys[1], [0x02; 32]);
    }

    #[test]
    fn from_recipient_keys_rejects_empty_keyring() {
        assert!(HttpOpenOptions::from_recipient_keys(Vec::<[u8; 32]>::new()).is_none());
        let options =
            HttpOpenOptions::from_recipient_keys([[0x03; 32], [0x04; 32]]).expect("non-empty");
        assert_eq!(options.recipient_key_count(), 2);
    }

    #[test]
    fn open_options_debug_redacts_every_key_but_shows_count() {
        let options = HttpOpenOptions::new([0x4D; 32]).with_recipient_key([0x5E; 32]);
        let rendered = format!("{options:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("recipient_key_count"));
        for leaked in [
            format!("{:?}", [0x4D_u8; 32]),
            format!("{:?}", [0x5E_u8; 32]),
        ] {
            assert!(
                !rendered.contains(&leaked),
                "a recipient secret leaked into Debug output: {rendered}"
            );
        }
    }
}
