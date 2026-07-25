use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::SysRng;
use rand_core::UnwrapErr;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::CoreError;

/// Signs native handshake transcripts with a long-term Ed25519 identity.
///
/// This is the seam for **hardware-backed or otherwise non-extractable** identity
/// keys: implement it for an HSM, a cloud KMS, a TPM, or an OS keystore so the
/// Ed25519 private key never enters process memory. The software
/// [`IdentityKeyPair`] implements it for the common case.
///
/// The contract is deliberately narrow — expose the public key and produce a
/// detached Ed25519 signature over `message` — so a signer is never asked to
/// reveal private key bytes. `Send + Sync` is required so a configured
/// [`Session`](crate::Session) stays usable across threads and async tasks.
pub trait HandshakeSigner: Send + Sync {
    /// Returns the Ed25519 public identity key (the verifying key).
    fn public_key(&self) -> [u8; 32];

    /// Produces a detached Ed25519 signature over `message`.
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

/// Authentication mode discriminator for native handshake messages.
pub const HANDSHAKE_AUTH_NONE: u8 = 0;
/// Ed25519-based transcript authentication for native handshake messages.
pub const HANDSHAKE_AUTH_ED25519: u8 = 1;

/// Local long-term identity key pair used to sign handshake transcripts.
#[derive(Clone)]
pub struct IdentityKeyPair {
    secret_key: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
}

impl core::fmt::Debug for IdentityKeyPair {
    /// Prints only the public key; the secret scalar is never formatted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl PartialEq for IdentityKeyPair {
    /// Compares identity key pairs in constant time over the secret scalar.
    fn eq(&self, other: &Self) -> bool {
        let secret_eq = self.secret_key.ct_eq(other.secret_key.as_ref());
        let public_eq = self.public_key.ct_eq(&other.public_key);
        (secret_eq & public_eq).into()
    }
}

impl Eq for IdentityKeyPair {}

impl IdentityKeyPair {
    /// Generates a fresh Ed25519 identity key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut UnwrapErr(SysRng));
        Self::from_secret_key_bytes(signing_key.to_bytes())
    }

    /// Builds an identity key pair from Ed25519 secret-key bytes.
    pub fn from_secret_key_bytes(secret_key: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret_key);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            secret_key: Zeroizing::new(secret_key),
            public_key,
        }
    }

    /// Returns the Ed25519 public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Exposes a zeroizing copy of the Ed25519 secret key bytes.
    ///
    /// This is a deliberate, auditable extraction of long-term secret material
    /// (for persistence or serialization). The returned [`Zeroizing`] wrapper
    /// wipes its copy on drop, but callers are responsible for not spreading
    /// further unprotected copies. Named with an `expose_` prefix so secret
    /// extraction is greppable and obvious at the call site.
    #[must_use]
    pub fn expose_secret_key_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.secret_key.clone()
    }

    /// Signs handshake transcript bytes.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signing_key = SigningKey::from_bytes(&self.secret_key);
        signing_key.sign(message).to_bytes()
    }
}

impl HandshakeSigner for IdentityKeyPair {
    fn public_key(&self) -> [u8; 32] {
        IdentityKeyPair::public_key(self)
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        IdentityKeyPair::sign(self, message)
    }
}

/// An outer-channel binding value mixed into the Foctet handshake transcript.
///
/// When both peers configure the *same* binding (for example a TLS exporter
/// value per RFC 5705, a TLS channel id, or any other value that is unique to
/// the authenticated outer channel), it is folded into the handshake transcript
/// hash. A man-in-the-middle that terminates the outer channel and relays the
/// Foctet handshake necessarily has a *different* binding value, so the two
/// sides compute different transcripts and the handshake fails closed — even
/// when no Foctet Ed25519 identity is used. This lets an authenticated outer
/// channel substitute for Foctet identity authentication.
///
/// The binding is **not** secret; it is authenticated context, not key
/// material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelBinding(Vec<u8>);

/// Maximum outer-channel binding length accepted by a session.
pub const MAX_CHANNEL_BINDING_LEN: usize = 1024;

impl ChannelBinding {
    /// Creates a channel binding from the outer channel's binding bytes.
    ///
    /// Empty bindings are rejected because they provide no authentication, and
    /// oversized bindings are rejected before copying or hashing them.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, CoreError> {
        let bytes = bytes.as_ref();
        if bytes.is_empty() {
            return Err(CoreError::InvalidChannelBinding);
        }
        if bytes.len() > MAX_CHANNEL_BINDING_LEN {
            return Err(CoreError::ChannelBindingTooLarge);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the binding bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Peer identity pin used to verify remote handshake authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    /// Expected Ed25519 public key bytes for the remote peer.
    pub public_key: [u8; 32],
}

impl PeerIdentity {
    /// Creates a pinned peer identity from public-key bytes.
    pub fn new(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }
}

/// A peer whose Ed25519 identity was proven during the handshake.
///
/// Obtained from [`crate::Session::authenticated_peer`] after a successful
/// handshake in which the remote side presented a valid identity signature (and,
/// when a [`PeerIdentity`] was pinned, matched it). It is the typed counterpart
/// to the [`crate::Session::peer_authenticated`] boolean: it additionally tells
/// you *which* identity authenticated. A handshake whose man-in-the-middle
/// resistance comes only from a [`ChannelBinding`] (no Foctet identity) yields
/// `None`, because no peer *identity* was proven.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeer {
    identity_public_key: [u8; 32],
}

impl AuthenticatedPeer {
    /// Creates an authenticated-peer record from a verified identity key.
    pub fn new(identity_public_key: [u8; 32]) -> Self {
        Self {
            identity_public_key,
        }
    }

    /// Returns the verified Ed25519 identity public key of the peer.
    pub fn identity_public_key(&self) -> [u8; 32] {
        self.identity_public_key
    }

    /// Returns whether this peer matches the given pinned [`PeerIdentity`].
    pub fn matches(&self, identity: &PeerIdentity) -> bool {
        self.identity_public_key.ct_eq(&identity.public_key).into()
    }
}

/// Authentication payload attached to a handshake control message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeAuth {
    /// Claimed Ed25519 identity public key.
    pub identity_public_key: [u8; 32],
    /// Ed25519 signature over the transcript message.
    pub signature: [u8; 64],
}

impl HandshakeAuth {
    /// Creates an authentication payload from a local signer and transcript message.
    ///
    /// Accepts any [`HandshakeSigner`] (the software [`IdentityKeyPair`] coerces
    /// automatically), so hardware-backed identities work without exposing key
    /// bytes.
    pub fn sign(signer: &dyn HandshakeSigner, message: &[u8]) -> Self {
        Self {
            identity_public_key: signer.public_key(),
            signature: signer.sign(message),
        }
    }

    /// Verifies the authentication payload against the transcript message.
    pub fn verify(&self, message: &[u8]) -> Result<(), CoreError> {
        let verifying_key = VerifyingKey::from_bytes(&self.identity_public_key)
            .map_err(|_| CoreError::InvalidPeerAuthentication)?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(message, &signature)
            .map_err(|_| CoreError::InvalidPeerAuthentication)
    }

    /// Returns encoded byte length without the auth-mode discriminator.
    pub const fn encoded_len() -> usize {
        32 + 64
    }
}

/// Session-level handshake authentication configuration.
///
/// # Safe by default
///
/// A default ([`SessionAuthConfig::new`]) configuration **fails closed**: the
/// native handshake will not complete unless the peer presents a valid
/// authenticated handshake. To run an intentionally unauthenticated handshake —
/// for example inside an already-authenticated outer channel such as mutually
/// authenticated TLS, or in tests — you must explicitly opt in with
/// [`SessionAuthConfig::unauthenticated_for_testing`] (or
/// [`SessionAuthConfig::dangerously_allow_unauthenticated`]). This makes the active
/// man-in-the-middle exposure of an unauthenticated ephemeral handshake an
/// explicit, auditable choice rather than a silent default.
#[derive(Clone, Default)]
pub struct SessionAuthConfig {
    local_signer: Option<Arc<dyn HandshakeSigner>>,
    peer_identity: Option<PeerIdentity>,
    require_peer_authentication: bool,
    allow_unauthenticated: bool,
    channel_binding: Option<ChannelBinding>,
}

/// Authentication configuration accepted by production handshake constructors.
///
/// This type can only be built with a pinned Foctet identity or a non-empty,
/// bounded authenticated-channel binding. The explicitly unauthenticated test
/// configuration cannot be converted into this type.
///
/// ```compile_fail
/// use foctet_core::{ProductionSessionAuth, SessionAuthConfig};
///
/// let test_only = SessionAuthConfig::unauthenticated_for_testing();
/// let production: ProductionSessionAuth = test_only.into();
/// # let _ = production;
/// ```
#[derive(Clone, Debug)]
pub struct ProductionSessionAuth(SessionAuthConfig);

impl ProductionSessionAuth {
    /// Requires mutual Foctet identity authentication with an in-process key.
    pub fn pinned_identity(local: IdentityKeyPair, peer: PeerIdentity) -> Self {
        Self(
            SessionAuthConfig::new()
                .with_local_identity(local)
                .with_peer_identity(peer)
                .require_peer_authentication(true),
        )
    }

    /// Requires mutual Foctet identity authentication with an external signer.
    pub fn pinned_signer<S: HandshakeSigner + 'static>(local: S, peer: PeerIdentity) -> Self {
        Self(
            SessionAuthConfig::new()
                .with_local_signer(local)
                .with_peer_identity(peer)
                .require_peer_authentication(true),
        )
    }

    /// Authenticates the handshake through a trusted outer-channel binding.
    pub fn authenticated_channel(binding: ChannelBinding) -> Self {
        Self(SessionAuthConfig::bound_to_channel(binding))
    }

    /// Additionally binds an identity-authenticated handshake to an outer channel.
    #[must_use]
    pub fn with_channel_binding(mut self, binding: ChannelBinding) -> Self {
        self.0 = self.0.with_channel_binding(binding);
        self
    }

    /// Converts into the lower-level session authentication configuration.
    pub fn into_session_auth(self) -> SessionAuthConfig {
        self.0
    }
}

impl core::fmt::Debug for SessionAuthConfig {
    /// Shows the local signer only by its public key (never secret material) and
    /// omits the trait object's internals.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionAuthConfig")
            .field(
                "local_signer_public_key",
                &self.local_signer.as_ref().map(|signer| signer.public_key()),
            )
            .field("peer_identity", &self.peer_identity)
            .field(
                "require_peer_authentication",
                &self.require_peer_authentication,
            )
            .field("allow_unauthenticated", &self.allow_unauthenticated)
            .field("channel_binding", &self.channel_binding)
            .finish()
    }
}

impl SessionAuthConfig {
    /// Creates an empty, fail-closed authentication configuration.
    ///
    /// Without a pinned [`PeerIdentity`] or an explicit
    /// [`SessionAuthConfig::dangerously_allow_unauthenticated`] opt-in, the handshake will
    /// reject a peer that does not authenticate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration that explicitly permits an unauthenticated
    /// handshake.
    ///
    /// Only use this when peer authentication is guaranteed by an outer channel
    /// (e.g. mutually authenticated TLS) or in tests. An unauthenticated Foctet
    /// handshake on an untrusted transport is vulnerable to an active
    /// man-in-the-middle.
    pub fn unauthenticated_for_testing() -> Self {
        Self {
            allow_unauthenticated: true,
            ..Self::default()
        }
    }

    /// Creates a configuration whose man-in-the-middle resistance comes from an
    /// authenticated outer channel rather than a Foctet Ed25519 identity.
    ///
    /// The `binding` (e.g. a TLS exporter value) is folded into the handshake
    /// transcript on both sides, so a relay across a different outer channel
    /// fails closed. This is the typed, production-oriented alternative to
    /// [`SessionAuthConfig::unauthenticated_for_testing`]: there is no Foctet
    /// identity, but the handshake is bound to a channel you already trust.
    pub fn bound_to_channel(binding: ChannelBinding) -> Self {
        Self {
            allow_unauthenticated: true,
            channel_binding: Some(binding),
            ..Self::default()
        }
    }

    /// Attaches a software local identity used to sign native handshake messages.
    ///
    /// Convenience over [`SessionAuthConfig::with_local_signer`] for the common
    /// in-process [`IdentityKeyPair`] case.
    pub fn with_local_identity(mut self, identity: IdentityKeyPair) -> Self {
        self.local_signer = Some(Arc::new(identity));
        self
    }

    /// Attaches a local [`HandshakeSigner`] used to sign native handshake
    /// messages.
    ///
    /// Use this for hardware-backed or otherwise non-extractable identity keys
    /// (HSM, cloud KMS, TPM, OS keystore): the private key never enters process
    /// memory. For an in-process key, prefer
    /// [`SessionAuthConfig::with_local_identity`].
    pub fn with_local_signer<S: HandshakeSigner + 'static>(mut self, signer: S) -> Self {
        self.local_signer = Some(Arc::new(signer));
        self
    }

    /// Binds the handshake transcript to an outer-channel [`ChannelBinding`].
    ///
    /// Additive to any identity configuration: both peers must supply the same
    /// binding or the handshake fails.
    pub fn with_channel_binding(mut self, binding: ChannelBinding) -> Self {
        self.channel_binding = Some(binding);
        self
    }

    /// Pins the expected remote identity public key.
    pub fn with_peer_identity(mut self, identity: PeerIdentity) -> Self {
        self.peer_identity = Some(identity);
        self
    }

    /// Requires the remote side to present a valid authenticated handshake.
    pub fn require_peer_authentication(mut self, require: bool) -> Self {
        self.require_peer_authentication = require;
        self
    }

    /// Explicitly permits (or forbids) completing an unauthenticated handshake.
    ///
    /// See [`SessionAuthConfig::unauthenticated_for_testing`] for the safety
    /// implications. This is ignored when peer authentication is required or a
    /// peer identity is pinned (those always demand authentication).
    pub fn dangerously_allow_unauthenticated(mut self, allow: bool) -> Self {
        self.allow_unauthenticated = allow;
        self
    }

    /// Returns whether an unauthenticated handshake is explicitly permitted.
    pub fn allows_unauthenticated(&self) -> bool {
        self.allow_unauthenticated
    }

    /// Returns the configured local handshake signer, if any.
    pub fn local_signer(&self) -> Option<&dyn HandshakeSigner> {
        self.local_signer.as_deref()
    }

    /// Returns the local identity public key, if a local signer is configured.
    pub fn local_identity_public_key(&self) -> Option<[u8; 32]> {
        self.local_signer.as_ref().map(|signer| signer.public_key())
    }

    /// Returns the pinned peer identity, if configured.
    pub fn peer_identity(&self) -> Option<PeerIdentity> {
        self.peer_identity
    }

    /// Returns whether remote handshake authentication is mandatory.
    pub fn requires_peer_authentication(&self) -> bool {
        self.require_peer_authentication
    }

    /// Returns the configured outer-channel binding bytes, or an empty slice
    /// when none is set.
    pub fn channel_binding_bytes(&self) -> &[u8] {
        match &self.channel_binding {
            Some(binding) => binding.as_bytes(),
            None => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_debug_redacts_secret_key() {
        let identity = IdentityKeyPair::from_secret_key_bytes([0x37; 32]);
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("<redacted>"));
        // The secret scalar's array form must never appear.
        let leaked = format!("{:?}", [0x37_u8; 32]);
        assert!(
            !rendered.contains(&leaked),
            "secret key leaked into Debug output: {rendered}"
        );
    }

    #[test]
    fn identity_equality_is_value_based() {
        let a = IdentityKeyPair::from_secret_key_bytes([0x11; 32]);
        let b = IdentityKeyPair::from_secret_key_bytes([0x11; 32]);
        let c = IdentityKeyPair::from_secret_key_bytes([0x22; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn expose_secret_key_bytes_round_trips() {
        let secret = [0x9C; 32];
        let identity = IdentityKeyPair::from_secret_key_bytes(secret);
        let exposed = identity.expose_secret_key_bytes();
        assert_eq!(*exposed, secret);
        // Rebuilding from the exposed bytes yields the same identity.
        assert_eq!(IdentityKeyPair::from_secret_key_bytes(*exposed), identity);
    }

    #[test]
    fn channel_binding_rejects_empty_and_oversized_inputs_before_copying() {
        assert!(matches!(
            ChannelBinding::new([]),
            Err(CoreError::InvalidChannelBinding)
        ));
        let oversized = [0xA5; MAX_CHANNEL_BINDING_LEN + 1];
        assert!(matches!(
            ChannelBinding::new(oversized),
            Err(CoreError::ChannelBindingTooLarge)
        ));
        let maximum = [0x5A; MAX_CHANNEL_BINDING_LEN];
        assert_eq!(
            ChannelBinding::new(maximum)
                .expect("maximum channel binding")
                .as_bytes(),
            maximum
        );
    }
}
