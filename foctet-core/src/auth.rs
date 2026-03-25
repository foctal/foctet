use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::CoreError;

/// Authentication mode discriminator for native handshake messages.
pub const HANDSHAKE_AUTH_NONE: u8 = 0;
/// Ed25519-based transcript authentication for native handshake messages.
pub const HANDSHAKE_AUTH_ED25519: u8 = 1;

/// Local long-term identity key pair used to sign handshake transcripts.
#[derive(Clone, Eq, PartialEq)]
pub struct IdentityKeyPair {
    secret_key: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
}

impl core::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl IdentityKeyPair {
    /// Generates a fresh Ed25519 identity key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
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

    /// Returns the Ed25519 secret key bytes.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        *self.secret_key
    }

    /// Signs handshake transcript bytes.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signing_key = SigningKey::from_bytes(&self.secret_key);
        signing_key.sign(message).to_bytes()
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

/// Authentication payload attached to a handshake control message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeAuth {
    /// Claimed Ed25519 identity public key.
    pub identity_public_key: [u8; 32],
    /// Ed25519 signature over the transcript message.
    pub signature: [u8; 64],
}

impl HandshakeAuth {
    /// Creates an authentication payload from a local identity and transcript message.
    pub fn sign(identity: &IdentityKeyPair, message: &[u8]) -> Self {
        Self {
            identity_public_key: identity.public_key(),
            signature: identity.sign(message),
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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionAuthConfig {
    local_identity: Option<IdentityKeyPair>,
    peer_identity: Option<PeerIdentity>,
    require_peer_authentication: bool,
}

impl SessionAuthConfig {
    /// Creates an empty authentication configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches a local identity used to sign native handshake messages.
    pub fn with_local_identity(mut self, identity: IdentityKeyPair) -> Self {
        self.local_identity = Some(identity);
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

    /// Returns the local identity, if configured.
    pub fn local_identity(&self) -> Option<&IdentityKeyPair> {
        self.local_identity.as_ref()
    }

    /// Returns the pinned peer identity, if configured.
    pub fn peer_identity(&self) -> Option<PeerIdentity> {
        self.peer_identity
    }

    /// Returns whether remote handshake authentication is mandatory.
    pub fn requires_peer_authentication(&self) -> bool {
        self.require_peer_authentication
    }
}
