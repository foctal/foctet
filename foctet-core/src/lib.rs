//! Foctet Core (Draft v0)
//! - Fixed-width frame header encoding
//! - Profile 0x01 crypto primitives
//! - Native handshake key schedule helpers
//! - Replay window enforcement
//! - Runtime-agnostic streaming adapters
//!
//! `foctet-core` is the low-level protocol crate for applications that need to
//! drive Foctet sessions directly. If you already have a split stream transport
//! such as QUIC, WebTransport, WebSocket multiplexing, or another byte-stream
//! abstraction, prefer `foctet-transport` for the recommended handshake and
//! channel builders.
//!
//! # Main Modules
//!
//! - [`body`]: `application/foctet` one-shot encrypted body envelope
//! - [`frame`]: wire frame structures, parser/encoder, framed transport types
//! - [`crypto`]: key schedule and frame AEAD helpers
//! - [`control`]: control message wire payloads
//! - [`session`]: handshake/rekey state machine
//! - [`payload`]: encrypted payload TLV schema
//! - [`io`]: runtime adapters and blocking `SyncIo`
//!
//! # Typical Flow
//!
//! 1. Build/derive [`TrafficKeys`] via handshake/session.
//! 2. Send/receive via [`frame::FoctetFramed`] or [`io::SyncIo`].
//! 3. Use [`Session`] to process control frames and rotate keys.
//! 4. Encode application bytes as TLV (`APPLICATION_DATA`) via [`payload`].
//!
//! # Authentication Guidance
//!
//! - The native handshake is authenticated by default: a default
//!   [`SessionAuthConfig`] fails closed and will reject an unauthenticated peer.
//! - For production use, prefer [`SessionAuthConfig`] with local identity keys,
//!   pinned [`PeerIdentity`] values, and
//!   `SessionAuthConfig::require_peer_authentication(true)`.
//! - If Foctet runs inside an already-authenticated outer channel, you may run
//!   the native handshake without identity signatures by explicitly opting in
//!   with `SessionAuthConfig::unauthenticated_for_testing()` (or
//!   `allow_unauthenticated(true)`); the outer channel then carries the
//!   peer-authentication responsibility.
//! - Sequence numbers and rekey identifiers fail closed on exhaustion; callers
//!   should treat those errors as terminal and establish a fresh session.
//!
//! # Typical Native Handshake
//!
//! ```rust,ignore
//! use foctet_core::{
//!     IdentityKeyPair, PeerIdentity, RekeyThresholds, Session, SessionAuthConfig,
//! };
//!
//! let auth = SessionAuthConfig::new()
//!     .with_local_identity(IdentityKeyPair::generate())
//!     .with_peer_identity(PeerIdentity::new(peer_identity_public_key))
//!     .require_peer_authentication(true);
//!
//! let mut initiator = Session::new_initiator_with_auth(RekeyThresholds::default(), auth);
//! let client_hello = initiator.start_handshake()?;
//! # let _ = client_hello;
//! # Ok::<(), foctet_core::CoreError>(())
//! ```

/// Handshake authentication helpers and identity-key types.
pub mod auth;
/// One-shot body-complete encrypted envelope (`application/foctet`) helpers.
pub mod body;
/// Streaming (chunked) `application/foctet` body with per-chunk AEAD.
pub mod body_stream;
/// Control-plane message types used inside encrypted control frames.
pub mod control;
/// Cryptographic primitives and key-derivation helpers.
pub mod crypto;
/// Datagram-oriented endpoint (one frame per datagram) for UDP/QUIC/WebTransport.
pub mod datagram;
/// Frame wire format, parser/encoder, and framed transport adapters.
pub mod frame;
/// Runtime adapters and blocking I/O wrappers.
pub mod io;
/// Centralized protocol resource limits for the stream-oriented transports.
pub mod limits;
/// Message-oriented endpoint (one frame per discrete message) for raw WebSocket.
pub mod message;
/// TLV payload encoding/decoding helpers for encrypted application bytes.
pub mod payload;
/// Replay-window tracking and duplicate-frame protection.
pub mod replay;
/// High-level blocking facade combining session/rekey and TLV application flow.
pub mod secure_channel;
/// Internal fail-closed outbound sequence allocation shared by all transport shapes.
mod sequence;
/// Session handshake/rekey state and key lifecycle handling.
pub mod session;

pub use auth::{
    AuthenticatedPeer, ChannelBinding, HANDSHAKE_AUTH_ED25519, HANDSHAKE_AUTH_NONE, HandshakeAuth,
    HandshakeSigner, IdentityKeyPair, PeerIdentity, SessionAuthConfig,
};
pub use body::{
    BODY_MAGIC, BODY_PROFILE_V0, BODY_VERSION_V0, BodyEnvelopeError, BodyEnvelopeLimits, open_body,
    open_body_for_key_id, open_body_for_key_id_with_context, open_body_for_key_id_with_limits,
    open_body_with_context, open_body_with_limits, seal_body, seal_body_with_context,
    seal_body_with_limits,
};
pub use body_stream::{
    DecodedChunk, STREAM_CHUNK_OVERHEAD, STREAM_MAGIC, STREAM_NONCE_PREFIX_LEN, STREAM_PROFILE_V0,
    STREAM_VERSION_V0, StreamFrameDecoder, StreamItem, StreamOpener, StreamSealer,
};
pub use control::{ControlMessage, ControlMessageKind};
pub use crypto::{
    Direction, EphemeralKeyPair, KeyHandle, TrafficKeys, decrypt_frame, decrypt_frame_with_key,
    derive_ratchet_root, derive_traffic_keys, dh_ratchet_step, encrypt_frame, make_nonce,
    random_session_salt,
};
pub use datagram::{
    DATAGRAM_FRAME_OVERHEAD, DEFAULT_MAX_DATAGRAM_SIZE, DatagramConfig, DatagramEndpoint,
    DecodedDatagram,
};
pub use frame::{
    DRAFT_MAGIC, FRAME_HEADER_LEN, FoctetFramed, FoctetStream, Frame, FrameHeader,
    PROFILE_X25519_HKDF_XCHACHA20POLY1305, WIRE_VERSION_V0,
};
pub use limits::{DEFAULT_MAX_CIPHERTEXT_LEN, DEFAULT_MAX_RETAINED_KEYS, ProtocolLimits};
pub use message::{
    DEFAULT_MAX_MESSAGE_SIZE, DecodedMessage, MESSAGE_FRAME_OVERHEAD, MessageConfig,
    MessageEndpoint,
};
pub use payload::{Tlv, decode_tlvs, encode_tlvs, tlv_type};
pub use replay::{
    DEFAULT_MAX_REPLAY_WINDOWS, DEFAULT_REPLAY_WINDOW, ReplayProtector, ReplayWindow,
};
pub use secure_channel::{AsyncSecureChannel, SecureChannel};
pub use session::{HandshakeRole, RekeyThresholds, Session, SessionState};

use thiserror::Error;

/// Core protocol error type.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Frame header length is not `FRAME_HEADER_LEN`.
    #[error("invalid frame header length: {0}")]
    InvalidHeaderLength(usize),
    /// Frame magic is invalid.
    #[error("invalid frame magic")]
    InvalidMagic,
    /// Protocol version is unsupported.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    /// Crypto profile is unsupported.
    #[error("unsupported profile: {0}")]
    UnsupportedProfile(u8),
    /// Header flags contain unknown bits.
    #[error("unknown or reserved flags are set: 0x{0:02x}")]
    UnknownFlags(u8),
    /// Header ciphertext length does not match payload length.
    #[error("ciphertext length mismatch: expected {expected}, got {actual}")]
    CiphertextLengthMismatch {
        /// Declared ciphertext length from frame header.
        expected: usize,
        /// Actual ciphertext length found in frame body.
        actual: usize,
    },
    /// AEAD operation failed.
    #[error("aead operation failed")]
    Aead,
    /// HKDF expansion failed.
    #[error("hkdf expand failed")]
    Hkdf,
    /// Symmetric key length is invalid.
    #[error("invalid key length")]
    InvalidKeyLength,
    /// Received key ID does not match expected one.
    #[error("unexpected key id: expected {expected}, got {actual}")]
    UnexpectedKeyId {
        /// Locally expected active key id.
        expected: u8,
        /// Key id found in the incoming frame.
        actual: u8,
    },
    /// Control payload is malformed.
    #[error("invalid control message")]
    InvalidControlMessage,
    /// Control payload is not valid for current protocol state.
    #[error("unexpected control message for current state")]
    UnexpectedControlMessage,
    /// Session operation was called in an invalid state.
    #[error("invalid session state")]
    InvalidSessionState,
    /// A rekey was initiated out of turn (the DH ratchet alternates between
    /// peers; only the side whose turn it is may initiate the next rekey).
    #[error("rekey not permitted: it is the peer's turn to ratchet")]
    RekeyNotPermitted,
    /// Session/shared secret is not available.
    #[error("missing session secret")]
    MissingSessionSecret,
    /// TLV payload is malformed.
    #[error("invalid tlv payload")]
    InvalidTlv,
    /// TLV payload exceeds configured limits.
    #[error("tlv payload too large")]
    TlvTooLarge,
    /// Replay check detected a duplicate frame.
    #[error("replay detected")]
    Replay,
    /// Frame sequence is outside replay window.
    #[error("frame is outside replay window")]
    ReplayWindowExceeded,
    /// Too many distinct `(key_id, stream_id)` replay windows are being tracked.
    #[error("replay window capacity exceeded")]
    ReplayCapacityExceeded,
    /// Frame exceeds configured size limits.
    #[error("frame exceeds configured limit")]
    FrameTooLarge,
    /// Unexpected EOF while reading/writing frame bytes.
    #[error("unexpected eof")]
    UnexpectedEof,
    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// X25519 produced a forbidden all-zero shared secret.
    #[error("invalid shared secret")]
    InvalidSharedSecret,
    /// Outbound sequence space is exhausted and must not wrap.
    #[error("sequence space exhausted")]
    SequenceExhausted,
    /// Rekey key identifier space is exhausted and must not wrap.
    #[error("key id space exhausted")]
    KeyIdExhausted,
    /// Peer authentication was required but not present.
    #[error("missing peer authentication")]
    MissingPeerAuthentication,
    /// Peer authentication failed validation.
    #[error("invalid peer authentication")]
    InvalidPeerAuthentication,
    /// Peer identity did not match the pinned expectation.
    #[error("peer identity mismatch")]
    PeerIdentityMismatch,
    /// The handshake did not complete within the configured deadline.
    #[error("handshake timed out")]
    HandshakeTimeout,
}
