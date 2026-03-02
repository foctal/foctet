//! Foctet Core (Draft v0)
//! - Fixed-width frame header encoding
//! - Profile 0x01 crypto primitives
//! - Native handshake key schedule helpers
//! - Replay window enforcement
//! - Runtime-agnostic streaming adapters
//!
//! # Main Modules
//!
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

/// Control-plane message types used inside encrypted control frames.
pub mod control;
/// Cryptographic primitives and key-derivation helpers.
pub mod crypto;
/// Frame wire format, parser/encoder, and framed transport adapters.
pub mod frame;
/// Runtime adapters and blocking I/O wrappers.
pub mod io;
/// TLV payload encoding/decoding helpers for encrypted application bytes.
pub mod payload;
/// Replay-window tracking and duplicate-frame protection.
pub mod replay;
/// High-level blocking facade combining session/rekey and TLV application flow.
pub mod secure_channel;
/// Session handshake/rekey state and key lifecycle handling.
pub mod session;

pub use control::{ControlMessage, ControlMessageKind};
pub use crypto::{
    Direction, EphemeralKeyPair, TrafficKeys, decrypt_frame, decrypt_frame_with_key,
    derive_rekey_traffic_keys, derive_traffic_keys, encrypt_frame, make_nonce, random_session_salt,
};
pub use frame::{
    DRAFT_MAGIC, FRAME_HEADER_LEN, FoctetFramed, FoctetStream, Frame, FrameHeader,
    PROFILE_X25519_HKDF_XCHACHA20POLY1305, WIRE_VERSION_V0,
};
pub use payload::{Tlv, decode_tlvs, encode_tlvs, tlv_type};
pub use replay::{DEFAULT_REPLAY_WINDOW, ReplayProtector, ReplayWindow};
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
    /// Frame exceeds configured size limits.
    #[error("frame exceeds configured limit")]
    FrameTooLarge,
    /// Unexpected EOF while reading/writing frame bytes.
    #[error("unexpected eof")]
    UnexpectedEof,
    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
