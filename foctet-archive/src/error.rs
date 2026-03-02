use thiserror::Error;

/// Error type for Foctet archive encode/decode operations.
#[derive(Debug, Error)]
pub enum ArchiveError {
    /// Container magic prefix does not match the expected format.
    #[error("invalid archive magic")]
    InvalidMagic,
    /// Archive wire version is not supported by this implementation.
    #[error("unsupported archive version: {0}")]
    UnsupportedVersion(u8),
    /// Archive crypto/profile identifier is not supported.
    #[error("unsupported profile: {0}")]
    UnsupportedProfile(u8),
    /// Container bytes are malformed or truncated.
    #[error("archive parsing failed")]
    Parse,
    /// Serialization of archive metadata failed.
    #[error("serialization error")]
    Serialize,
    /// Deserialization of archive metadata failed.
    #[error("deserialization error")]
    Deserialize,
    /// HKDF expansion failed.
    #[error("hkdf expand failed")]
    Hkdf,
    /// AEAD encryption/decryption failed.
    #[error("aead operation failed")]
    Aead,
    /// No recipient key wrapper matched the provided recipient key.
    #[error("missing recipient key wrapper")]
    MissingRecipient,
    /// Reconstructed plaintext hash does not match manifest hash.
    #[error("overall hash mismatch")]
    OverallHashMismatch,
    /// A required split part is missing.
    #[error("missing part: {0}")]
    MissingPart(u32),
    /// Duplicate split part number was provided.
    #[error("duplicate part: {0}")]
    DuplicatePart(u32),
    /// A split part hash did not match the manifest entry.
    #[error("part hash mismatch")]
    PartHashMismatch,
    /// Caller-provided input parameters are invalid.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
}
