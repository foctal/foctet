use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

pub use foctet_core::{PROFILE_X25519_HKDF_XCHACHA20POLY1305, WIRE_VERSION_V0};

/// Magic bytes for single-file archive containers.
pub const ARCHIVE_MAGIC: [u8; 8] = *b"FOCTETAR";
/// Magic bytes for split-archive manifest files (`manifest.far`).
pub const MANIFEST_MAGIC: [u8; 8] = *b"FOCTETMF";
/// Magic bytes for split-archive part files (`data.partNNN.far`).
pub const PART_MAGIC: [u8; 8] = *b"FOCTETPT";
/// Default plaintext chunk size used during archive build.
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Options controlling archive metadata and chunking behavior.
#[derive(Clone, Debug, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct ArchiveOptions {
    /// Target plaintext chunk size in bytes.
    pub chunk_size: usize,
    /// Optional file name stored in encrypted metadata.
    pub file_name: Option<String>,
    /// Optional content type stored in encrypted metadata.
    pub content_type: Option<String>,
    /// Optional creation timestamp (Unix seconds) stored in encrypted metadata.
    pub created_at_unix: Option<u64>,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            file_name: None,
            content_type: None,
            created_at_unix: None,
        }
    }
}

/// Recipient-specific wrapped copy of the archive data-encryption key (DEK).
#[derive(Clone, Debug, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct WrappedDek {
    /// Recipient public key bytes.
    pub recipient_public: [u8; 32],
    /// Ephemeral sender public key used for ECDH wrapping.
    pub ephemeral_public: [u8; 32],
    /// Nonce used to encrypt the wrapped DEK.
    pub nonce: [u8; 24],
    /// Encrypted DEK bytes.
    pub ciphertext: Vec<u8>,
}

/// Per-file manifest metadata embedded in the encrypted header.
#[derive(Clone, Debug, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct FileManifest {
    /// Random file identifier.
    pub file_id: [u8; 16],
    /// Optional original file name.
    pub file_name: Option<String>,
    /// Original plaintext size in bytes.
    pub file_size: u64,
    /// Plaintext chunk size used for segmentation.
    pub chunk_size: u32,
    /// Total number of chunks in the archive.
    pub total_chunks: u32,
    /// BLAKE3 hash of full plaintext contents.
    pub overall_hash: [u8; 32],
}

/// Encrypted header payload stored in archive containers.
#[derive(Clone, Debug, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct EncryptedHeader {
    /// Random archive identifier shared by manifest and part files.
    pub archive_id: [u8; 16],
    /// Optional creation timestamp (Unix seconds).
    pub created_at_unix: Option<u64>,
    /// Optional content type of archived data.
    pub content_type: Option<String>,
    /// File-level manifest metadata.
    pub manifest: FileManifest,
}

#[derive(Clone, Debug, Archive, RkyvSerialize, RkyvDeserialize)]
pub(crate) struct ChunkPlain {
    pub(crate) chunk_index: u32,
    pub(crate) plain_len: u32,
    pub(crate) payload_hash: [u8; 32],
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct EncryptedChunkRecord {
    pub(crate) chunk_index: u32,
    pub(crate) chunk_ct: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct ManifestPartEntry {
    pub(crate) part_no: u32,
    pub(crate) first_chunk_index: u32,
    pub(crate) chunk_count: u32,
    pub(crate) part_hash: [u8; 32],
}

/// Build metadata returned by archive creation functions.
#[derive(Clone, Debug)]
pub struct ArchiveBuildResult {
    /// Random archive identifier.
    pub archive_id: [u8; 16],
    /// Random file identifier.
    pub file_id: [u8; 16],
    /// Plaintext size in bytes.
    pub file_size: u64,
    /// Total number of encrypted chunks.
    pub total_chunks: u32,
}

/// Output of split-archive creation.
#[derive(Clone, Debug)]
pub struct SplitArchive {
    /// Serialized manifest file bytes (`manifest.far`).
    pub manifest: Vec<u8>,
    /// Serialized part file bytes in part-number order.
    pub parts: Vec<Vec<u8>>,
    /// Build metadata for the generated archive.
    pub meta: ArchiveBuildResult,
}

pub(crate) struct BuiltArchive {
    pub(crate) wrapped: Vec<WrappedDek>,
    pub(crate) header_plain: Vec<u8>,
    pub(crate) chunks: Vec<EncryptedChunkRecord>,
    pub(crate) dek: [u8; 32],
    pub(crate) meta: ArchiveBuildResult,
}

pub(crate) struct ParsedPart {
    pub(crate) archive_id: [u8; 16],
    pub(crate) part_no: u32,
    pub(crate) first_chunk_index: u32,
    pub(crate) chunk_count: u32,
    pub(crate) chunk_ciphertexts: Vec<Vec<u8>>,
}
