/// Defensive parser and decode limits for untrusted archive input.
///
/// These limits are enforced before large allocations and while validating
/// declared lengths/counts from container bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    /// Maximum accepted single-file archive input size in bytes.
    pub max_archive_bytes: usize,
    /// Maximum accepted split-manifest input size in bytes.
    pub max_manifest_bytes: usize,
    /// Maximum accepted split-part file size in bytes.
    pub max_part_bytes: usize,
    /// Maximum recipient wrapper entries in one container.
    pub max_wrapped_recipients: usize,
    /// Maximum wrapped DEK ciphertext size for one recipient.
    pub max_wrapped_ciphertext_len: usize,
    /// Maximum encrypted header ciphertext size.
    pub max_header_ciphertext_len: usize,
    /// Maximum encrypted chunk ciphertext size.
    pub max_chunk_ciphertext_len: usize,
    /// Maximum chunk records in a file.
    pub max_total_chunks: usize,
    /// Maximum part entries in a split manifest.
    pub max_total_parts: usize,
    /// Maximum chunk records in one part file.
    pub max_part_chunks: usize,
    /// Maximum plaintext bytes produced by decrypt-to-bytes APIs.
    pub max_total_output_bytes: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 768 * 1024 * 1024,
            max_manifest_bytes: 32 * 1024 * 1024,
            max_part_bytes: 256 * 1024 * 1024,
            max_wrapped_recipients: 1024,
            max_wrapped_ciphertext_len: 4096,
            max_header_ciphertext_len: 4 * 1024 * 1024,
            max_chunk_ciphertext_len: 16 * 1024 * 1024,
            max_total_chunks: 65_536,
            max_total_parts: 65_536,
            max_part_chunks: 65_536,
            max_total_output_bytes: 512 * 1024 * 1024,
        }
    }
}
