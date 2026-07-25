/// Hard maximum recipient wrappers accepted or produced by one archive.
pub const MAX_ARCHIVE_RECIPIENTS: usize = 1024;
/// Hard maximum chunk records accepted or produced by one archive.
pub const MAX_ARCHIVE_CHUNKS: usize = 65_536;
/// Hard maximum split parts accepted or produced by one archive.
pub const MAX_ARCHIVE_PARTS: usize = 65_536;
/// Hard maximum chunk records accepted in one split part.
pub const MAX_ARCHIVE_PART_CHUNKS: usize = 65_536;

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
            max_wrapped_recipients: MAX_ARCHIVE_RECIPIENTS,
            max_wrapped_ciphertext_len: 4096,
            max_header_ciphertext_len: 4 * 1024 * 1024,
            max_chunk_ciphertext_len: 16 * 1024 * 1024,
            max_total_chunks: MAX_ARCHIVE_CHUNKS,
            max_total_parts: MAX_ARCHIVE_PARTS,
            max_part_chunks: MAX_ARCHIVE_PART_CHUNKS,
            max_total_output_bytes: 512 * 1024 * 1024,
        }
    }
}

impl ArchiveLimits {
    pub(crate) fn wrapped_recipients(&self) -> usize {
        self.max_wrapped_recipients.min(MAX_ARCHIVE_RECIPIENTS)
    }

    pub(crate) fn total_chunks(&self) -> usize {
        self.max_total_chunks.min(MAX_ARCHIVE_CHUNKS)
    }

    pub(crate) fn total_parts(&self) -> usize {
        self.max_total_parts.min(MAX_ARCHIVE_PARTS)
    }

    pub(crate) fn part_chunks(&self) -> usize {
        self.max_part_chunks.min(MAX_ARCHIVE_PART_CHUNKS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_counts_cannot_raise_hard_allocation_limits() {
        let limits = ArchiveLimits {
            max_wrapped_recipients: usize::MAX,
            max_total_chunks: usize::MAX,
            max_total_parts: usize::MAX,
            max_part_chunks: usize::MAX,
            ..ArchiveLimits::default()
        };
        assert_eq!(limits.wrapped_recipients(), MAX_ARCHIVE_RECIPIENTS);
        assert_eq!(limits.total_chunks(), MAX_ARCHIVE_CHUNKS);
        assert_eq!(limits.total_parts(), MAX_ARCHIVE_PARTS);
        assert_eq!(limits.part_chunks(), MAX_ARCHIVE_PART_CHUNKS);
    }
}
