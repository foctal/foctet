//! Foctet Secure Archive (Draft v0)
//! - Single-file archive creation and decryption
//! - Multi-file split archive (`manifest.far` + `data.partNNN.far`)
//! - Recipient-based DEK key wrapping
//! - Encrypted metadata + encrypted chunk records
//!
//! # Public API
//!
//! - Single-file:
//!   - [`create_archive_from_bytes`]
//!   - [`decrypt_archive_to_bytes`]
//! - Split archive:
//!   - [`create_split_archive_from_bytes`]
//!   - [`decrypt_split_archive_to_bytes`]
//!
//! # Safety Notes
//!
//! - Uses validated-only `rkyv` deserialization (`bytecheck` enabled).
//! - Rejects malformed container structures with explicit parse errors.
//! - Treats archive bytes as untrusted input and enforces [`ArchiveLimits`]
//!   before attacker-controlled allocations.

mod build;
mod codec;
mod crypto;
mod error;
mod limits;
mod single;
mod split;
mod types;

pub use error::ArchiveError;
pub use limits::ArchiveLimits;
pub use single::{
    create_archive_from_bytes, decrypt_archive_to_bytes, decrypt_archive_to_bytes_with_limits,
};
pub use split::{
    create_split_archive_from_bytes, decrypt_split_archive_to_bytes,
    decrypt_split_archive_to_bytes_with_limits,
};
pub use types::{
    ARCHIVE_MAGIC, ArchiveBuildResult, ArchiveOptions, DEFAULT_CHUNK_SIZE, EncryptedHeader,
    FileManifest, MANIFEST_MAGIC, PART_MAGIC, PROFILE_X25519_HKDF_XCHACHA20POLY1305, SplitArchive,
    WIRE_VERSION_V0, WrappedDek,
};

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::crypto::{unwrap_dek_from_recipients, wrap_dek};

    #[test]
    fn wrap_and_unwrap_dek_roundtrip() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);

        let wrapped = wrap_dek(&dek, recipient_pub).expect("wrap");
        let unwrapped =
            unwrap_dek_from_recipients(&[wrapped], recipient_priv.to_bytes()).expect("unwrap");
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn archive_encrypt_decrypt_roundtrip() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let payload = vec![0xAB; 2 * 1024 * 1024 + 17];
        let options = ArchiveOptions {
            chunk_size: 256 * 1024,
            file_name: Some("blob.bin".into()),
            content_type: Some("application/octet-stream".into()),
            created_at_unix: Some(1_700_000_000),
        };

        let (archive, meta) =
            create_archive_from_bytes(&payload, &[recipient_pub], options).expect("create archive");
        assert!(meta.total_chunks > 1);

        let plain =
            decrypt_archive_to_bytes(&archive, recipient_priv.to_bytes()).expect("decrypt archive");
        assert_eq!(plain, payload);
    }

    #[test]
    fn split_archive_roundtrip_with_reordered_parts() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let payload = vec![0xCD; 3 * 1024 * 1024 + 333];
        let options = ArchiveOptions {
            chunk_size: 256 * 1024,
            file_name: Some("blob-split.bin".into()),
            content_type: Some("application/octet-stream".into()),
            created_at_unix: Some(1_700_000_123),
        };

        let split =
            create_split_archive_from_bytes(&payload, &[recipient_pub], options, 500 * 1024)
                .expect("create split archive");
        assert!(split.parts.len() > 1);

        let mut parts_refs = split.parts.iter().map(|p| p.as_slice()).collect::<Vec<_>>();
        parts_refs.reverse();

        let plain =
            decrypt_split_archive_to_bytes(&split.manifest, &parts_refs, recipient_priv.to_bytes())
                .expect("decrypt split archive");
        assert_eq!(plain, payload);
    }
}
