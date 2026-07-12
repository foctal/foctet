#![cfg_attr(docsrs, feature(doc_cfg))]
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
//!   - [`create_archive_from_bytes_with_secrets`]
//!   - [`decrypt_archive_to_bytes`]
//! - Split archive:
//!   - [`create_split_archive_from_bytes`]
//!   - [`create_split_archive_from_bytes_with_secrets`]
//!   - [`decrypt_split_archive_to_bytes`]
//!
//! # Safety Notes
//!
//! - Uses validated-only `rkyv` deserialization (`bytecheck` enabled).
//! - Rejects malformed container structures with explicit parse errors.
//! - Treats archive bytes as untrusted input and enforces [`ArchiveLimits`]
//!   before attacker-controlled allocations.
//! - [`ArchiveBuildSecrets`] exists for reproducible vectors and deterministic
//!   tests only. Production archive creation should keep the default randomized
//!   builders so archive identifiers, DEKs, and wrapping ephemeral keys remain
//!   unique per build.

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
    create_archive_from_bytes, create_archive_from_bytes_with_secrets, decrypt_archive_to_bytes,
    decrypt_archive_to_bytes_with_limits,
};
pub use split::{
    create_split_archive_from_bytes, create_split_archive_from_bytes_with_secrets,
    decrypt_split_archive_to_bytes, decrypt_split_archive_to_bytes_with_limits,
};
pub use types::{
    ARCHIVE_MAGIC, ArchiveBuildResult, ArchiveBuildSecrets, ArchiveOptions, DEFAULT_CHUNK_SIZE,
    EncryptedHeader, FileManifest, MANIFEST_MAGIC, PART_MAGIC,
    PROFILE_X25519_HKDF_XCHACHA20POLY1305, SplitArchive, WIRE_VERSION_V0, WrappedDek,
};

#[cfg(test)]
mod tests {
    use getrandom::SysRng;
    use rand_core::{TryRng, UnwrapErr};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::crypto::{unwrap_dek_from_recipients, wrap_dek};

    #[test]
    fn wrap_and_unwrap_dek_roundtrip() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let mut dek = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut dek)
            .expect("OS random number generator is unavailable");

        let wrapped = wrap_dek(&dek, recipient_pub).expect("wrap");
        let unwrapped =
            unwrap_dek_from_recipients(&[wrapped], recipient_priv.to_bytes()).expect("unwrap");
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn wrapping_rejects_low_order_recipient_public_keys() {
        let dek = [0xA5; 32];
        for recipient_public in [[0u8; 32], {
            let mut low_order = [0u8; 32];
            low_order[0] = 1;
            low_order
        }] {
            assert!(matches!(
                wrap_dek(&dek, recipient_public),
                Err(ArchiveError::InvalidRecipientKey)
            ));
        }
    }

    #[test]
    fn archive_encrypt_decrypt_roundtrip() {
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
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
        let recipient_priv = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
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

    #[test]
    fn deterministic_archive_builds_are_reproducible() {
        let recipient_priv = StaticSecret::from([0x77; 32]);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();
        let payload: Vec<u8> = (0..(96 * 1024 + 19)).map(|i| (i % 251) as u8).collect();
        let options = ArchiveOptions {
            chunk_size: 32 * 1024,
            file_name: Some("fixture.bin".into()),
            content_type: Some("application/octet-stream".into()),
            created_at_unix: Some(1_700_123_456),
        };
        let secrets = ArchiveBuildSecrets {
            archive_id: [0x91; 16],
            file_id: [0x92; 16],
            dek: [0x93; 32],
            wrap_ephemeral_secret_keys: vec![[0x94; 32]],
        };

        let (archive_a, meta_a) = create_archive_from_bytes_with_secrets(
            &payload,
            &[recipient_pub],
            options.clone(),
            &secrets,
        )
        .expect("create single archive a");
        let (archive_b, meta_b) = create_archive_from_bytes_with_secrets(
            &payload,
            &[recipient_pub],
            options.clone(),
            &secrets,
        )
        .expect("create single archive b");
        assert_eq!(archive_a, archive_b);
        assert_eq!(meta_a.archive_id, secrets.archive_id);
        assert_eq!(meta_a.file_id, secrets.file_id);
        assert_eq!(meta_a.archive_id, meta_b.archive_id);
        assert_eq!(meta_a.file_id, meta_b.file_id);

        let split_a = create_split_archive_from_bytes_with_secrets(
            &payload,
            &[recipient_pub],
            options.clone(),
            40 * 1024,
            &secrets,
        )
        .expect("create split archive a");
        let split_b = create_split_archive_from_bytes_with_secrets(
            &payload,
            &[recipient_pub],
            options,
            40 * 1024,
            &secrets,
        )
        .expect("create split archive b");
        assert_eq!(split_a.manifest, split_b.manifest);
        assert_eq!(split_a.parts, split_b.parts);
        assert_eq!(split_a.meta.archive_id, secrets.archive_id);
        assert_eq!(split_a.meta.file_id, secrets.file_id);
        assert_eq!(split_a.meta.archive_id, split_b.meta.archive_id);
        assert_eq!(split_a.meta.file_id, split_b.meta.file_id);
    }

    #[test]
    fn deterministic_archive_builds_reject_mismatched_wrapping_secret_count() {
        let recipient_priv = StaticSecret::from([0x55; 32]);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();
        let payload = b"foctet archive fixture";
        let options = ArchiveOptions::default();
        let secrets = ArchiveBuildSecrets {
            archive_id: [0x11; 16],
            file_id: [0x22; 16],
            dek: [0x33; 32],
            wrap_ephemeral_secret_keys: Vec::new(),
        };

        let err =
            create_archive_from_bytes_with_secrets(payload, &[recipient_pub], options, &secrets)
                .expect_err("mismatched wrapping secret count must fail");
        assert!(matches!(
            err,
            ArchiveError::InvalidBuildSecrets(
                "wrap_ephemeral_secret_keys length must match recipient count"
            )
        ));
    }
}
