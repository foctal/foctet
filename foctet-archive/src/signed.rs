//! Signed archives verify an independently pinned writer before decrypting.
use crate::*;
use foctet_core::{HandshakeSigner, PeerIdentity, sign_ciphertext, verify_ciphertext};

/// A complete archive and its detached writer signature.
#[derive(Clone, Debug)]
pub struct SignedArchive {
    /// Exact encrypted archive bytes.
    pub ciphertext: Vec<u8>,
    /// Signature over ciphertext and the caller's canonical object context.
    pub signature: [u8; 64],
}
impl SignedArchive {
    /// Creates a randomized, signed archive. Context should include object/version.
    pub fn create(
        plaintext: &[u8],
        recipients: &[[u8; 32]],
        options: ArchiveOptions,
        context: &[u8],
        writer: &dyn HandshakeSigner,
    ) -> Result<Self, ArchiveError> {
        let (ciphertext, _) = create_archive_from_bytes(plaintext, recipients, options)?;
        let signature = sign_ciphertext(&ciphertext, context, writer);
        Ok(Self {
            ciphertext,
            signature,
        })
    }
    /// Verifies the trusted writer before decryption, enforcing resource limits.
    pub fn open(
        &self,
        secret: [u8; 32],
        context: &[u8],
        writer: PeerIdentity,
        limits: &ArchiveLimits,
    ) -> Result<Vec<u8>, ArchiveError> {
        if self.ciphertext.len() > limits.max_archive_bytes {
            return Err(ArchiveError::LimitExceeded("archive_bytes"));
        }
        verify_ciphertext(&self.ciphertext, context, self.signature, writer)
            .map_err(|_| ArchiveError::Aead)?;
        decrypt_archive_to_bytes_with_limits(&self.ciphertext, secret, limits)
    }
}

/// Split archive with a writer signature covering the manifest and its part hashes.
#[derive(Clone, Debug)]
pub struct SignedSplitArchive {
    /// Encrypted manifest and parts.
    pub archive: SplitArchive,
    /// Detached signature covering the manifest and caller context.
    pub signature: [u8; 64],
}
impl SignedSplitArchive {
    /// Creates a signed split archive. File splitting is not threshold sharing.
    pub fn create(
        plaintext: &[u8],
        recipients: &[[u8; 32]],
        options: ArchiveOptions,
        part_size: usize,
        context: &[u8],
        writer: &dyn HandshakeSigner,
    ) -> Result<Self, ArchiveError> {
        let archive = create_split_archive_from_bytes(plaintext, recipients, options, part_size)?;
        let signature = sign_ciphertext(&archive.manifest, context, writer);
        Ok(Self { archive, signature })
    }
    /// Checks writer identity before any part is decrypted.
    pub fn open(
        &self,
        secret: [u8; 32],
        context: &[u8],
        writer: PeerIdentity,
        limits: &ArchiveLimits,
    ) -> Result<Vec<u8>, ArchiveError> {
        if self.archive.manifest.len() > limits.max_manifest_bytes {
            return Err(ArchiveError::LimitExceeded("manifest_bytes"));
        }
        verify_ciphertext(&self.archive.manifest, context, self.signature, writer)
            .map_err(|_| ArchiveError::Aead)?;
        if self.archive.parts.len() > limits.total_parts() {
            return Err(ArchiveError::LimitExceeded("total_parts"));
        }
        let parts: Vec<_> = self.archive.parts.iter().map(Vec::as_slice).collect();
        decrypt_split_archive_to_bytes_with_limits(&self.archive.manifest, &parts, secret, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archive_wrappers_require_expected_writer_and_context() {
        let secret = x25519_dalek::StaticSecret::from([1; 32]);
        let recipient = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let writer = foctet_core::IdentityKeyPair::from_secret_key_bytes([2; 32]);
        let pin = PeerIdentity::new(writer.public_key());
        let wrong = PeerIdentity::new(
            foctet_core::IdentityKeyPair::from_secret_key_bytes([3; 32]).public_key(),
        );
        let limits = ArchiveLimits::default();
        let mut archive = SignedArchive::create(
            b"signed",
            &[recipient],
            ArchiveOptions::default(),
            b"object/1",
            &writer,
        )
        .unwrap();
        assert_eq!(
            archive
                .open(secret.to_bytes(), b"object/1", pin, &limits)
                .unwrap(),
            b"signed"
        );
        assert!(
            archive
                .open(secret.to_bytes(), b"object/2", pin, &limits)
                .is_err()
        );
        assert!(
            archive
                .open(secret.to_bytes(), b"object/1", wrong, &limits)
                .is_err()
        );
        archive.ciphertext[0] ^= 1;
        assert!(
            archive
                .open(secret.to_bytes(), b"object/1", pin, &limits)
                .is_err()
        );
        let split = SignedSplitArchive::create(
            b"signed",
            &[recipient],
            ArchiveOptions::default(),
            64 * 1024,
            b"object/1",
            &writer,
        )
        .unwrap();
        assert_eq!(
            split
                .open(secret.to_bytes(), b"object/1", pin, &limits)
                .unwrap(),
            b"signed"
        );
        assert!(
            split
                .open(secret.to_bytes(), b"object/2", pin, &limits)
                .is_err()
        );
        let bounded = ArchiveLimits {
            max_total_parts: 0,
            ..limits
        };
        assert!(
            split
                .open(secret.to_bytes(), b"object/1", pin, &bounded)
                .is_err()
        );
    }
}
