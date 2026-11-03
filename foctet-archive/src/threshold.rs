//! Authenticated k-of-n recovery of an archive's randomly generated recipient key.
//!
//! Shamir arithmetic is provided by vsss-rs, not implemented here. Keep shares
//! with independent custodians, encrypted in transit and at rest. The expected
//! set and writer pin must be trusted; old valid sets remain valid without an
//! independent rollback checkpoint. Recovery exposes a key at the endpoint.
use crate::*;
use foctet_core::{HandshakeSigner, PeerIdentity, sign_ciphertext, verify_ciphertext};
use getrandom::SysRng;
use rand_core::{TryRng, UnwrapErr};
use vsss_rs::Gf256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"FOCTETSS";
const DOMAIN: &[u8] = b"foctet recovery share v1";
/// Serialized share length, including the signed recovery descriptor.
pub const SHARE_BYTES: usize = 187;

/// Public recovery descriptor. Persist a trusted copy independently of shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverySet {
    /// Random set identifier, renewed on every creation.
    pub id: [u8; 16],
    /// Required number of distinct shares (at least two).
    pub threshold: u8,
    /// Total number of issued shares.
    pub total: u8,
    /// Recovered key's X25519 public key, used to verify reconstruction.
    pub recipient: [u8; 32],
    /// Digest of the exact encrypted archive.
    pub archive_hash: [u8; 32],
}
impl RecoverySet {
    fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend(self.id);
        out.push(self.threshold);
        out.push(self.total);
        out.extend(self.recipient);
        out.extend(self.archive_hash);
        out
    }
    fn validate(&self) -> Result<(), ArchiveError> {
        if self.threshold < 2 || self.threshold > self.total {
            return Err(ArchiveError::InvalidInput("invalid recovery threshold"));
        }
        Ok(())
    }
}

/// Sensitive, signed recovery share. Debug intentionally omits share material.
pub struct RecoveryShare {
    set: RecoverySet,
    value: Zeroizing<Vec<u8>>,
    signature: [u8; 64],
}
impl core::fmt::Debug for RecoveryShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryShare")
            .field("set", &self.set)
            .field("value", &"<redacted>")
            .finish()
    }
}
impl RecoveryShare {
    /// Returns the public descriptor. Parsing alone does not authenticate it.
    pub fn recovery_set(&self) -> &RecoverySet {
        &self.set
    }
    /// Exports sensitive share bytes. Encrypt separately for each custodian.
    pub fn expose_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Reserve the complete encoding before copying any secret material:
        // Zeroizing wipes on drop, but cannot wipe buffers retired by realloc.
        let mut out = Zeroizing::new(Vec::with_capacity(SHARE_BYTES));
        out.extend_from_slice(&self.set.encode());
        out.extend_from_slice(&self.value);
        out.extend(self.signature);
        out
    }
    /// Parses a bounded share. Authentication occurs during recovery.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArchiveError> {
        if bytes.len() != SHARE_BYTES || &bytes[..8] != MAGIC {
            return Err(ArchiveError::Parse);
        }
        let set = RecoverySet {
            id: bytes[8..24].try_into().map_err(|_| ArchiveError::Parse)?,
            threshold: bytes[24],
            total: bytes[25],
            recipient: bytes[26..58].try_into().map_err(|_| ArchiveError::Parse)?,
            archive_hash: bytes[58..90].try_into().map_err(|_| ArchiveError::Parse)?,
        };
        set.validate()?;
        Ok(Self {
            set,
            value: Zeroizing::new(bytes[90..123].to_vec()),
            signature: bytes[123..].try_into().map_err(|_| ArchiveError::Parse)?,
        })
    }
}

/// Creates an encrypted archive and independently signed recovery shares.
/// To rotate or revoke shares, recover and create a new archive/set; old copies
/// cannot be cryptographically revoked from holders of the old threshold.
pub fn create_threshold_archive(
    plaintext: &[u8],
    options: ArchiveOptions,
    threshold: u8,
    total: u8,
    writer: &dyn HandshakeSigner,
) -> Result<(Vec<u8>, RecoverySet, Vec<RecoveryShare>), ArchiveError> {
    if threshold < 2 || threshold > total {
        return Err(ArchiveError::InvalidInput("invalid recovery threshold"));
    }
    let secret = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
    let recipient = PublicKey::from(&secret).to_bytes();
    let (archive, _) = create_archive_from_bytes(plaintext, &[recipient], options)?;
    let mut id = [0; 16];
    SysRng
        .try_fill_bytes(&mut id)
        .map_err(|_| ArchiveError::InvalidInput("random source failed"))?;
    let set = RecoverySet {
        id,
        threshold,
        total,
        recipient,
        archive_hash: *blake3::hash(&archive).as_bytes(),
    };
    let secret_bytes = Zeroizing::new(secret.to_bytes());
    let values = Gf256::split_bytes(
        threshold as usize,
        total as usize,
        &secret_bytes[..],
        UnwrapErr(SysRng),
    )
    .map_err(|_| ArchiveError::InvalidInput("secret sharing failed"))?;
    let shares = values
        .into_iter()
        .map(|value| {
            let value = Zeroizing::new(value);
            let mut signed = Zeroizing::new(set.encode());
            signed.extend_from_slice(&value);
            let signature = sign_ciphertext(&signed, DOMAIN, writer);
            RecoveryShare {
                set: set.clone(),
                value,
                signature,
            }
        })
        .collect();
    Ok((archive, set, shares))
}

/// Verifies every supplied share and the archive before reconstructing and opening.
/// Duplicate, mixed, insufficient or forged shares fail closed; no subset search
/// silently ignores corrupted inputs. Retry with a separately selected valid set.
pub fn recover_threshold_archive(
    archive: &[u8],
    expected: &RecoverySet,
    shares: &[RecoveryShare],
    writer: PeerIdentity,
    limits: &ArchiveLimits,
) -> Result<Vec<u8>, ArchiveError> {
    expected.validate()?;
    if archive.len() > limits.max_archive_bytes {
        return Err(ArchiveError::LimitExceeded("archive_bytes"));
    }
    if shares.len() < expected.threshold as usize || shares.len() > expected.total as usize {
        return Err(ArchiveError::InvalidInput("invalid share count"));
    }
    if blake3::hash(archive).as_bytes() != &expected.archive_hash {
        return Err(ArchiveError::Aead);
    }
    let mut seen = [false; 256];
    let mut values = Zeroizing::new(Vec::with_capacity(shares.len()));
    for share in shares {
        if share.set != *expected || share.value.len() != 33 {
            return Err(ArchiveError::Parse);
        }
        let index = share.value[0] as usize;
        if index == 0 || index > expected.total as usize || seen[index] {
            return Err(ArchiveError::InvalidInput("duplicate or invalid share"));
        }
        seen[index] = true;
        let mut signed = Zeroizing::new(expected.encode());
        signed.extend_from_slice(&share.value);
        verify_ciphertext(&signed, DOMAIN, share.signature, writer)
            .map_err(|_| ArchiveError::Aead)?;
        values.push(share.value.to_vec());
    }
    let recovered =
        Zeroizing::new(Gf256::combine_bytes(&values[..]).map_err(|_| ArchiveError::Aead)?);
    let mut key: [u8; 32] = recovered
        .as_slice()
        .try_into()
        .map_err(|_| ArchiveError::Aead)?;
    let secret = StaticSecret::from(key);
    key.zeroize();
    if PublicKey::from(&secret).to_bytes() != expected.recipient {
        return Err(ArchiveError::Aead);
    }
    decrypt_archive_to_bytes_with_limits(archive, secret.to_bytes(), limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn threshold_boundaries_all_three_of_five_subsets_and_wrong_writer() {
        let writer = foctet_core::IdentityKeyPair::from_secret_key_bytes([11; 32]);
        let pin = PeerIdentity::new(writer.public_key());
        for (k, n) in [(0, 3), (1, 3), (4, 3), (255, 254)] {
            assert!(
                create_threshold_archive(b"x", ArchiveOptions::default(), k, n, &writer).is_err()
            );
        }
        let (archive, set, shares) =
            create_threshold_archive(b"threshold", ArchiveOptions::default(), 3, 5, &writer)
                .unwrap();
        let limits = ArchiveLimits::default();
        for a in 0..3 {
            for b in a + 1..4 {
                for c in b + 1..5 {
                    let selected: Vec<_> = [a, b, c]
                        .into_iter()
                        .map(|i| RecoveryShare::from_bytes(&shares[i].expose_bytes()).unwrap())
                        .collect();
                    assert_eq!(
                        recover_threshold_archive(&archive, &set, &selected, pin, &limits).unwrap(),
                        b"threshold"
                    );
                }
            }
        }
        assert_eq!(
            recover_threshold_archive(&archive, &set, &shares, pin, &limits).unwrap(),
            b"threshold"
        );
        let wrong = PeerIdentity::new(
            foctet_core::IdentityKeyPair::from_secret_key_bytes([12; 32]).public_key(),
        );
        assert!(recover_threshold_archive(&archive, &set, &shares, wrong, &limits).is_err());
        for share in &shares {
            let bytes = share.expose_bytes();
            assert_eq!(bytes.len(), SHARE_BYTES);
            assert_eq!(bytes.capacity(), SHARE_BYTES);
        }
        let (archive, set, shares) =
            create_threshold_archive(b"max", ArchiveOptions::default(), 255, 255, &writer).unwrap();
        assert_eq!(
            recover_threshold_archive(&archive, &set, &shares, pin, &limits).unwrap(),
            b"max"
        );
    }
    #[test]
    fn every_threshold_subset_recovers_and_corruption_fails() {
        let writer = foctet_core::IdentityKeyPair::from_secret_key_bytes([42; 32]);
        let pin = PeerIdentity::new(writer.public_key());
        let (archive, set, shares) =
            create_threshold_archive(b"recovery", ArchiveOptions::default(), 2, 3, &writer)
                .unwrap();
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            let selected = [
                RecoveryShare::from_bytes(&shares[a].expose_bytes()).unwrap(),
                RecoveryShare::from_bytes(&shares[b].expose_bytes()).unwrap(),
            ];
            assert_eq!(
                recover_threshold_archive(
                    &archive,
                    &set,
                    &selected,
                    pin,
                    &ArchiveLimits::default()
                )
                .unwrap(),
                b"recovery"
            );
        }
        assert!(
            recover_threshold_archive(&archive, &set, &shares[..1], pin, &ArchiveLimits::default())
                .is_err()
        );
        let duplicate = [
            RecoveryShare::from_bytes(&shares[0].expose_bytes()).unwrap(),
            RecoveryShare::from_bytes(&shares[0].expose_bytes()).unwrap(),
        ];
        assert!(
            recover_threshold_archive(&archive, &set, &duplicate, pin, &ArchiveLimits::default())
                .is_err()
        );
        let mut bytes = shares[0].expose_bytes();
        bytes[95] ^= 1;
        let corrupt = [
            RecoveryShare::from_bytes(&bytes).unwrap(),
            RecoveryShare::from_bytes(&shares[1].expose_bytes()).unwrap(),
        ];
        assert!(
            recover_threshold_archive(&archive, &set, &corrupt, pin, &ArchiveLimits::default())
                .is_err()
        );
        let (_, other, _) =
            create_threshold_archive(b"recovery", ArchiveOptions::default(), 2, 3, &writer)
                .unwrap();
        assert!(
            recover_threshold_archive(&archive, &other, &shares, pin, &ArchiveLimits::default())
                .is_err()
        );
    }
}
