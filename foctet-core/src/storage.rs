//! At-rest storage envelopes with record-identity binding.
//!
//! [`seal_storage_record`] / [`open_storage_record`] wrap the body envelope
//! ([`crate::body`]) and bind a record's identity — namespace, record id, and a
//! monotonic version — into the payload AEAD. A storage backend (Cloudflare KV,
//! D1, Durable Object storage, an object store, …) therefore only ever holds
//! opaque ciphertext it cannot read, and it cannot undetectably:
//!
//! - **substitute** one record's ciphertext for another (the namespace / record
//!   id in the reader's descriptor would not match), or
//! - **roll back** a record to a stale ciphertext (the bound version would not
//!   match the version the reader expects).
//!
//! The binding is authenticated but not secret: the descriptor bytes are folded
//! into the AEAD associated data and are **not** stored in the envelope, so the
//! reader must supply a byte-identical [`StorageRecord`] to open it. This is a
//! confidentiality building block — only the client holds a key; the
//! server stores and returns bytes.
//!
//! This API does not authenticate writers: anyone with the recipient public key
//! can create a new valid envelope. Use [`crate::sign_ciphertext`] and verify the
//! detached signature against a pinned writer before opening untrusted storage.
//!
//! Rollback protection is only as strong as the reader's knowledge of the
//! current version: bind the version the caller *expects* (tracked client-side
//! or via an authenticated version pointer), so serving an older ciphertext
//! fails to open.

use crate::body::{
    BodyEnvelopeError, BodyEnvelopeLimits, open_body_with_context, seal_body_with_context,
};

/// Domain-separation tag so a storage-record AAD can never collide with another
/// context-bound envelope (for example an HTTP protected context).
const STORAGE_RECORD_AAD_DOMAIN: &[u8] = b"foctet-storage-record-v1";

/// Identity of a stored record, bound into the envelope AEAD.
///
/// An envelope opens only with the *same* descriptor used to seal it, so the
/// fields pin which record and which version a ciphertext belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageRecord<'a> {
    /// Logical collection the record lives in (for example `b"vault-items"`).
    /// Separates records that share an id across different collections.
    pub namespace: &'a [u8],
    /// Stable identifier of the record within `namespace`.
    pub record_id: &'a [u8],
    /// Monotonic version of the record. Bind the version the caller expects so a
    /// backend cannot serve a stale ciphertext without detection.
    pub version: u64,
}

impl<'a> StorageRecord<'a> {
    /// Creates a record descriptor.
    pub fn new(namespace: &'a [u8], record_id: &'a [u8], version: u64) -> Self {
        Self {
            namespace,
            record_id,
            version,
        }
    }

    /// Encodes the descriptor into canonical, unambiguous AAD bytes: a domain
    /// tag, then each variable-length field length-prefixed, then the
    /// fixed-width version. Length-prefixing prevents a `(namespace, record_id)`
    /// pair from colliding with a different split of the same concatenated bytes.
    fn to_aad(self, limits: &BodyEnvelopeLimits) -> Result<Vec<u8>, BodyEnvelopeError> {
        let length = STORAGE_RECORD_AAD_DOMAIN
            .len()
            .checked_add(24)
            .and_then(|n| n.checked_add(self.namespace.len()))
            .and_then(|n| n.checked_add(self.record_id.len()))
            .filter(|&n| n <= limits.max_context_len)
            .ok_or(BodyEnvelopeError::LimitExceeded("context_len"))?;
        let mut aad = Vec::with_capacity(length);
        aad.extend_from_slice(STORAGE_RECORD_AAD_DOMAIN);
        aad.extend_from_slice(&(self.namespace.len() as u64).to_be_bytes());
        aad.extend_from_slice(self.namespace);
        aad.extend_from_slice(&(self.record_id.len() as u64).to_be_bytes());
        aad.extend_from_slice(self.record_id);
        aad.extend_from_slice(&self.version.to_be_bytes());
        Ok(aad)
    }
}

/// Seals `plaintext` for at-rest storage, binding `record` into the AEAD.
///
/// `recipient_public_key` is the key the data is encrypted to — the caller's own
/// key for a personal vault, or a peer's key for a one-to-one share. The
/// resulting bytes are opaque and safe to hand to an untrusted store; only a
/// holder of the matching secret key **and** the same [`StorageRecord`] can open
/// them.
pub fn seal_storage_record(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
    record: StorageRecord<'_>,
) -> Result<Vec<u8>, BodyEnvelopeError> {
    seal_storage_record_with_limits(
        plaintext,
        recipient_public_key,
        recipient_key_id,
        record,
        &BodyEnvelopeLimits::default(),
    )
}

/// [`seal_storage_record`] with explicit parser/encoder limits.
pub fn seal_storage_record_with_limits(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
    record: StorageRecord<'_>,
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, BodyEnvelopeError> {
    seal_body_with_context(
        plaintext,
        recipient_public_key,
        recipient_key_id,
        &record.to_aad(limits)?,
        limits,
    )
}

/// Opens a storage envelope, requiring the same [`StorageRecord`] it was sealed
/// with.
///
/// Fails with [`BodyEnvelopeError::DecryptFailed`] if the descriptor does not
/// match — for example when the store returned a different record's ciphertext
/// (substitution) or a stale version (rollback).
pub fn open_storage_record(
    envelope: &[u8],
    recipient_secret_key: [u8; 32],
    record: StorageRecord<'_>,
) -> Result<Vec<u8>, BodyEnvelopeError> {
    open_storage_record_with_limits(
        envelope,
        recipient_secret_key,
        record,
        &BodyEnvelopeLimits::default(),
    )
}

/// [`open_storage_record`] with explicit parser limits.
pub fn open_storage_record_with_limits(
    envelope: &[u8],
    recipient_secret_key: [u8; 32],
    record: StorageRecord<'_>,
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, BodyEnvelopeError> {
    open_body_with_context(
        envelope,
        recipient_secret_key,
        &record.to_aad(limits)?,
        limits,
    )
}

/// Seals a record and authenticates its writer with a detached signature.
///
/// Persist both returned values. Verify with [`open_signed_storage_record`],
/// using an externally pinned writer and expected record version.
pub fn seal_signed_storage_record(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
    record: StorageRecord<'_>,
    writer: &dyn crate::HandshakeSigner,
    limits: &BodyEnvelopeLimits,
) -> Result<(Vec<u8>, [u8; 64]), BodyEnvelopeError> {
    let aad = record.to_aad(limits)?;
    let ciphertext = seal_body_with_context(
        plaintext,
        recipient_public_key,
        recipient_key_id,
        &aad,
        limits,
    )?;
    let signature = crate::sign_ciphertext(&ciphertext, &aad, writer);
    Ok((ciphertext, signature))
}

/// Verifies the pinned writer before opening a stored record.
///
/// A writer key received from the untrusted store is not a valid trust anchor.
/// The expected version must also come from a trusted checkpoint to detect rollback.
pub fn open_signed_storage_record(
    envelope: &[u8],
    signature: [u8; 64],
    recipient_secret_key: [u8; 32],
    record: StorageRecord<'_>,
    writer: crate::PeerIdentity,
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, BodyEnvelopeError> {
    let aad = record.to_aad(limits)?;
    let max_envelope = limits
        .max_header_bytes
        .saturating_add(limits.max_payload_len);
    if envelope.len() > max_envelope {
        return Err(BodyEnvelopeError::LimitExceeded("envelope_len"));
    }
    crate::verify_ciphertext(envelope, &aad, signature, writer)
        .map_err(|_| BodyEnvelopeError::DecryptFailed)?;
    open_body_with_context(envelope, recipient_secret_key, &aad, limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;
    use rand_core::UnwrapErr;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let public = PublicKey::from(&secret).to_bytes();
        (secret.to_bytes(), public)
    }

    #[test]
    fn malicious_store_cannot_replace_a_signed_record() {
        let (secret, public) = keypair();
        let writer = crate::IdentityKeyPair::from_secret_key_bytes([42; 32]);
        let pin = crate::PeerIdentity::new(writer.public_key());
        let limits = BodyEnvelopeLimits::default();
        let record = StorageRecord::new(b"vault", b"item", 7);
        let (sealed, signature) =
            seal_signed_storage_record(b"original", public, b"kid", record, &writer, &limits)
                .unwrap();
        assert_eq!(
            open_signed_storage_record(&sealed, signature, secret, record, pin, &limits).unwrap(),
            b"original"
        );
        // A store knows the public key and descriptor and can encrypt arbitrary
        // replacements. Encryption alone accepts them; writer verification must not.
        let replacement = seal_storage_record(b"forged", public, b"kid", record).unwrap();
        assert_eq!(
            open_storage_record(&replacement, secret, record).unwrap(),
            b"forged"
        );
        assert!(
            open_signed_storage_record(&replacement, signature, secret, record, pin, &limits)
                .is_err()
        );
        assert!(
            open_signed_storage_record(
                &sealed,
                signature,
                secret,
                StorageRecord::new(b"vault", b"item", 8),
                pin,
                &limits
            )
            .is_err()
        );
    }

    #[test]
    fn descriptor_budget_is_checked_before_encoding() {
        let record = StorageRecord::new(b"ns", b"id", 1);
        let length = STORAGE_RECORD_AAD_DOMAIN.len() + 24 + 4;
        let mut limits = BodyEnvelopeLimits {
            max_context_len: length,
            ..Default::default()
        };
        assert_eq!(record.to_aad(&limits).unwrap().len(), length);
        limits.max_context_len -= 1;
        assert!(matches!(
            record.to_aad(&limits),
            Err(BodyEnvelopeError::LimitExceeded("context_len"))
        ));
    }

    #[test]
    fn roundtrip_with_matching_descriptor() {
        let (secret, public) = keypair();
        let record = StorageRecord::new(b"vault-items", b"item-42", 7);
        let sealed = seal_storage_record(b"super secret note", public, b"account-kid", record)
            .expect("seal");
        let opened = open_storage_record(&sealed, secret, record).expect("open");
        assert_eq!(opened, b"super secret note");
    }

    #[test]
    fn substituted_record_id_is_rejected() {
        let (secret, public) = keypair();
        let sealed = seal_storage_record(
            b"secret",
            public,
            b"kid",
            StorageRecord::new(b"vault-items", b"item-a", 1),
        )
        .expect("seal");
        // The store returns item-a's ciphertext when the client asked for item-b.
        let err = open_storage_record(
            &sealed,
            secret,
            StorageRecord::new(b"vault-items", b"item-b", 1),
        )
        .expect_err("substitution must fail");
        assert!(matches!(err, BodyEnvelopeError::DecryptFailed));
    }

    #[test]
    fn substituted_namespace_is_rejected() {
        let (secret, public) = keypair();
        let sealed = seal_storage_record(
            b"secret",
            public,
            b"kid",
            StorageRecord::new(b"vault-items", b"shared-id", 1),
        )
        .expect("seal");
        let err = open_storage_record(
            &sealed,
            secret,
            StorageRecord::new(b"secure-notes", b"shared-id", 1),
        )
        .expect_err("cross-namespace reuse must fail");
        assert!(matches!(err, BodyEnvelopeError::DecryptFailed));
    }

    #[test]
    fn rolled_back_version_is_rejected() {
        let (secret, public) = keypair();
        let sealed = seal_storage_record(
            b"v3 secret",
            public,
            b"kid",
            StorageRecord::new(b"vault-items", b"item-42", 3),
        )
        .expect("seal");
        // The client expects the current version (4); a stale v3 ciphertext must
        // not open.
        let err = open_storage_record(
            &sealed,
            secret,
            StorageRecord::new(b"vault-items", b"item-42", 4),
        )
        .expect_err("rollback must fail");
        assert!(matches!(err, BodyEnvelopeError::DecryptFailed));
    }

    #[test]
    fn length_prefixing_prevents_field_boundary_ambiguity() {
        let (secret, public) = keypair();
        // ("ab", "c") and ("a", "bc") share the concatenation "abc"; the length
        // prefixes must keep their descriptors distinct.
        let sealed = seal_storage_record(
            b"secret",
            public,
            b"kid",
            StorageRecord::new(b"ab", b"c", 1),
        )
        .expect("seal");
        let err = open_storage_record(&sealed, secret, StorageRecord::new(b"a", b"bc", 1))
            .expect_err("shifted field boundary must fail");
        assert!(matches!(err, BodyEnvelopeError::DecryptFailed));
    }
}
