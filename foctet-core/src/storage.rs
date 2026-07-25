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
//! zero-knowledge storage building block — only the client holds a key; the
//! server stores and returns bytes.
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
    fn to_aad(self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            STORAGE_RECORD_AAD_DOMAIN.len()
                + 8
                + self.namespace.len()
                + 8
                + self.record_id.len()
                + 8,
        );
        aad.extend_from_slice(STORAGE_RECORD_AAD_DOMAIN);
        aad.extend_from_slice(&(self.namespace.len() as u64).to_be_bytes());
        aad.extend_from_slice(self.namespace);
        aad.extend_from_slice(&(self.record_id.len() as u64).to_be_bytes());
        aad.extend_from_slice(self.record_id);
        aad.extend_from_slice(&self.version.to_be_bytes());
        aad
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
        &record.to_aad(),
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
    open_body_with_context(envelope, recipient_secret_key, &record.to_aad(), limits)
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
