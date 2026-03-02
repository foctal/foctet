use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{ArchiveError, WrappedDek};

pub(crate) fn wrap_dek(
    dek: &[u8; 32],
    recipient_public: [u8; 32],
) -> Result<WrappedDek, ArchiveError> {
    let eph_priv = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_priv);
    let recipient = PublicKey::from(recipient_public);
    let shared = Zeroizing::new(eph_priv.diffie_hellman(&recipient).to_bytes());

    let mut okm = Zeroizing::new([0u8; 56]);
    let hk = Hkdf::<Sha256>::new(None, &shared[..]);
    hk.expand(b"foctet archive wrap", &mut okm[..])
        .map_err(|_| ArchiveError::Hkdf)?;

    let mut wrap_key = Zeroizing::new([0u8; 32]);
    wrap_key.copy_from_slice(&okm[..32]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&okm[32..56]);

    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(&recipient_public);
    aad.extend_from_slice(eph_pub.as_bytes());

    let ciphertext = aead_encrypt(&wrap_key, &nonce, &aad, dek)?;

    Ok(WrappedDek {
        recipient_public,
        ephemeral_public: eph_pub.to_bytes(),
        nonce,
        ciphertext,
    })
}

pub(crate) fn unwrap_dek_from_recipients(
    recipients: &[WrappedDek],
    recipient_private: [u8; 32],
) -> Result<[u8; 32], ArchiveError> {
    let priv_key = StaticSecret::from(recipient_private);
    let expected_public = PublicKey::from(&priv_key).to_bytes();

    for item in recipients {
        if item.recipient_public != expected_public {
            continue;
        }

        let eph_pub = PublicKey::from(item.ephemeral_public);
        let shared = Zeroizing::new(priv_key.diffie_hellman(&eph_pub).to_bytes());

        let mut okm = Zeroizing::new([0u8; 56]);
        let hk = Hkdf::<Sha256>::new(None, &shared[..]);
        hk.expand(b"foctet archive wrap", &mut okm[..])
            .map_err(|_| ArchiveError::Hkdf)?;

        let mut wrap_key = Zeroizing::new([0u8; 32]);
        wrap_key.copy_from_slice(&okm[..32]);

        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(&item.recipient_public);
        aad.extend_from_slice(&item.ephemeral_public);

        let dek = aead_decrypt(&wrap_key, &item.nonce, &aad, &item.ciphertext)?;
        if dek.len() != 32 {
            return Err(ArchiveError::Parse);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&dek);
        let mut dek = dek;
        dek.zeroize();
        return Ok(out);
    }

    Err(ArchiveError::MissingRecipient)
}

pub(crate) fn header_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0] = 0xFF;
    nonce
}

pub(crate) fn chunk_nonce(archive_id: [u8; 16], chunk_index: u32) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0] = 0x00;
    nonce[1..17].copy_from_slice(&archive_id);
    nonce[17..21].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

pub(crate) fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ArchiveError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ArchiveError::Aead)?;
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ArchiveError::Aead)
}

pub(crate) fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ArchiveError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ArchiveError::Aead)?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ArchiveError::Aead)
}
