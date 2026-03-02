use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    CoreError,
    frame::{Frame, FrameHeader, PROFILE_X25519_HKDF_XCHACHA20POLY1305},
};

/// Direction of protected traffic keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Client-to-server direction.
    C2S,
    /// Server-to-client direction.
    S2C,
}

/// Bidirectional traffic keys bound to a single `key_id`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrafficKeys {
    /// Active key identifier carried in frame headers.
    pub key_id: u8,
    /// Client-to-server key bytes.
    pub c2s: [u8; 32],
    /// Server-to-client key bytes.
    pub s2c: [u8; 32],
}

impl TrafficKeys {
    /// Returns key bytes for the specified direction.
    pub fn key_for(&self, direction: Direction) -> [u8; 32] {
        match direction {
            Direction::C2S => self.c2s,
            Direction::S2C => self.s2c,
        }
    }
}

impl Drop for TrafficKeys {
    fn drop(&mut self) {
        self.c2s.zeroize();
        self.s2c.zeroize();
    }
}

/// Builds a Draft v0 XChaCha nonce from frame metadata.
pub fn make_nonce(key_id: u8, stream_id: u32, seq: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[0] = key_id;
    nonce[1..5].copy_from_slice(&stream_id.to_be_bytes());
    nonce[5..13].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// Derives initial traffic keys from a shared secret and session salt.
pub fn derive_traffic_keys(
    shared_secret: &[u8],
    session_salt: &[u8; 32],
    key_id: u8,
) -> Result<TrafficKeys, CoreError> {
    let hk = Hkdf::<Sha256>::new(Some(session_salt), shared_secret);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"foctet c2s", &mut c2s)
        .map_err(|_| CoreError::Hkdf)?;
    hk.expand(b"foctet s2c", &mut s2c)
        .map_err(|_| CoreError::Hkdf)?;
    Ok(TrafficKeys { key_id, c2s, s2c })
}

/// Derives rekeyed traffic keys from shared/session/rekey salt inputs.
pub fn derive_rekey_traffic_keys(
    shared_secret: &[u8; 32],
    session_salt: &[u8; 32],
    rekey_salt: &[u8; 32],
    key_id: u8,
) -> Result<TrafficKeys, CoreError> {
    let mut salt = Zeroizing::new([0u8; 64]);
    salt[..32].copy_from_slice(session_salt);
    salt[32..].copy_from_slice(rekey_salt);
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), shared_secret);

    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];

    let mut info_c2s = [0u8; 17];
    info_c2s[..16].copy_from_slice(b"foctet rekey c2s");
    info_c2s[16] = key_id;
    let mut info_s2c = [0u8; 17];
    info_s2c[..16].copy_from_slice(b"foctet rekey s2c");
    info_s2c[16] = key_id;

    hk.expand(&info_c2s, &mut c2s)
        .map_err(|_| CoreError::Hkdf)?;
    hk.expand(&info_s2c, &mut s2c)
        .map_err(|_| CoreError::Hkdf)?;

    Ok(TrafficKeys { key_id, c2s, s2c })
}

/// Generates a random session salt for key derivation.
pub fn random_session_salt() -> [u8; 32] {
    let mut out = [0u8; 32];
    OsRng.fill_bytes(&mut out);
    out
}

/// Ephemeral X25519 key pair used during native handshake.
#[derive(Clone, Debug)]
pub struct EphemeralKeyPair {
    private: Zeroizing<[u8; 32]>,
    /// Public key bytes.
    pub public: [u8; 32],
}

impl EphemeralKeyPair {
    /// Generates a fresh ephemeral X25519 key pair.
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        Self {
            private: Zeroizing::new(private.to_bytes()),
            public: public.to_bytes(),
        }
    }

    /// Computes shared secret with peer ephemeral public key.
    pub fn shared_secret(&self, peer_public: [u8; 32]) -> [u8; 32] {
        let private = StaticSecret::from(*self.private);
        let peer = PublicKey::from(peer_public);
        private.diffie_hellman(&peer).to_bytes()
    }
}

/// Encrypts plaintext into a Foctet frame using AEAD profile `0x01`.
pub fn encrypt_frame(
    keys: &TrafficKeys,
    direction: Direction,
    flags: u8,
    stream_id: u32,
    seq: u64,
    plaintext: &[u8],
) -> Result<Frame, CoreError> {
    let key = Zeroizing::new(keys.key_for(direction));
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CoreError::InvalidKeyLength)?;

    let mut header = FrameHeader::new(
        flags,
        PROFILE_X25519_HKDF_XCHACHA20POLY1305,
        keys.key_id,
        stream_id,
        seq,
        0,
    );

    let nonce_raw = make_nonce(keys.key_id, stream_id, seq);
    let nonce = XNonce::from_slice(&nonce_raw);

    let mut aad_header = header.clone();
    aad_header.ct_len = (plaintext.len() + 16) as u32;
    let aad = aad_header.encode();

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::Aead)?;

    header.ct_len = ciphertext.len() as u32;
    Ok(Frame { header, ciphertext })
}

/// Decrypts a frame and enforces `key_id` equality with `keys`.
pub fn decrypt_frame(
    keys: &TrafficKeys,
    direction: Direction,
    frame: &Frame,
) -> Result<Vec<u8>, CoreError> {
    frame.header.validate_v0()?;
    if frame.header.key_id != keys.key_id {
        return Err(CoreError::UnexpectedKeyId {
            expected: keys.key_id,
            actual: frame.header.key_id,
        });
    }
    decrypt_frame_with_key(keys, direction, frame)
}

/// Decrypts a frame with a specific key record, without key-id equality check.
pub fn decrypt_frame_with_key(
    keys: &TrafficKeys,
    direction: Direction,
    frame: &Frame,
) -> Result<Vec<u8>, CoreError> {
    frame.header.validate_v0()?;
    if frame.ciphertext.len() != frame.header.ct_len as usize {
        return Err(CoreError::CiphertextLengthMismatch {
            expected: frame.header.ct_len as usize,
            actual: frame.ciphertext.len(),
        });
    }

    let key = Zeroizing::new(keys.key_for(direction));
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CoreError::InvalidKeyLength)?;
    let nonce_raw = make_nonce(
        frame.header.key_id,
        frame.header.stream_id,
        frame.header.seq,
    );
    let nonce = XNonce::from_slice(&nonce_raw);
    let aad = frame.header.encode();
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &frame.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CoreError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_encrypt_decrypt() {
        let eph_a = EphemeralKeyPair::generate();
        let eph_b = EphemeralKeyPair::generate();
        let ss_a = eph_a.shared_secret(eph_b.public);
        let ss_b = eph_b.shared_secret(eph_a.public);
        assert_eq!(ss_a, ss_b);

        let salt = random_session_salt();
        let keys = derive_traffic_keys(&ss_a, &salt, 7).expect("derive traffic keys");

        let plaintext = b"foctet core frame roundtrip";
        let frame =
            encrypt_frame(&keys, Direction::C2S, 0b10, 10, 42, plaintext).expect("encrypt frame");
        let bytes = frame.to_bytes();

        let parsed = Frame::from_bytes(&bytes).expect("parse frame");
        let out = decrypt_frame(&keys, Direction::C2S, &parsed).expect("decrypt frame");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn nonce_layout_matches_spec() {
        let nonce = make_nonce(0xAB, 0x0102_0304, 0x0102_0304_0506_0708);
        assert_eq!(nonce[0], 0xAB);
        assert_eq!(&nonce[1..5], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            &nonce[5..13],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(&nonce[13..], &[0u8; 11]);
    }
}
