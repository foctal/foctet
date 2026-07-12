use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use std::ops::Deref;
use std::sync::Arc;

use getrandom::SysRng;
use hkdf::Hkdf;
use rand_core::{TryRng, UnwrapErr};
use sha2::Sha256;
use subtle::ConstantTimeEq;
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
///
/// # Secret material
///
/// The `c2s` / `s2c` fields are live XChaCha20-Poly1305 keys. They are
/// **not** printed by the [`Debug`] implementation (which redacts them), are
/// compared in constant time (see the [`PartialEq`] impl), and are zeroized on
/// drop. Reading the raw bytes directly via the public fields is an explicit,
/// auditable exposure — prefer [`TrafficKeys::key_for`], and only copy the
/// bytes out when you immediately wrap the copy (e.g. in
/// [`zeroize::Zeroizing`]).
///
/// `TrafficKeys` is deliberately **not** `Clone`: the secret key bytes exist in
/// exactly one place and are zeroized when that place is dropped. Share keys
/// through a [`KeyHandle`] (a reference-counted handle) instead of copying the
/// secret bytes into multiple owners.
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

impl core::fmt::Debug for TrafficKeys {
    /// Redacts the directional key bytes so they cannot leak into logs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrafficKeys")
            .field("key_id", &self.key_id)
            .field("c2s", &"<redacted>")
            .field("s2c", &"<redacted>")
            .finish()
    }
}

impl PartialEq for TrafficKeys {
    /// Compares the directional keys in constant time.
    ///
    /// The `key_id` is a public frame-header byte and is compared normally; the
    /// secret key bytes are compared with [`subtle::ConstantTimeEq`] so that
    /// equality checks do not leak key material through timing.
    fn eq(&self, other: &Self) -> bool {
        let c2s_eq = self.c2s.ct_eq(&other.c2s);
        let s2c_eq = self.s2c.ct_eq(&other.s2c);
        self.key_id == other.key_id && (c2s_eq & s2c_eq).into()
    }
}

impl Eq for TrafficKeys {}

impl Drop for TrafficKeys {
    fn drop(&mut self) {
        self.c2s.zeroize();
        self.s2c.zeroize();
    }
}

/// A shared, reference-counted handle to a set of [`TrafficKeys`].
///
/// Because [`TrafficKeys`] is not `Clone`, the session key ring, the previous-key
/// retention list, and the various I/O endpoints share one key set through a
/// `KeyHandle` rather than each owning a copy of the secret bytes. Cloning a
/// `KeyHandle` only bumps the reference count; the underlying key bytes are
/// zeroized once the last handle is dropped.
///
/// A `KeyHandle` dereferences to the inner [`TrafficKeys`], so field access
/// (`handle.key_id`) and methods (`handle.key_for(dir)`) work directly, and it
/// coerces to `&TrafficKeys` at call sites such as [`encrypt_frame`]. Equality
/// and `Debug` delegate to [`TrafficKeys`] (constant-time comparison, redacted
/// secret bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyHandle(Arc<TrafficKeys>);

impl KeyHandle {
    /// Wraps a freshly derived key set in a shared handle.
    pub fn new(keys: TrafficKeys) -> Self {
        Self(Arc::new(keys))
    }
}

impl From<TrafficKeys> for KeyHandle {
    fn from(keys: TrafficKeys) -> Self {
        Self::new(keys)
    }
}

impl Deref for KeyHandle {
    type Target = TrafficKeys;

    fn deref(&self) -> &TrafficKeys {
        &self.0
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

/// Derives the initial DH-ratchet root key from the handshake shared secret.
///
/// The root key seeds the rekey ratchet (see [`dh_ratchet_step`]); it is mixed
/// with a fresh Diffie-Hellman output at every rekey so that traffic keys gain
/// forward secrecy and post-compromise security across rekeys, rather than all
/// being derivable from the one handshake secret.
pub fn derive_ratchet_root(
    session_salt: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Result<[u8; 32], CoreError> {
    let hk = Hkdf::<Sha256>::new(Some(session_salt), shared_secret);
    let mut root = [0u8; 32];
    hk.expand(b"foctet ratchet init", &mut root)
        .map_err(|_| CoreError::Hkdf)?;
    Ok(root)
}

/// Performs one DH-ratchet step: mixes a fresh Diffie-Hellman output `dh` into
/// the ratchet `root`, returning the advanced root and the next traffic keys.
///
/// `(new_root, c2s, s2c)` are independent HKDF-SHA-256 expansions of
/// `HKDF(salt = root, ikm = dh)`. Because `dh` comes from a freshly generated
/// ephemeral key at each rekey, an attacker who learns the current keys cannot
/// derive the keys after the next rekey (post-compromise security), and an
/// attacker who later compromises the long-term state cannot derive past keys
/// (forward secrecy) once the ephemeral private keys are discarded.
pub fn dh_ratchet_step(
    root: &[u8; 32],
    dh: &[u8; 32],
    key_id: u8,
) -> Result<([u8; 32], TrafficKeys), CoreError> {
    let hk = Hkdf::<Sha256>::new(Some(root), dh);

    let mut new_root = [0u8; 32];
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];

    hk.expand(b"foctet ratchet root", &mut new_root)
        .map_err(|_| CoreError::Hkdf)?;

    let mut info_c2s = [0u8; 19];
    info_c2s[..18].copy_from_slice(b"foctet ratchet c2s");
    info_c2s[18] = key_id;
    let mut info_s2c = [0u8; 19];
    info_s2c[..18].copy_from_slice(b"foctet ratchet s2c");
    info_s2c[18] = key_id;

    hk.expand(&info_c2s, &mut c2s)
        .map_err(|_| CoreError::Hkdf)?;
    hk.expand(&info_s2c, &mut s2c)
        .map_err(|_| CoreError::Hkdf)?;

    Ok((new_root, TrafficKeys { key_id, c2s, s2c }))
}

/// Generates a random session salt for key derivation.
pub fn random_session_salt() -> [u8; 32] {
    let mut out = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut out)
        .expect("OS random number generator is unavailable");
    out
}

/// Ephemeral X25519 key pair used during native handshake.
#[derive(Clone)]
pub struct EphemeralKeyPair {
    private: Zeroizing<[u8; 32]>,
    /// Public key bytes.
    pub public: [u8; 32],
}

impl core::fmt::Debug for EphemeralKeyPair {
    /// Redacts the private scalar so it cannot leak into logs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EphemeralKeyPair")
            .field("private", &"<redacted>")
            .field("public", &self.public)
            .finish()
    }
}

impl EphemeralKeyPair {
    /// Generates a fresh ephemeral X25519 key pair.
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let public = PublicKey::from(&private);
        Self {
            private: Zeroizing::new(private.to_bytes()),
            public: public.to_bytes(),
        }
    }

    /// Computes shared secret with peer ephemeral public key.
    pub fn shared_secret(&self, peer_public: [u8; 32]) -> Result<[u8; 32], CoreError> {
        let private = StaticSecret::from(*self.private);
        let shared = x25519_shared_secret(&private, peer_public)?;
        Ok(*shared)
    }
}

/// Computes an X25519 shared secret and rejects the forbidden all-zero result.
///
/// X25519 accepts every 32-byte input at the type level. Some low-order public
/// inputs, however, produce an all-zero shared secret. Callers must use this
/// helper instead of calling `StaticSecret::diffie_hellman` directly so those
/// inputs cannot turn a public recipient key into a predictable wrapping key.
/// The returned secret is zeroized when dropped.
pub fn x25519_shared_secret(
    private: &StaticSecret,
    peer_public: [u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let peer = PublicKey::from(peer_public);
    let shared = Zeroizing::new(private.diffie_hellman(&peer).to_bytes());
    if shared.iter().all(|byte| *byte == 0) {
        return Err(CoreError::InvalidSharedSecret);
    }
    Ok(shared)
}

/// XChaCha20-Poly1305 authentication tag length, in bytes.
const AEAD_TAG_LEN: usize = 16;

/// Computes the ciphertext length (plaintext + AEAD tag) for a given plaintext
/// length, failing closed instead of silently truncating if it would not fit
/// in the frame header's `u32 ct_len` field.
fn checked_ciphertext_len(plaintext_len: usize) -> Result<u32, CoreError> {
    if plaintext_len > (u32::MAX as usize) - AEAD_TAG_LEN {
        return Err(CoreError::FrameTooLarge);
    }
    Ok((plaintext_len + AEAD_TAG_LEN) as u32)
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
    // Reject plaintext that would make the ciphertext length (plaintext + AEAD
    // tag) overflow the header's `u32 ct_len` field. Without this check the
    // cast below would silently truncate, producing a frame whose declared
    // length doesn't match its actual ciphertext.
    let expected_ct_len = checked_ciphertext_len(plaintext.len())?;

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
    let nonce = &XNonce::try_from(&nonce_raw[..]).expect("fixed-size nonce");

    let mut aad_header = header.clone();
    aad_header.ct_len = expected_ct_len;
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
    let nonce = &XNonce::try_from(&nonce_raw[..]).expect("fixed-size nonce");
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
    use x25519_dalek::StaticSecret;

    #[test]
    fn x25519_rejects_all_zero_and_low_order_public_inputs() {
        let private = StaticSecret::from([0x42; 32]);
        for public in [[0u8; 32], {
            let mut low_order = [0u8; 32];
            low_order[0] = 1;
            low_order
        }] {
            assert!(matches!(
                x25519_shared_secret(&private, public),
                Err(CoreError::InvalidSharedSecret)
            ));
        }
    }

    #[test]
    fn ephemeral_key_pair_uses_shared_secret_helper() {
        let pair = EphemeralKeyPair::generate();
        assert!(matches!(
            pair.shared_secret([0u8; 32]),
            Err(CoreError::InvalidSharedSecret)
        ));
    }

    #[test]
    fn frame_roundtrip_encrypt_decrypt() {
        let eph_a = EphemeralKeyPair::generate();
        let eph_b = EphemeralKeyPair::generate();
        let ss_a = eph_a.shared_secret(eph_b.public).expect("shared secret a");
        let ss_b = eph_b.shared_secret(eph_a.public).expect("shared secret b");
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

    #[test]
    fn checked_ciphertext_len_fits_just_below_overflow() {
        let max_plaintext = (u32::MAX as usize) - AEAD_TAG_LEN;
        assert_eq!(
            checked_ciphertext_len(max_plaintext).expect("fits"),
            u32::MAX
        );
    }

    #[test]
    fn checked_ciphertext_len_fails_closed_on_overflow() {
        let max_plaintext = (u32::MAX as usize) - AEAD_TAG_LEN;
        let err = checked_ciphertext_len(max_plaintext + 1).expect_err("must not truncate");
        assert!(matches!(err, CoreError::FrameTooLarge));
    }

    #[test]
    fn traffic_keys_debug_redacts_key_bytes() {
        let keys = TrafficKeys {
            key_id: 9,
            c2s: [0xAB; 32],
            s2c: [0xCD; 32],
        };
        let rendered = format!("{keys:?}");
        assert!(rendered.contains("key_id: 9"));
        assert!(rendered.contains("<redacted>"));
        // No raw key byte should appear in the debug output.
        assert!(!rendered.contains("ab"));
        assert!(!rendered.contains("171")); // 0xAB as decimal
        assert!(!rendered.contains("205")); // 0xCD as decimal
    }

    #[test]
    fn traffic_keys_equality_is_value_based() {
        let a = TrafficKeys {
            key_id: 1,
            c2s: [0x01; 32],
            s2c: [0x02; 32],
        };
        let b = TrafficKeys {
            key_id: 1,
            c2s: [0x01; 32],
            s2c: [0x02; 32],
        };
        let c = TrafficKeys {
            key_id: 1,
            c2s: [0x01; 32],
            s2c: [0x03; 32],
        };
        let d = TrafficKeys {
            key_id: 2,
            c2s: [0x01; 32],
            s2c: [0x02; 32],
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn ephemeral_key_pair_debug_redacts_private_scalar() {
        // Use a fixed private scalar so we can assert its rendered array form is
        // absent from the Debug output.
        let private = Zeroizing::new([0x5A_u8; 32]);
        let public = PublicKey::from(&StaticSecret::from(*private)).to_bytes();
        let pair = EphemeralKeyPair { private, public };

        let rendered = format!("{pair:?}");
        assert!(rendered.contains("<redacted>"));
        // The private scalar's array representation must never appear.
        let leaked = format!("{:?}", [0x5A_u8; 32]);
        assert!(
            !rendered.contains(&leaked),
            "private scalar leaked into Debug output: {rendered}"
        );
    }
}
