use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// `application/foctet` body-envelope magic bytes.
pub const BODY_MAGIC: [u8; 8] = *b"FOCTETHB";
/// Body-envelope wire version `v0`.
pub const BODY_VERSION_V0: u8 = 0x01;
/// Profile `0x01` (`X25519 + HKDF-SHA256 + XChaCha20-Poly1305`).
pub const BODY_PROFILE_V0: u8 = 0x01;
/// X25519 public key length in bytes.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const XCHACHA_NONCE_LEN: usize = 24;
const CONTENT_KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WRAP_INFO_LABEL: &[u8] = b"foctet body wrap v0";

/// Parser and encoder hardening limits for body envelopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyEnvelopeLimits {
    /// Maximum parsed header length in bytes.
    pub max_header_bytes: usize,
    /// Maximum number of recipient entries allowed in one envelope.
    pub max_recipients: usize,
    /// Maximum recipient key identifier length in bytes.
    pub max_key_id_len: usize,
    /// Maximum wrapped content-key length in bytes.
    pub max_wrapped_key_len: usize,
    /// Maximum payload ciphertext length in bytes.
    pub max_payload_len: usize,
}

impl Default for BodyEnvelopeLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_recipients: 16,
            max_key_id_len: 512,
            max_wrapped_key_len: 512,
            max_payload_len: 64 * 1024 * 1024,
        }
    }
}

/// Envelope parser/sealer error type for `application/foctet`.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum BodyEnvelopeError {
    /// Envelope magic bytes are invalid.
    #[error("invalid body-envelope magic")]
    InvalidMagic,
    /// Body-envelope version is unsupported.
    #[error("unsupported body-envelope version: {0}")]
    UnsupportedVersion(u8),
    /// Body-envelope profile is unsupported.
    #[error("unsupported body-envelope profile: {0}")]
    UnsupportedProfile(u8),
    /// Input bytes are truncated.
    #[error("truncated body-envelope input")]
    Truncated,
    /// Header bytes are malformed or inconsistent.
    #[error("invalid body-envelope header: {0}")]
    InvalidHeader(&'static str),
    /// A configured parser or encoder limit was exceeded.
    #[error("body-envelope limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// No matching recipient entry could be used.
    #[error("recipient not found")]
    RecipientNotFound,
    /// Content-key unwrap failed for a selected recipient entry.
    #[error("content-key unwrap failed")]
    KeyUnwrapFailed,
    /// Payload decryption failed.
    #[error("payload decryption failed")]
    DecryptFailed,
    /// Payload encryption failed.
    #[error("payload encryption failed")]
    EncryptFailed,
    /// HKDF expansion failed.
    #[error("hkdf expand failed")]
    Hkdf,
}

#[derive(Clone, Debug)]
struct RecipientEntry {
    key_id: Vec<u8>,
    wrapped_key: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ParsedEnvelope<'a> {
    header_bytes: &'a [u8],
    payload_ciphertext: &'a [u8],
    ephemeral_public: [u8; X25519_PUBLIC_KEY_LEN],
    payload_nonce: [u8; XCHACHA_NONCE_LEN],
    recipients: Vec<RecipientEntry>,
}

/// Seals plaintext bytes into an `application/foctet` v0 body envelope.
pub fn seal_body(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
) -> Result<Vec<u8>, BodyEnvelopeError> {
    seal_body_with_limits(
        plaintext,
        recipient_public_key,
        recipient_key_id,
        &BodyEnvelopeLimits::default(),
    )
}

/// Seals plaintext bytes with explicit limits for defensive encoding.
pub fn seal_body_with_limits(
    plaintext: &[u8],
    recipient_public_key: [u8; 32],
    recipient_key_id: &[u8],
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, BodyEnvelopeError> {
    if recipient_key_id.is_empty() {
        return Err(BodyEnvelopeError::InvalidHeader("empty recipient key id"));
    }
    if recipient_key_id.len() > limits.max_key_id_len {
        return Err(BodyEnvelopeError::LimitExceeded("key_id_len"));
    }

    let payload_len = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(BodyEnvelopeError::LimitExceeded("payload_len overflow"))?;
    if payload_len > limits.max_payload_len {
        return Err(BodyEnvelopeError::LimitExceeded("payload_len"));
    }

    let mut content_key = Zeroizing::new([0u8; CONTENT_KEY_LEN]);
    OsRng.fill_bytes(&mut content_key[..]);

    let mut payload_nonce = [0u8; XCHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut payload_nonce);

    let eph_priv = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_priv).to_bytes();

    let wrapped_key = wrap_content_key(
        &content_key,
        recipient_public_key,
        eph_priv,
        eph_pub,
        recipient_key_id,
    )?;

    if wrapped_key.len() > limits.max_wrapped_key_len {
        return Err(BodyEnvelopeError::LimitExceeded("wrapped_key_len"));
    }

    let header = encode_header(
        &eph_pub,
        &payload_nonce,
        recipient_key_id,
        &wrapped_key,
        payload_len,
        limits,
    )?;

    if header.len() > limits.max_header_bytes {
        return Err(BodyEnvelopeError::LimitExceeded("header_len"));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(&content_key[..])
        .map_err(|_| BodyEnvelopeError::EncryptFailed)?;
    let payload_ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&payload_nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| BodyEnvelopeError::EncryptFailed)?;

    let mut out = Vec::with_capacity(
        header
            .len()
            .checked_add(payload_ciphertext.len())
            .ok_or(BodyEnvelopeError::LimitExceeded("envelope_len overflow"))?,
    );
    out.extend_from_slice(&header);
    out.extend_from_slice(&payload_ciphertext);
    Ok(out)
}

/// Opens an `application/foctet` v0 body envelope with default limits.
pub fn open_body(
    envelope: &[u8],
    recipient_secret_key: [u8; 32],
) -> Result<Vec<u8>, BodyEnvelopeError> {
    open_body_with_limits(
        envelope,
        recipient_secret_key,
        &BodyEnvelopeLimits::default(),
    )
}

/// Opens an `application/foctet` v0 body envelope with explicit parser limits.
pub fn open_body_with_limits(
    envelope: &[u8],
    recipient_secret_key: [u8; 32],
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, BodyEnvelopeError> {
    let parsed = parse_envelope(envelope, limits)?;

    for recipient in &parsed.recipients {
        let content_key = match unwrap_content_key(
            &recipient.wrapped_key,
            &recipient.key_id,
            recipient_secret_key,
            parsed.ephemeral_public,
        ) {
            Ok(key) => key,
            Err(BodyEnvelopeError::KeyUnwrapFailed) => continue,
            Err(err) => return Err(err),
        };

        let cipher = XChaCha20Poly1305::new_from_slice(&content_key[..])
            .map_err(|_| BodyEnvelopeError::DecryptFailed)?;

        let plain = cipher
            .decrypt(
                XNonce::from_slice(&parsed.payload_nonce),
                Payload {
                    msg: parsed.payload_ciphertext,
                    aad: parsed.header_bytes,
                },
            )
            .map_err(|_| BodyEnvelopeError::DecryptFailed)?;

        return Ok(plain);
    }

    Err(BodyEnvelopeError::RecipientNotFound)
}

/// Opens an envelope for a specific recipient key identifier.
pub fn open_body_for_key_id(
    envelope: &[u8],
    recipient_secret_key: [u8; 32],
    recipient_key_id: &[u8],
) -> Result<Vec<u8>, BodyEnvelopeError> {
    open_body_for_key_id_with_limits(
        envelope,
        recipient_secret_key,
        recipient_key_id,
        &BodyEnvelopeLimits::default(),
    )
}

/// Opens an envelope for a specific recipient key identifier using explicit limits.
pub fn open_body_for_key_id_with_limits(
    envelope: &[u8],
    recipient_secret_key: [u8; 32],
    recipient_key_id: &[u8],
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, BodyEnvelopeError> {
    let parsed = parse_envelope(envelope, limits)?;

    let entry = parsed
        .recipients
        .iter()
        .find(|entry| entry.key_id.as_slice() == recipient_key_id)
        .ok_or(BodyEnvelopeError::RecipientNotFound)?;

    let content_key = unwrap_content_key(
        &entry.wrapped_key,
        &entry.key_id,
        recipient_secret_key,
        parsed.ephemeral_public,
    )?;

    let cipher = XChaCha20Poly1305::new_from_slice(&content_key[..])
        .map_err(|_| BodyEnvelopeError::DecryptFailed)?;

    cipher
        .decrypt(
            XNonce::from_slice(&parsed.payload_nonce),
            Payload {
                msg: parsed.payload_ciphertext,
                aad: parsed.header_bytes,
            },
        )
        .map_err(|_| BodyEnvelopeError::DecryptFailed)
}

fn parse_envelope<'a>(
    envelope: &'a [u8],
    limits: &BodyEnvelopeLimits,
) -> Result<ParsedEnvelope<'a>, BodyEnvelopeError> {
    let mut cur = 0usize;

    let magic = take(envelope, &mut cur, BODY_MAGIC.len())?;
    if magic != BODY_MAGIC {
        return Err(BodyEnvelopeError::InvalidMagic);
    }

    let version = *take(envelope, &mut cur, 1)?
        .first()
        .ok_or(BodyEnvelopeError::Truncated)?;
    if version != BODY_VERSION_V0 {
        return Err(BodyEnvelopeError::UnsupportedVersion(version));
    }

    let profile = *take(envelope, &mut cur, 1)?
        .first()
        .ok_or(BodyEnvelopeError::Truncated)?;
    if profile != BODY_PROFILE_V0 {
        return Err(BodyEnvelopeError::UnsupportedProfile(profile));
    }

    let flags = *take(envelope, &mut cur, 1)?
        .first()
        .ok_or(BodyEnvelopeError::Truncated)?;
    if flags != 0 {
        return Err(BodyEnvelopeError::InvalidHeader("unknown flags"));
    }

    let eph_len = *take(envelope, &mut cur, 1)?
        .first()
        .ok_or(BodyEnvelopeError::Truncated)? as usize;
    if eph_len != X25519_PUBLIC_KEY_LEN {
        return Err(BodyEnvelopeError::InvalidHeader(
            "invalid ephemeral_public_key_len",
        ));
    }

    let header_len = decode_varint(envelope, &mut cur)?;
    let recipient_count = decode_varint(envelope, &mut cur)?;
    let payload_len = decode_varint(envelope, &mut cur)?;

    let header_len = to_usize(header_len, "header_len")?;
    let recipient_count = to_usize(recipient_count, "recipient_count")?;
    let payload_len = to_usize(payload_len, "payload_len")?;

    if header_len > limits.max_header_bytes {
        return Err(BodyEnvelopeError::LimitExceeded("header_len"));
    }
    if recipient_count > limits.max_recipients {
        return Err(BodyEnvelopeError::LimitExceeded("recipient_count"));
    }
    if payload_len > limits.max_payload_len {
        return Err(BodyEnvelopeError::LimitExceeded("payload_len"));
    }
    if header_len > envelope.len() {
        return Err(BodyEnvelopeError::Truncated);
    }

    let min_tail = eph_len
        .checked_add(XCHACHA_NONCE_LEN)
        .ok_or(BodyEnvelopeError::InvalidHeader("header length overflow"))?;
    if cur
        .checked_add(min_tail)
        .ok_or(BodyEnvelopeError::InvalidHeader("header length overflow"))?
        > header_len
    {
        return Err(BodyEnvelopeError::InvalidHeader("header_len too small"));
    }

    let mut ephemeral_public = [0u8; X25519_PUBLIC_KEY_LEN];
    ephemeral_public.copy_from_slice(take(envelope, &mut cur, X25519_PUBLIC_KEY_LEN)?);

    let mut payload_nonce = [0u8; XCHACHA_NONCE_LEN];
    payload_nonce.copy_from_slice(take(envelope, &mut cur, XCHACHA_NONCE_LEN)?);

    let mut recipients = Vec::new();
    for _ in 0..recipient_count {
        if cur >= header_len {
            return Err(BodyEnvelopeError::Truncated);
        }

        let key_id_len = to_usize(decode_varint(envelope, &mut cur)?, "key_id_len")?;
        let wrapped_key_len = to_usize(decode_varint(envelope, &mut cur)?, "wrapped_key_len")?;

        if key_id_len == 0 {
            return Err(BodyEnvelopeError::InvalidHeader("empty key_id"));
        }
        if key_id_len > limits.max_key_id_len {
            return Err(BodyEnvelopeError::LimitExceeded("key_id_len"));
        }
        if wrapped_key_len > limits.max_wrapped_key_len {
            return Err(BodyEnvelopeError::LimitExceeded("wrapped_key_len"));
        }
        if wrapped_key_len != CONTENT_KEY_LEN + TAG_LEN {
            return Err(BodyEnvelopeError::InvalidHeader(
                "invalid wrapped_key_len for v0",
            ));
        }

        let end = cur
            .checked_add(key_id_len)
            .and_then(|v| v.checked_add(wrapped_key_len))
            .ok_or(BodyEnvelopeError::InvalidHeader("recipient entry overflow"))?;
        if end > header_len || end > envelope.len() {
            return Err(BodyEnvelopeError::Truncated);
        }

        let key_id = take(envelope, &mut cur, key_id_len)?.to_vec();
        let wrapped_key = take(envelope, &mut cur, wrapped_key_len)?.to_vec();
        recipients.push(RecipientEntry {
            key_id,
            wrapped_key,
        });
    }

    if recipients.is_empty() {
        return Err(BodyEnvelopeError::InvalidHeader(
            "recipient_count must be >= 1",
        ));
    }

    if cur != header_len {
        return Err(BodyEnvelopeError::InvalidHeader(
            "unexpected trailing header bytes",
        ));
    }

    let expected_total = header_len
        .checked_add(payload_len)
        .ok_or(BodyEnvelopeError::InvalidHeader("envelope length overflow"))?;
    if envelope.len() < expected_total {
        return Err(BodyEnvelopeError::Truncated);
    }
    if envelope.len() != expected_total {
        return Err(BodyEnvelopeError::InvalidHeader(
            "unexpected trailing body bytes",
        ));
    }

    let payload_ciphertext = &envelope[header_len..expected_total];
    if payload_ciphertext.len() < TAG_LEN {
        return Err(BodyEnvelopeError::InvalidHeader(
            "payload ciphertext too short",
        ));
    }

    Ok(ParsedEnvelope {
        header_bytes: &envelope[..header_len],
        payload_ciphertext,
        ephemeral_public,
        payload_nonce,
        recipients,
    })
}

fn wrap_content_key(
    content_key: &[u8; CONTENT_KEY_LEN],
    recipient_public_key: [u8; 32],
    eph_priv: StaticSecret,
    eph_pub: [u8; 32],
    key_id: &[u8],
) -> Result<Vec<u8>, BodyEnvelopeError> {
    let recipient = PublicKey::from(recipient_public_key);
    let shared = Zeroizing::new(eph_priv.diffie_hellman(&recipient).to_bytes());

    let (wrap_key, wrap_nonce) = derive_wrap_material(&shared, eph_pub, recipient_public_key)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&wrap_key[..])
        .map_err(|_| BodyEnvelopeError::KeyUnwrapFailed)?;
    cipher
        .encrypt(
            XNonce::from_slice(&wrap_nonce),
            Payload {
                msg: content_key,
                aad: key_id,
            },
        )
        .map_err(|_| BodyEnvelopeError::KeyUnwrapFailed)
}

fn unwrap_content_key(
    wrapped_key: &[u8],
    key_id: &[u8],
    recipient_secret_key: [u8; 32],
    ephemeral_public_key: [u8; 32],
) -> Result<[u8; CONTENT_KEY_LEN], BodyEnvelopeError> {
    let recipient_priv = StaticSecret::from(recipient_secret_key);
    let recipient_public = PublicKey::from(&recipient_priv).to_bytes();
    let eph_pub = PublicKey::from(ephemeral_public_key);

    let shared = Zeroizing::new(recipient_priv.diffie_hellman(&eph_pub).to_bytes());
    let (wrap_key, wrap_nonce) =
        derive_wrap_material(&shared, ephemeral_public_key, recipient_public)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&wrap_key[..])
        .map_err(|_| BodyEnvelopeError::KeyUnwrapFailed)?;
    let unwrapped = cipher
        .decrypt(
            XNonce::from_slice(&wrap_nonce),
            Payload {
                msg: wrapped_key,
                aad: key_id,
            },
        )
        .map_err(|_| BodyEnvelopeError::KeyUnwrapFailed)?;

    if unwrapped.len() != CONTENT_KEY_LEN {
        return Err(BodyEnvelopeError::KeyUnwrapFailed);
    }

    let mut out = [0u8; CONTENT_KEY_LEN];
    out.copy_from_slice(&unwrapped);
    Ok(out)
}

fn derive_wrap_material(
    shared_secret: &[u8; 32],
    ephemeral_public_key: [u8; 32],
    recipient_public_key: [u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 24]), BodyEnvelopeError> {
    let mut info = [0u8; WRAP_INFO_LABEL.len() + 64];
    let label_len = WRAP_INFO_LABEL.len();
    info[..label_len].copy_from_slice(WRAP_INFO_LABEL);
    info[label_len..label_len + 32].copy_from_slice(&ephemeral_public_key);
    info[label_len + 32..].copy_from_slice(&recipient_public_key);

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; CONTENT_KEY_LEN + XCHACHA_NONCE_LEN]);
    hk.expand(&info, &mut okm[..])
        .map_err(|_| BodyEnvelopeError::Hkdf)?;

    let mut wrap_key = Zeroizing::new([0u8; CONTENT_KEY_LEN]);
    wrap_key.copy_from_slice(&okm[..CONTENT_KEY_LEN]);

    let mut wrap_nonce = [0u8; XCHACHA_NONCE_LEN];
    wrap_nonce.copy_from_slice(&okm[CONTENT_KEY_LEN..]);

    Ok((wrap_key, wrap_nonce))
}

fn encode_header(
    ephemeral_public_key: &[u8; 32],
    payload_nonce: &[u8; XCHACHA_NONCE_LEN],
    recipient_key_id: &[u8],
    wrapped_key: &[u8],
    payload_len: usize,
    limits: &BodyEnvelopeLimits,
) -> Result<Vec<u8>, BodyEnvelopeError> {
    let payload_len_u64 = u64::try_from(payload_len)
        .map_err(|_| BodyEnvelopeError::LimitExceeded("payload_len overflow"))?;

    // Header length includes this varint itself. Solve by fixed-point iteration.
    let mut header_len_guess = 0u64;
    let mut converged = false;
    let mut encoded = Vec::new();

    for _ in 0..4 {
        encoded.clear();
        encoded.extend_from_slice(&BODY_MAGIC);
        encoded.push(BODY_VERSION_V0);
        encoded.push(BODY_PROFILE_V0);
        encoded.push(0); // flags
        encoded.push(X25519_PUBLIC_KEY_LEN as u8);
        encode_varint(header_len_guess, &mut encoded);
        encode_varint(1, &mut encoded);
        encode_varint(payload_len_u64, &mut encoded);

        encoded.extend_from_slice(ephemeral_public_key);
        encoded.extend_from_slice(payload_nonce);
        encode_varint(recipient_key_id.len() as u64, &mut encoded);
        encode_varint(wrapped_key.len() as u64, &mut encoded);
        encoded.extend_from_slice(recipient_key_id);
        encoded.extend_from_slice(wrapped_key);

        let actual = u64::try_from(encoded.len())
            .map_err(|_| BodyEnvelopeError::LimitExceeded("header_len overflow"))?;
        if actual == header_len_guess {
            converged = true;
            break;
        }
        header_len_guess = actual;
    }

    if !converged {
        return Err(BodyEnvelopeError::InvalidHeader(
            "header_len encoding did not converge",
        ));
    }

    let final_len = encoded.len();
    if final_len > limits.max_header_bytes {
        return Err(BodyEnvelopeError::LimitExceeded("header_len"));
    }

    Ok(encoded)
}

fn to_usize(v: u64, field: &'static str) -> Result<usize, BodyEnvelopeError> {
    usize::try_from(v).map_err(|_| BodyEnvelopeError::LimitExceeded(field))
}

fn take<'a>(input: &'a [u8], cur: &mut usize, len: usize) -> Result<&'a [u8], BodyEnvelopeError> {
    let end = cur.checked_add(len).ok_or(BodyEnvelopeError::Truncated)?;
    if end > input.len() {
        return Err(BodyEnvelopeError::Truncated);
    }
    let out = &input[*cur..end];
    *cur = end;
    Ok(out)
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn decode_varint(input: &[u8], cur: &mut usize) -> Result<u64, BodyEnvelopeError> {
    let mut shift = 0u32;
    let mut value = 0u64;

    for _ in 0..10 {
        let byte = *take(input, cur, 1)?
            .first()
            .ok_or(BodyEnvelopeError::Truncated)?;
        let chunk = (byte & 0x7F) as u64;

        if shift >= 64 && chunk != 0 {
            return Err(BodyEnvelopeError::InvalidHeader("varint overflow"));
        }

        value |= chunk
            .checked_shl(shift)
            .ok_or(BodyEnvelopeError::InvalidHeader("varint overflow"))?;

        if byte & 0x80 == 0 {
            return Ok(value);
        }

        shift += 7;
    }

    Err(BodyEnvelopeError::InvalidHeader("varint too long"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_roundtrip_single_recipient() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let plain = b"hello application/foctet body";
        let envelope = seal_body(plain, recipient_pub, b"kid-1").expect("seal");
        let out = open_body(&envelope, recipient_priv.to_bytes()).expect("open");

        assert_eq!(out, plain);
    }

    #[test]
    fn open_rejects_invalid_magic() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let plain = b"hello";
        let mut envelope = seal_body(plain, recipient_pub, b"kid").expect("seal");
        envelope[0] ^= 0xFF;

        let err = open_body(&envelope, recipient_priv.to_bytes()).expect_err("must fail");
        assert_eq!(err, BodyEnvelopeError::InvalidMagic);
    }

    #[test]
    fn open_rejects_unsupported_version() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let plain = b"hello";
        let mut envelope = seal_body(plain, recipient_pub, b"kid").expect("seal");
        envelope[8] = 0xFF;

        let err = open_body(&envelope, recipient_priv.to_bytes()).expect_err("must fail");
        assert_eq!(err, BodyEnvelopeError::UnsupportedVersion(0xFF));
    }

    #[test]
    fn open_rejects_truncated_input() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let plain = b"hello";
        let envelope = seal_body(plain, recipient_pub, b"kid").expect("seal");
        let truncated = &envelope[..envelope.len() - 1];

        let err = open_body(truncated, recipient_priv.to_bytes()).expect_err("must fail");
        assert_eq!(err, BodyEnvelopeError::Truncated);
    }

    #[test]
    fn open_rejects_oversized_lengths() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let plain = b"hello";
        let envelope = seal_body(plain, recipient_pub, b"kid").expect("seal");

        let limits = BodyEnvelopeLimits {
            max_header_bytes: 16,
            ..BodyEnvelopeLimits::default()
        };

        let err = open_body_with_limits(&envelope, recipient_priv.to_bytes(), &limits)
            .expect_err("must fail");
        assert_eq!(err, BodyEnvelopeError::LimitExceeded("header_len"));
    }

    #[test]
    fn open_with_wrong_recipient_fails() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();
        let wrong_priv = StaticSecret::random_from_rng(OsRng);

        let plain = b"hello";
        let envelope = seal_body(plain, recipient_pub, b"kid").expect("seal");

        let err = open_body(&envelope, wrong_priv.to_bytes()).expect_err("must fail");
        assert_eq!(err, BodyEnvelopeError::RecipientNotFound);
    }

    #[test]
    fn malformed_wrapped_key_is_rejected() {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let plain = b"hello";
        let envelope = seal_body(plain, recipient_pub, b"kid").expect("seal");

        // Parse once to locate wrapped_key_len varint, then corrupt it from 48 to 47.
        let mut cur = 0usize;
        cur += 8 + 1 + 1 + 1 + 1;
        let _ = decode_varint(&envelope, &mut cur).expect("header_len");
        let _ = decode_varint(&envelope, &mut cur).expect("recipient_count");
        let _ = decode_varint(&envelope, &mut cur).expect("payload_len");
        cur += X25519_PUBLIC_KEY_LEN + XCHACHA_NONCE_LEN;
        let _ = decode_varint(&envelope, &mut cur).expect("key_id_len");

        let mut malformed = envelope.clone();
        malformed[cur] = 47; // wrapped_key_len varint (single-byte in this fixture)

        let err = open_body(&malformed, recipient_priv.to_bytes()).expect_err("must fail");
        assert_eq!(
            err,
            BodyEnvelopeError::InvalidHeader("invalid wrapped_key_len for v0")
        );
    }
}
