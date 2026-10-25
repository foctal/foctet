//! Bounded-memory, writer-authenticated streaming files (FOCTETFS version 1).
//!
//! This is a separate format from the existing in-memory archive containers.
//! Context binds application-defined filename/object/version metadata. It is not
//! embedded in the file. Extraction to a writer is provisional until success;
//! use `decrypt_stream_to_file` for atomic, non-overwriting publication.
use crate::ArchiveError;
use foctet_core::{
    BodyEnvelopeLimits, HandshakeSigner, PeerIdentity, StreamOpener, StreamSealer, sign_ciphertext,
    verify_ciphertext,
};
use std::io::{Read, Write};

const MAGIC: &[u8; 8] = b"FOCTETFS";
/// Memory and aggregate limits for a streaming archive.
#[derive(Clone, Debug)]
pub struct StreamingLimits {
    /// Plaintext chunk budget, between 1 byte and 16 MiB.
    pub chunk_bytes: usize,
    /// Maximum aggregate plaintext; default 1 TiB.
    pub total_bytes: u64,
    /// Maximum chunk frames, including the empty final frame.
    pub frames: u64,
}
impl Default for StreamingLimits {
    fn default() -> Self {
        Self {
            chunk_bytes: 1024 * 1024,
            total_bytes: 1 << 40,
            frames: 1 << 24,
        }
    }
}
impl StreamingLimits {
    fn body(&self) -> Result<BodyEnvelopeLimits, ArchiveError> {
        if self.chunk_bytes == 0 || self.chunk_bytes > 16 * 1024 * 1024 || self.frames == 0 {
            return Err(ArchiveError::InvalidInput("invalid streaming limits"));
        }
        Ok(BodyEnvelopeLimits {
            max_payload_len: self.chunk_bytes + 16,
            ..Default::default()
        })
    }
}
fn context_bytes(context: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    if context.len() > 60 * 1024 {
        return Err(ArchiveError::LimitExceeded("stream_context"));
    }
    let mut out = b"foctet signed file stream v1\0".to_vec();
    out.extend_from_slice(context);
    Ok(out)
}
fn write_record(
    out: &mut impl Write,
    bytes: &[u8],
    context: &[u8],
    signer: &dyn HandshakeSigner,
) -> Result<(), ArchiveError> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| ArchiveError::LimitExceeded("stream_record"))?;
    out.write_all(&len.to_be_bytes())?;
    out.write_all(bytes)?;
    out.write_all(&sign_ciphertext(bytes, context, signer))?;
    Ok(())
}
fn read_record(
    input: &mut impl Read,
    max: usize,
    context: &[u8],
    pin: PeerIdentity,
) -> Result<Vec<u8>, ArchiveError> {
    let mut size = [0; 4];
    input.read_exact(&mut size)?;
    let len = u32::from_be_bytes(size) as usize;
    if len > max {
        return Err(ArchiveError::LimitExceeded("stream_record"));
    }
    let mut bytes = vec![0; len];
    input.read_exact(&mut bytes)?;
    let mut signature = [0; 64];
    input.read_exact(&mut signature)?;
    verify_ciphertext(&bytes, context, signature, pin).map_err(|_| ArchiveError::Aead)?;
    Ok(bytes)
}

/// Encrypts a reader to a writer with fixed memory, fresh keys and signed chunks.
/// A failed output must be discarded. Successful return flushes the writer.
pub fn encrypt_stream(
    input: &mut impl Read,
    output: &mut impl Write,
    recipient: [u8; 32],
    context: &[u8],
    signer: &dyn HandshakeSigner,
    limits: &StreamingLimits,
) -> Result<u64, ArchiveError> {
    let body_limits = limits.body()?;
    let mut context = context_bytes(context)?;
    let (mut sealer, header) = StreamSealer::new(recipient, b"stream-v1", &context, &body_limits)?;
    output.write_all(MAGIC)?;
    output.write_all(&[1])?;
    write_record(output, &header, &context, signer)?;
    context.extend_from_slice(blake3::hash(&header).as_bytes());
    let mut buffer = zeroize::Zeroizing::new(vec![0; limits.chunk_bytes]);
    let mut total = 0u64;
    let mut eof = false;
    for _ in 0..limits.frames {
        // Fill chunks despite short reads, retaining only one plaintext chunk.
        let mut count = 0;
        while !eof && count < buffer.len() {
            match input.read(&mut buffer[count..]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => count += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        total = total
            .checked_add(count as u64)
            .filter(|&n| n <= limits.total_bytes)
            .ok_or(ArchiveError::LimitExceeded("stream_total"))?;
        let final_chunk = count == 0;
        let chunk = sealer.seal_chunk(&buffer[..count], final_chunk)?;
        write_record(output, &chunk, &context, signer)?;
        if final_chunk {
            output.flush()?;
            return Ok(total);
        }
    }
    Err(ArchiveError::LimitExceeded("stream_frames"))
}

/// Verifies and decrypts bounded chunks to a provisional destination.
/// On ANY error discard ALL output, including previously authenticated chunks.
/// Success requires a signed FINAL chunk and EOF with no trailing bytes.
pub fn decrypt_stream(
    input: &mut impl Read,
    output: &mut impl Write,
    recipient_secret: [u8; 32],
    context: &[u8],
    writer: PeerIdentity,
    limits: &StreamingLimits,
) -> Result<u64, ArchiveError> {
    let body_limits = limits.body()?;
    let mut context = context_bytes(context)?;
    let mut magic = [0; 9];
    input.read_exact(&mut magic)?;
    if &magic[..8] != MAGIC || magic[8] != 1 {
        return Err(ArchiveError::InvalidMagic);
    }
    let header = read_record(input, body_limits.max_header_bytes, &context, writer)?;
    let mut opener = StreamOpener::new(recipient_secret, &header, &context, &body_limits)?;
    context.extend_from_slice(blake3::hash(&header).as_bytes());
    let mut total = 0u64;
    for _ in 0..limits.frames {
        let chunk = read_record(
            input,
            body_limits.max_payload_len + foctet_core::STREAM_CHUNK_OVERHEAD,
            &context,
            writer,
        )?;
        let decoded = opener.open_chunk(&chunk)?;
        let plain = zeroize::Zeroizing::new(decoded.plaintext);
        total = total
            .checked_add(plain.len() as u64)
            .filter(|&n| n <= limits.total_bytes)
            .ok_or(ArchiveError::LimitExceeded("stream_total"))?;
        output.write_all(&plain)?;
        if opener.is_finished() {
            let mut trailing = [0];
            loop {
                match input.read(&mut trailing) {
                    Ok(0) => break,
                    Ok(_) => return Err(ArchiveError::Parse),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            output.flush()?;
            return Ok(total);
        }
    }
    Err(ArchiveError::LimitExceeded("stream_frames"))
}

/// Atomically publishes plaintext only after full validation and file sync.
/// Never overwrites an existing destination. Temporary files are created with
/// restrictive permissions in the destination directory and removed on failure.
/// Filesystem directory durability across power loss remains platform-dependent.
#[cfg(not(target_arch = "wasm32"))]
pub fn decrypt_stream_to_file(
    input: &mut impl Read,
    destination: &std::path::Path,
    recipient_secret: [u8; 32],
    context: &[u8],
    writer: PeerIdentity,
    limits: &StreamingLimits,
) -> Result<u64, ArchiveError> {
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    let count = decrypt_stream(
        input,
        temp.as_file_mut(),
        recipient_secret,
        context,
        writer,
        limits,
    )?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(destination)
        .map_err(|e| ArchiveError::Io(e.error))?;
    Ok(count)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    #[test]
    fn short_reads_limits_splicing_and_failed_publication() {
        struct ShortReader {
            bytes: &'static [u8],
            ended: bool,
        }
        impl Read for ShortReader {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                assert!(!self.ended, "read after observed EOF");
                let n = out.len().min(self.bytes.len()).min(2);
                out[..n].copy_from_slice(&self.bytes[..n]);
                self.bytes = &self.bytes[n..];
                self.ended = n == 0;
                Ok(n)
            }
        }
        let secret = x25519_dalek::StaticSecret::from([9; 32]);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let writer = foctet_core::IdentityKeyPair::from_secret_key_bytes([7; 32]);
        let pin = PeerIdentity::new(writer.public_key());
        let limits = StreamingLimits {
            chunk_bytes: 8,
            total_bytes: 3,
            frames: 2,
        };
        let mut sealed = Vec::new();
        encrypt_stream(
            &mut ShortReader {
                bytes: b"abc",
                ended: false,
            },
            &mut sealed,
            public,
            b"test",
            &writer,
            &limits,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output");
        for cut in 0..sealed.len() {
            assert!(
                decrypt_stream_to_file(
                    &mut &sealed[..cut],
                    &path,
                    secret.to_bytes(),
                    b"test",
                    pin,
                    &limits
                )
                .is_err()
            );
            assert!(!path.exists());
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        for small in [
            StreamingLimits {
                total_bytes: 2,
                ..limits.clone()
            },
            StreamingLimits {
                frames: 1,
                ..limits.clone()
            },
            StreamingLimits {
                chunk_bytes: 2,
                ..limits.clone()
            },
        ] {
            assert!(
                decrypt_stream(
                    &mut &sealed[..],
                    &mut Vec::new(),
                    secret.to_bytes(),
                    b"test",
                    pin,
                    &small
                )
                .is_err()
            );
        }
        let mut other = Vec::new();
        encrypt_stream(
            &mut &b"xyz"[..],
            &mut other,
            public,
            b"test",
            &writer,
            &limits,
        )
        .unwrap();
        let offset = 9 + 4 + u32::from_be_bytes(sealed[9..13].try_into().unwrap()) as usize + 64;
        sealed[offset..].copy_from_slice(&other[offset..]);
        assert!(
            decrypt_stream_to_file(
                &mut &sealed[..],
                &path,
                secret.to_bytes(),
                b"test",
                pin,
                &limits
            )
            .is_err()
        );
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn stream_roundtrip_tampering_truncation_and_atomic_publication() {
        let secret = x25519_dalek::StaticSecret::from([9; 32]);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let writer = foctet_core::IdentityKeyPair::from_secret_key_bytes([7; 32]);
        let pin = PeerIdentity::new(writer.public_key());
        let limits = StreamingLimits {
            chunk_bytes: 7,
            ..Default::default()
        };
        let mut sealed = Vec::new();
        let plain = b"a payload crossing multiple chunk boundaries";
        encrypt_stream(
            &mut &plain[..],
            &mut sealed,
            public,
            b"file/version",
            &writer,
            &limits,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream(
            &mut &sealed[..],
            &mut out,
            secret.to_bytes(),
            b"file/version",
            pin,
            &limits,
        )
        .unwrap();
        assert_eq!(out, plain);
        for cut in [0, 9, sealed.len() - 1] {
            assert!(
                decrypt_stream(
                    &mut &sealed[..cut],
                    &mut Vec::new(),
                    secret.to_bytes(),
                    b"file/version",
                    pin,
                    &limits
                )
                .is_err()
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("result");
        let mut extended = sealed.clone();
        extended.push(0);
        assert!(
            decrypt_stream_to_file(
                &mut &extended[..],
                &path,
                secret.to_bytes(),
                b"file/version",
                pin,
                &limits
            )
            .is_err()
        );
        assert!(!path.exists());
        decrypt_stream_to_file(
            &mut &sealed[..],
            &path,
            secret.to_bytes(),
            b"file/version",
            pin,
            &limits,
        )
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), plain);
        assert!(
            decrypt_stream_to_file(
                &mut &sealed[..],
                &path,
                secret.to_bytes(),
                b"file/version",
                pin,
                &limits
            )
            .is_err()
        );
        let mut corrupt = sealed;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(
            decrypt_stream(
                &mut &corrupt[..],
                &mut Vec::new(),
                secret.to_bytes(),
                b"file/version",
                pin,
                &limits
            )
            .is_err()
        );
    }
}
