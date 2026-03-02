use std::io::{Cursor, Read};

use crate::{
    ARCHIVE_MAGIC, ArchiveBuildResult, ArchiveError, ArchiveOptions,
    PROFILE_X25519_HKDF_XCHACHA20POLY1305, WIRE_VERSION_V0,
    build::{
        build_encrypted_materials, decrypt_chunk_records, decrypt_header, ensure_profile,
        ensure_version,
    },
    codec::{archive_prefix_len, decode_wrapped_table, encode_wrapped_table, read_u8, read_u32_be},
    crypto::{aead_encrypt, header_nonce, unwrap_dek_from_recipients},
    types::EncryptedChunkRecord,
};

/// Creates a single-file Foctet archive from plaintext bytes.
///
/// The output contains container bytes and build metadata.
pub fn create_archive_from_bytes(
    plaintext: &[u8],
    recipient_public_keys: &[[u8; 32]],
    options: ArchiveOptions,
) -> Result<(Vec<u8>, ArchiveBuildResult), ArchiveError> {
    let built = build_encrypted_materials(plaintext, recipient_public_keys, options)?;

    let mut out = Vec::with_capacity(plaintext.len() + 4096);
    out.extend_from_slice(&ARCHIVE_MAGIC);
    out.push(WIRE_VERSION_V0);
    out.push(PROFILE_X25519_HKDF_XCHACHA20POLY1305);
    encode_wrapped_table(&mut out, &built.wrapped)?;

    let aad_prefix = out.clone();
    let header_ct = aead_encrypt(
        &built.dek,
        &header_nonce(),
        &aad_prefix,
        &built.header_plain,
    )?;
    out.extend_from_slice(&(header_ct.len() as u32).to_be_bytes());
    out.extend_from_slice(&header_ct);

    for rec in &built.chunks {
        out.extend_from_slice(&(rec.chunk_ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&rec.chunk_ct);
    }

    Ok((out, built.meta))
}

/// Decrypts a single-file Foctet archive and returns the plaintext bytes.
///
/// The provided recipient private key must correspond to one of the wrapped
/// recipient public keys present in the archive.
pub fn decrypt_archive_to_bytes(
    archive_bytes: &[u8],
    recipient_private_key: [u8; 32],
) -> Result<Vec<u8>, ArchiveError> {
    let mut rd = Cursor::new(archive_bytes);

    let mut magic = [0u8; 8];
    rd.read_exact(&mut magic).map_err(|_| ArchiveError::Parse)?;
    if magic != ARCHIVE_MAGIC {
        return Err(ArchiveError::InvalidMagic);
    }

    let version = read_u8(&mut rd)?;
    ensure_version(version, WIRE_VERSION_V0)?;

    let profile = read_u8(&mut rd)?;
    ensure_profile(profile, PROFILE_X25519_HKDF_XCHACHA20POLY1305)?;

    let wrapped = decode_wrapped_table(&mut rd)?;

    let header_len = read_u32_be(&mut rd)? as usize;
    let mut header_ct = vec![0u8; header_len];
    rd.read_exact(&mut header_ct)
        .map_err(|_| ArchiveError::Parse)?;

    let dek = unwrap_dek_from_recipients(&wrapped, recipient_private_key)?;
    let aad_prefix_len = archive_prefix_len(&wrapped);
    let aad_prefix = archive_bytes
        .get(..aad_prefix_len)
        .ok_or(ArchiveError::Parse)?;

    let header = decrypt_header(&dek, aad_prefix, &header_ct)?;

    let mut chunks = Vec::with_capacity(header.manifest.total_chunks as usize);
    for idx in 0..header.manifest.total_chunks {
        let chunk_len = read_u32_be(&mut rd)? as usize;
        let mut chunk_ct = vec![0u8; chunk_len];
        rd.read_exact(&mut chunk_ct)
            .map_err(|_| ArchiveError::Parse)?;
        chunks.push(EncryptedChunkRecord {
            chunk_index: idx,
            chunk_ct,
        });
    }

    decrypt_chunk_records(&dek, &header, &chunks)
}
