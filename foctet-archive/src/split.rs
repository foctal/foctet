use std::{
    collections::HashMap,
    io::{Cursor, Read},
};

use crate::{
    ArchiveError, ArchiveLimits, ArchiveOptions, MANIFEST_MAGIC, PART_MAGIC,
    PROFILE_X25519_HKDF_XCHACHA20POLY1305, SplitArchive, WIRE_VERSION_V0,
    build::{
        build_encrypted_materials, decrypt_header, ensure_profile, ensure_version, partition_chunks,
    },
    codec::{
        decode_wrapped_table, encode_wrapped_table, manifest_prefix_len,
        parse_manifest_part_entries, parse_part_file, read_u8, read_u32_be,
    },
    crypto::{aead_encrypt, header_nonce, unwrap_dek_from_recipients},
    types::{EncryptedChunkRecord, ManifestPartEntry},
};

/// Creates split-archive outputs (`manifest.far` and `data.partNNN.far`) from plaintext bytes.
pub fn create_split_archive_from_bytes(
    plaintext: &[u8],
    recipient_public_keys: &[[u8; 32]],
    options: ArchiveOptions,
    target_part_size: usize,
) -> Result<SplitArchive, ArchiveError> {
    if target_part_size == 0 {
        return Err(ArchiveError::InvalidInput(
            "target_part_size must be greater than zero",
        ));
    }

    let built = build_encrypted_materials(plaintext, recipient_public_keys, options)?;
    let part_groups = partition_chunks(&built.chunks, target_part_size);

    let mut part_entries = Vec::with_capacity(part_groups.len());
    let mut parts = Vec::with_capacity(part_groups.len());

    for (part_no, group) in part_groups.iter().enumerate() {
        let part_no_u32 = part_no as u32;
        let first_chunk_index = group.first().map(|c| c.chunk_index).unwrap_or(0);
        let chunk_count = group.len() as u32;

        let mut part_bytes = Vec::new();
        part_bytes.extend_from_slice(&PART_MAGIC);
        part_bytes.push(WIRE_VERSION_V0);
        part_bytes.push(PROFILE_X25519_HKDF_XCHACHA20POLY1305);
        part_bytes.extend_from_slice(&built.meta.archive_id);
        part_bytes.extend_from_slice(&part_no_u32.to_be_bytes());
        part_bytes.extend_from_slice(&first_chunk_index.to_be_bytes());
        part_bytes.extend_from_slice(&chunk_count.to_be_bytes());

        for rec in group {
            part_bytes.extend_from_slice(&(rec.chunk_ct.len() as u32).to_be_bytes());
            part_bytes.extend_from_slice(&rec.chunk_ct);
        }

        let part_hash = *blake3::hash(&part_bytes).as_bytes();
        part_entries.push(ManifestPartEntry {
            part_no: part_no_u32,
            first_chunk_index,
            chunk_count,
            part_hash,
        });
        parts.push(part_bytes);
    }

    let mut manifest = Vec::with_capacity(4096 + part_entries.len() * (4 + 4 + 4 + 32));
    manifest.extend_from_slice(&MANIFEST_MAGIC);
    manifest.push(WIRE_VERSION_V0);
    manifest.push(PROFILE_X25519_HKDF_XCHACHA20POLY1305);
    encode_wrapped_table(&mut manifest, &built.wrapped)?;
    manifest.extend_from_slice(&(part_entries.len() as u32).to_be_bytes());

    for entry in &part_entries {
        manifest.extend_from_slice(&entry.part_no.to_be_bytes());
        manifest.extend_from_slice(&entry.first_chunk_index.to_be_bytes());
        manifest.extend_from_slice(&entry.chunk_count.to_be_bytes());
        manifest.extend_from_slice(&entry.part_hash);
    }

    let aad_prefix = manifest.clone();
    let header_ct = aead_encrypt(
        &built.dek,
        &header_nonce(),
        &aad_prefix,
        &built.header_plain,
    )?;
    manifest.extend_from_slice(&(header_ct.len() as u32).to_be_bytes());
    manifest.extend_from_slice(&header_ct);

    Ok(SplitArchive {
        manifest,
        parts,
        meta: built.meta,
    })
}

/// Decrypts split-archive data from a manifest file and part files.
///
/// Part files may be provided in any order as long as all required parts are
/// present and unmodified.
pub fn decrypt_split_archive_to_bytes(
    manifest_bytes: &[u8],
    part_files: &[&[u8]],
    recipient_private_key: [u8; 32],
) -> Result<Vec<u8>, ArchiveError> {
    decrypt_split_archive_to_bytes_with_limits(
        manifest_bytes,
        part_files,
        recipient_private_key,
        &ArchiveLimits::default(),
    )
}

/// Decrypts split-archive data with explicit parser limits.
pub fn decrypt_split_archive_to_bytes_with_limits(
    manifest_bytes: &[u8],
    part_files: &[&[u8]],
    recipient_private_key: [u8; 32],
    limits: &ArchiveLimits,
) -> Result<Vec<u8>, ArchiveError> {
    if manifest_bytes.len() > limits.max_manifest_bytes {
        return Err(ArchiveError::LimitExceeded("manifest_bytes"));
    }

    let mut rd = Cursor::new(manifest_bytes);

    let mut magic = [0u8; 8];
    rd.read_exact(&mut magic)
        .map_err(|_| ArchiveError::Truncated)?;
    if magic != MANIFEST_MAGIC {
        return Err(ArchiveError::InvalidMagic);
    }

    let version = read_u8(&mut rd)?;
    ensure_version(version, WIRE_VERSION_V0)?;

    let profile = read_u8(&mut rd)?;
    ensure_profile(profile, PROFILE_X25519_HKDF_XCHACHA20POLY1305)?;

    let wrapped = decode_wrapped_table(&mut rd, limits)?;

    let total_parts = read_u32_be(&mut rd)? as usize;
    if total_parts > limits.max_total_parts {
        return Err(ArchiveError::LimitExceeded("total_parts"));
    }
    let manifest_parts = parse_manifest_part_entries(&mut rd, total_parts, limits)?;

    let header_len = read_u32_be(&mut rd)? as usize;
    if header_len > limits.max_header_ciphertext_len {
        return Err(ArchiveError::LimitExceeded("header_ciphertext_len"));
    }
    let manifest_remaining = manifest_bytes.len().saturating_sub(rd.position() as usize);
    if header_len > manifest_remaining {
        return Err(ArchiveError::Truncated);
    }
    let mut header_ct = vec![0u8; header_len];
    rd.read_exact(&mut header_ct)
        .map_err(|_| ArchiveError::Truncated)?;

    let dek = unwrap_dek_from_recipients(&wrapped, recipient_private_key)?;
    let aad_prefix_len = manifest_prefix_len(&wrapped, total_parts);
    if aad_prefix_len > manifest_bytes.len() {
        return Err(ArchiveError::Parse);
    }
    let aad_prefix = manifest_bytes
        .get(..aad_prefix_len)
        .ok_or(ArchiveError::Parse)?;
    let header = decrypt_header(&dek, aad_prefix, &header_ct)?;
    let total_chunks = header.manifest.total_chunks as usize;
    if total_chunks > limits.max_total_chunks {
        return Err(ArchiveError::LimitExceeded("total_chunks"));
    }

    if part_files.len() != total_parts {
        return Err(ArchiveError::InvalidInput(
            "provided part count does not match manifest",
        ));
    }

    let mut seen_part = HashMap::with_capacity(total_parts);
    let mut chunks_by_index: HashMap<u32, Vec<u8>> = HashMap::new();

    for part in part_files {
        let parsed = parse_part_file(
            part,
            WIRE_VERSION_V0,
            PROFILE_X25519_HKDF_XCHACHA20POLY1305,
            limits,
        )?;
        if parsed.archive_id != header.archive_id {
            return Err(ArchiveError::Parse);
        }

        if seen_part.insert(parsed.part_no, ()).is_some() {
            return Err(ArchiveError::DuplicatePart(parsed.part_no));
        }

        let expected = manifest_parts
            .get(&parsed.part_no)
            .ok_or(ArchiveError::MissingPart(parsed.part_no))?;

        if expected.first_chunk_index != parsed.first_chunk_index
            || expected.chunk_count != parsed.chunk_count
        {
            return Err(ArchiveError::Parse);
        }

        let digest = blake3::hash(part);
        if digest.as_bytes() != &expected.part_hash {
            return Err(ArchiveError::PartHashMismatch);
        }

        for (offset, ct) in parsed.chunk_ciphertexts.into_iter().enumerate() {
            let idx = parsed
                .first_chunk_index
                .checked_add(offset as u32)
                .ok_or(ArchiveError::Parse)?;
            if idx >= header.manifest.total_chunks {
                return Err(ArchiveError::Parse);
            }
            chunks_by_index.insert(idx, ct);
        }
    }

    for part_no in manifest_parts.keys() {
        if !seen_part.contains_key(part_no) {
            return Err(ArchiveError::MissingPart(*part_no));
        }
    }

    let mut ordered_chunks = Vec::with_capacity(total_chunks);
    for idx in 0..header.manifest.total_chunks {
        let ct = chunks_by_index.remove(&idx).ok_or(ArchiveError::Parse)?;
        ordered_chunks.push(EncryptedChunkRecord {
            chunk_index: idx,
            chunk_ct: ct,
        });
    }

    crate::build::decrypt_chunk_records_with_limits(&dek, &header, &ordered_chunks, limits)
}
