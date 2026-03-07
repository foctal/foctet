use blake3::Hasher as Blake3;
use rand_core::{OsRng, RngCore};
use rkyv::rancor::Error as RkyvError;

use crate::{
    ArchiveError, ArchiveLimits, ArchiveOptions, EncryptedHeader, FileManifest,
    crypto::{aead_decrypt, aead_encrypt, chunk_nonce, header_nonce, wrap_dek},
    types::{ArchiveBuildResult, BuiltArchive, ChunkPlain, EncryptedChunkRecord},
};

pub(crate) fn build_encrypted_materials(
    plaintext: &[u8],
    recipient_public_keys: &[[u8; 32]],
    options: ArchiveOptions,
) -> Result<BuiltArchive, ArchiveError> {
    validate_inputs(recipient_public_keys, &options)?;

    let mut archive_id = [0u8; 16];
    let mut file_id = [0u8; 16];
    OsRng.fill_bytes(&mut archive_id);
    OsRng.fill_bytes(&mut file_id);

    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);

    let mut hasher = Blake3::new();
    hasher.update(plaintext);
    let overall_hash = *hasher.finalize().as_bytes();

    let total_chunks = plaintext.len().div_ceil(options.chunk_size) as u32;

    let wrapped = recipient_public_keys
        .iter()
        .map(|recipient_public| wrap_dek(&dek, *recipient_public))
        .collect::<Result<Vec<_>, _>>()?;

    let manifest = FileManifest {
        file_id,
        file_name: options.file_name,
        file_size: plaintext.len() as u64,
        chunk_size: options.chunk_size as u32,
        total_chunks,
        overall_hash,
    };

    let encrypted_header = EncryptedHeader {
        archive_id,
        created_at_unix: options.created_at_unix,
        content_type: options.content_type,
        manifest,
    };

    let header_plain = rkyv::to_bytes::<RkyvError>(&encrypted_header)
        .map_err(|_| ArchiveError::Serialize)?
        .to_vec();

    let mut chunks = Vec::with_capacity(total_chunks as usize);
    for (idx, chunk) in plaintext.chunks(options.chunk_size).enumerate() {
        let mut chunk_hasher = Blake3::new();
        chunk_hasher.update(chunk);
        let chunk_record = ChunkPlain {
            chunk_index: idx as u32,
            plain_len: chunk.len() as u32,
            payload_hash: *chunk_hasher.finalize().as_bytes(),
            payload: chunk.to_vec(),
        };
        let chunk_plain =
            rkyv::to_bytes::<RkyvError>(&chunk_record).map_err(|_| ArchiveError::Serialize)?;
        let nonce = chunk_nonce(archive_id, idx as u32);
        let chunk_ct = aead_encrypt(&dek, &nonce, &[], &chunk_plain)?;
        chunks.push(EncryptedChunkRecord {
            chunk_index: idx as u32,
            chunk_ct,
        });
    }

    Ok(BuiltArchive {
        wrapped,
        header_plain,
        chunks,
        dek,
        meta: ArchiveBuildResult {
            archive_id,
            file_id,
            file_size: plaintext.len() as u64,
            total_chunks,
        },
    })
}

pub(crate) fn decrypt_header(
    dek: &[u8; 32],
    aad_prefix: &[u8],
    header_ct: &[u8],
) -> Result<EncryptedHeader, ArchiveError> {
    let header_plain = aead_decrypt(dek, &header_nonce(), aad_prefix, header_ct)?;
    rkyv::from_bytes::<EncryptedHeader, RkyvError>(&header_plain)
        .map_err(|_| ArchiveError::Deserialize)
}

pub(crate) fn decrypt_chunk_records_with_limits(
    dek: &[u8; 32],
    header: &EncryptedHeader,
    records: &[EncryptedChunkRecord],
    limits: &ArchiveLimits,
) -> Result<Vec<u8>, ArchiveError> {
    if records.len() != header.manifest.total_chunks as usize {
        return Err(ArchiveError::Parse);
    }
    if records.len() > limits.max_total_chunks {
        return Err(ArchiveError::LimitExceeded("total_chunks"));
    }
    let file_size = usize::try_from(header.manifest.file_size)
        .map_err(|_| ArchiveError::LimitExceeded("file_size"))?;
    if file_size > limits.max_total_output_bytes {
        return Err(ArchiveError::LimitExceeded("file_size"));
    }

    let mut output = Vec::with_capacity(file_size);
    let mut overall = Blake3::new();

    for expected_index in 0..header.manifest.total_chunks {
        let rec = records
            .get(expected_index as usize)
            .ok_or(ArchiveError::Parse)?;
        if rec.chunk_index != expected_index {
            return Err(ArchiveError::Parse);
        }

        let nonce = chunk_nonce(header.archive_id, expected_index);
        let plain = aead_decrypt(dek, &nonce, &[], &rec.chunk_ct)?;
        let chunk: ChunkPlain = rkyv::from_bytes::<ChunkPlain, RkyvError>(&plain)
            .map_err(|_| ArchiveError::Deserialize)?;

        if chunk.chunk_index != expected_index {
            return Err(ArchiveError::Parse);
        }
        if chunk.payload.len() != chunk.plain_len as usize {
            return Err(ArchiveError::Parse);
        }

        let hash = blake3::hash(&chunk.payload);
        if hash.as_bytes() != &chunk.payload_hash {
            return Err(ArchiveError::Parse);
        }
        if output
            .len()
            .checked_add(chunk.payload.len())
            .ok_or(ArchiveError::LimitExceeded("file_size overflow"))?
            > limits.max_total_output_bytes
        {
            return Err(ArchiveError::LimitExceeded("file_size"));
        }

        overall.update(&chunk.payload);
        output.extend_from_slice(&chunk.payload);
    }

    if output.len() as u64 != header.manifest.file_size {
        return Err(ArchiveError::Parse);
    }

    if overall.finalize().as_bytes() != &header.manifest.overall_hash {
        return Err(ArchiveError::OverallHashMismatch);
    }

    Ok(output)
}

pub(crate) fn partition_chunks(
    chunks: &[EncryptedChunkRecord],
    target_part_size: usize,
) -> Vec<Vec<EncryptedChunkRecord>> {
    if chunks.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut current = Vec::new();
    let mut current_size = 0usize;

    for rec in chunks {
        let record_size = 4 + rec.chunk_ct.len();
        if !current.is_empty() && current_size + record_size > target_part_size {
            out.push(current);
            current = Vec::new();
            current_size = 0;
        }
        current.push(rec.clone());
        current_size += record_size;
    }

    if !current.is_empty() {
        out.push(current);
    }

    out
}

pub(crate) fn validate_inputs(
    recipient_public_keys: &[[u8; 32]],
    options: &ArchiveOptions,
) -> Result<(), ArchiveError> {
    if recipient_public_keys.is_empty() {
        return Err(ArchiveError::InvalidInput(
            "at least one recipient key is required",
        ));
    }
    if options.chunk_size == 0 {
        return Err(ArchiveError::InvalidInput(
            "chunk_size must be greater than zero",
        ));
    }
    if options.chunk_size > u32::MAX as usize {
        return Err(ArchiveError::InvalidInput("chunk_size exceeds u32 max"));
    }
    if recipient_public_keys.len() > u16::MAX as usize {
        return Err(ArchiveError::InvalidInput("too many recipients"));
    }
    Ok(())
}

pub(crate) fn ensure_version(version: u8, expected: u8) -> Result<(), ArchiveError> {
    if version != expected {
        return Err(ArchiveError::UnsupportedVersion(version));
    }
    Ok(())
}

pub(crate) fn ensure_profile(profile: u8, expected: u8) -> Result<(), ArchiveError> {
    if profile != expected {
        return Err(ArchiveError::UnsupportedProfile(profile));
    }
    Ok(())
}
