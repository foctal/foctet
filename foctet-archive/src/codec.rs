use std::io::{Cursor, Read};

use crate::{
    ArchiveError, ArchiveLimits, PART_MAGIC, WrappedDek,
    types::{ManifestPartEntry, ParsedPart},
};

pub(crate) fn read_u8<R: Read>(rd: &mut R) -> Result<u8, ArchiveError> {
    let mut b = [0u8; 1];
    rd.read_exact(&mut b).map_err(|_| ArchiveError::Truncated)?;
    Ok(b[0])
}

pub(crate) fn read_u16_be<R: Read>(rd: &mut R) -> Result<u16, ArchiveError> {
    let mut b = [0u8; 2];
    rd.read_exact(&mut b).map_err(|_| ArchiveError::Truncated)?;
    Ok(u16::from_be_bytes(b))
}

pub(crate) fn read_u32_be<R: Read>(rd: &mut R) -> Result<u32, ArchiveError> {
    let mut b = [0u8; 4];
    rd.read_exact(&mut b).map_err(|_| ArchiveError::Truncated)?;
    Ok(u32::from_be_bytes(b))
}

pub(crate) fn encode_wrapped_table(
    out: &mut Vec<u8>,
    wrapped: &[WrappedDek],
) -> Result<(), ArchiveError> {
    if wrapped.len() > u16::MAX as usize {
        return Err(ArchiveError::InvalidInput("too many recipients"));
    }
    out.extend_from_slice(&(wrapped.len() as u16).to_be_bytes());
    for item in wrapped {
        if item.ciphertext.len() > u16::MAX as usize {
            return Err(ArchiveError::InvalidInput(
                "wrapped DEK ciphertext too large",
            ));
        }
        out.extend_from_slice(&item.recipient_public);
        out.extend_from_slice(&item.ephemeral_public);
        out.extend_from_slice(&item.nonce);
        out.extend_from_slice(&(item.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&item.ciphertext);
    }
    Ok(())
}

pub(crate) fn decode_wrapped_table<R: Read>(
    rd: &mut R,
    limits: &ArchiveLimits,
) -> Result<Vec<WrappedDek>, ArchiveError> {
    let wrapped_count = read_u16_be(rd)? as usize;
    if wrapped_count > limits.max_wrapped_recipients {
        return Err(ArchiveError::LimitExceeded("wrapped_recipients"));
    }
    let mut wrapped = Vec::with_capacity(wrapped_count);
    for _ in 0..wrapped_count {
        let mut recipient_public = [0u8; 32];
        let mut ephemeral_public = [0u8; 32];
        let mut nonce = [0u8; 24];
        rd.read_exact(&mut recipient_public)
            .map_err(|_| ArchiveError::Truncated)?;
        rd.read_exact(&mut ephemeral_public)
            .map_err(|_| ArchiveError::Truncated)?;
        rd.read_exact(&mut nonce)
            .map_err(|_| ArchiveError::Truncated)?;
        let ct_len = read_u16_be(rd)? as usize;
        if ct_len > limits.max_wrapped_ciphertext_len {
            return Err(ArchiveError::LimitExceeded("wrapped_ciphertext_len"));
        }
        let mut ciphertext = vec![0u8; ct_len];
        rd.read_exact(&mut ciphertext)
            .map_err(|_| ArchiveError::Truncated)?;
        wrapped.push(WrappedDek {
            recipient_public,
            ephemeral_public,
            nonce,
            ciphertext,
        });
    }
    Ok(wrapped)
}

pub(crate) fn archive_prefix_len(wrapped: &[WrappedDek]) -> usize {
    (8 + 1 + 1 + 2)
        + wrapped
            .iter()
            .map(|w| 32 + 32 + 24 + 2 + w.ciphertext.len())
            .sum::<usize>()
}

pub(crate) fn manifest_prefix_len(wrapped: &[WrappedDek], total_parts: usize) -> usize {
    archive_prefix_len(wrapped) + 4 + total_parts * (4 + 4 + 4 + 32)
}

pub(crate) fn parse_manifest_part_entries<R: Read>(
    rd: &mut R,
    total_parts: usize,
    limits: &ArchiveLimits,
) -> Result<std::collections::HashMap<u32, ManifestPartEntry>, ArchiveError> {
    if total_parts > limits.max_total_parts {
        return Err(ArchiveError::LimitExceeded("total_parts"));
    }
    let mut manifest_parts = std::collections::HashMap::with_capacity(total_parts);
    for _ in 0..total_parts {
        let part_no = read_u32_be(rd)?;
        let first_chunk_index = read_u32_be(rd)?;
        let chunk_count = read_u32_be(rd)?;
        let mut part_hash = [0u8; 32];
        rd.read_exact(&mut part_hash)
            .map_err(|_| ArchiveError::Truncated)?;
        if manifest_parts
            .insert(
                part_no,
                ManifestPartEntry {
                    part_no,
                    first_chunk_index,
                    chunk_count,
                    part_hash,
                },
            )
            .is_some()
        {
            return Err(ArchiveError::Parse);
        }
    }
    Ok(manifest_parts)
}

pub(crate) fn parse_part_file(
    part_bytes: &[u8],
    expected_version: u8,
    expected_profile: u8,
    limits: &ArchiveLimits,
) -> Result<ParsedPart, ArchiveError> {
    if part_bytes.len() > limits.max_part_bytes {
        return Err(ArchiveError::LimitExceeded("part_bytes"));
    }
    let mut rd = Cursor::new(part_bytes);

    let mut magic = [0u8; 8];
    rd.read_exact(&mut magic)
        .map_err(|_| ArchiveError::Truncated)?;
    if magic != PART_MAGIC {
        return Err(ArchiveError::InvalidMagic);
    }

    let version = read_u8(&mut rd)?;
    if version != expected_version {
        return Err(ArchiveError::UnsupportedVersion(version));
    }

    let profile = read_u8(&mut rd)?;
    if profile != expected_profile {
        return Err(ArchiveError::UnsupportedProfile(profile));
    }

    let mut archive_id = [0u8; 16];
    rd.read_exact(&mut archive_id)
        .map_err(|_| ArchiveError::Truncated)?;

    let part_no = read_u32_be(&mut rd)?;
    let first_chunk_index = read_u32_be(&mut rd)?;
    let chunk_count = read_u32_be(&mut rd)?;
    let chunk_count_usize =
        usize::try_from(chunk_count).map_err(|_| ArchiveError::LimitExceeded("part_chunks"))?;
    if chunk_count_usize > limits.max_part_chunks {
        return Err(ArchiveError::LimitExceeded("part_chunks"));
    }

    let mut chunk_ciphertexts = Vec::with_capacity(chunk_count_usize);
    for _ in 0..chunk_count {
        let len = read_u32_be(&mut rd)? as usize;
        if len > limits.max_chunk_ciphertext_len {
            return Err(ArchiveError::LimitExceeded("chunk_ciphertext_len"));
        }
        let pos = usize::try_from(rd.position()).map_err(|_| ArchiveError::Parse)?;
        let remaining = part_bytes.len().saturating_sub(pos);
        if len > remaining {
            return Err(ArchiveError::Truncated);
        }
        let mut ct = vec![0u8; len];
        rd.read_exact(&mut ct)
            .map_err(|_| ArchiveError::Truncated)?;
        chunk_ciphertexts.push(ct);
    }

    if rd.position() as usize != part_bytes.len() {
        return Err(ArchiveError::Parse);
    }

    Ok(ParsedPart {
        archive_id,
        part_no,
        first_chunk_index,
        chunk_count,
        chunk_ciphertexts,
    })
}
