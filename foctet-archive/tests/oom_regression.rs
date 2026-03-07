use foctet_archive::{
    ARCHIVE_MAGIC, ArchiveError, MANIFEST_MAGIC, PROFILE_X25519_HKDF_XCHACHA20POLY1305,
    WIRE_VERSION_V0, decrypt_archive_to_bytes, decrypt_split_archive_to_bytes,
};

#[test]
fn rejects_huge_single_header_len() {
    // Regression: malformed input previously could drive huge header allocation.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&ARCHIVE_MAGIC);
    bytes.push(WIRE_VERSION_V0);
    bytes.push(PROFILE_X25519_HKDF_XCHACHA20POLY1305);
    bytes.extend_from_slice(&0u16.to_be_bytes()); // wrapped recipient table count
    bytes.extend_from_slice(&u32::MAX.to_be_bytes()); // malicious header_len

    let err = decrypt_archive_to_bytes(&bytes, [0u8; 32]).expect_err("must reject");
    assert!(matches!(
        err,
        ArchiveError::LimitExceeded("header_ciphertext_len")
    ));
}

#[test]
fn rejects_huge_manifest_part_count() {
    // Regression: malformed split manifest previously could drive huge HashMap allocation.
    let mut manifest = Vec::new();
    manifest.extend_from_slice(&MANIFEST_MAGIC);
    manifest.push(WIRE_VERSION_V0);
    manifest.push(PROFILE_X25519_HKDF_XCHACHA20POLY1305);
    manifest.extend_from_slice(&0u16.to_be_bytes()); // wrapped recipient table count
    manifest.extend_from_slice(&u32::MAX.to_be_bytes()); // malicious total_parts

    let err = decrypt_split_archive_to_bytes(&manifest, &[], [0u8; 32]).expect_err("must reject");
    assert!(matches!(err, ArchiveError::LimitExceeded("total_parts")));
}
