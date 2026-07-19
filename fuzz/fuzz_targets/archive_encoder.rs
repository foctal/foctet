#![no_main]

use foctet_archive::{
    ArchiveBuildSecrets, ArchiveOptions, create_archive_from_bytes_with_secrets,
    create_split_archive_from_bytes_with_secrets,
};
use libfuzzer_sys::fuzz_target;
use x25519_dalek::{PublicKey, StaticSecret};

fuzz_target!(|data: &[u8]| {
    let plaintext = &data[..data.len().min(64 * 1024)];
    let recipient = PublicKey::from(&StaticSecret::from([0x31; 32])).to_bytes();
    let chunk_size = data
        .first()
        .map_or(1024, |value| usize::from(*value).max(1));
    let options = ArchiveOptions {
        chunk_size,
        file_name: Some(
            String::from_utf8_lossy(plaintext)
                .chars()
                .take(128)
                .collect(),
        ),
        content_type: Some("application/octet-stream".into()),
        created_at_unix: Some(1_700_000_000),
    };
    let secrets = ArchiveBuildSecrets {
        archive_id: [0x41; 16],
        file_id: [0x42; 16],
        dek: [0x43; 32],
        wrap_ephemeral_secret_keys: vec![[0x44; 32]],
    };
    let _ =
        create_archive_from_bytes_with_secrets(plaintext, &[recipient], options.clone(), &secrets);
    let part_size = data.get(1).map_or(4096, |value| usize::from(*value).max(1));
    let _ = create_split_archive_from_bytes_with_secrets(
        plaintext,
        &[recipient],
        options,
        part_size,
        &secrets,
    );
});
