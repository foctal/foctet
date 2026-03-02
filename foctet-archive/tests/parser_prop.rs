use foctet_archive::{
    ArchiveOptions, create_archive_from_bytes, create_split_archive_from_bytes,
    decrypt_archive_to_bytes, decrypt_split_archive_to_bytes,
};
use proptest::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

fn keypair_from_seed(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let sk = StaticSecret::from(seed);
    let pk = PublicKey::from(&sk).to_bytes();
    (sk.to_bytes(), pk)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn archive_decrypt_never_panics_on_random_input(
        bytes in proptest::collection::vec(any::<u8>(), 0..8192),
        key in any::<[u8; 32]>(),
    ) {
        let _ = decrypt_archive_to_bytes(&bytes, key);
    }

    #[test]
    fn split_archive_decrypt_never_panics_on_random_input(
        manifest in proptest::collection::vec(any::<u8>(), 0..4096),
        parts in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..2048), 0..8),
        key in any::<[u8; 32]>(),
    ) {
        let part_refs = parts.iter().map(|p| p.as_slice()).collect::<Vec<_>>();
        let _ = decrypt_split_archive_to_bytes(&manifest, &part_refs, key);
    }

    #[test]
    fn archive_roundtrip_holds(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        seed in any::<[u8; 32]>(),
        chunk_shift in 0u8..=6u8,
    ) {
        let (privk, pubk) = keypair_from_seed(seed);
        let chunk_size = 64usize << chunk_shift;
        let opts = ArchiveOptions {
            chunk_size,
            file_name: Some("prop.bin".into()),
            content_type: Some("application/octet-stream".into()),
            created_at_unix: Some(1_700_123_456),
        };

        let (archive, _) = create_archive_from_bytes(&payload, &[pubk], opts).expect("create archive");
        let plain = decrypt_archive_to_bytes(&archive, privk).expect("decrypt archive");
        prop_assert_eq!(plain, payload);
    }

    #[test]
    fn split_archive_roundtrip_holds(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        seed in any::<[u8; 32]>(),
        chunk_shift in 0u8..=5u8,
    ) {
        let (privk, pubk) = keypair_from_seed(seed);
        let opts = ArchiveOptions {
            chunk_size: 64usize << chunk_shift,
            file_name: Some("split-prop.bin".into()),
            content_type: Some("application/octet-stream".into()),
            created_at_unix: Some(1_700_654_321),
        };

        let split = create_split_archive_from_bytes(&payload, &[pubk], opts, 1024).expect("create split");
        let mut refs = split.parts.iter().map(|p| p.as_slice()).collect::<Vec<_>>();
        refs.reverse();

        let plain = decrypt_split_archive_to_bytes(&split.manifest, &refs, privk).expect("decrypt split");
        prop_assert_eq!(plain, payload);
    }
}
