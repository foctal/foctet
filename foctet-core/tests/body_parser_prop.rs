use foctet_core::body::{open_body, seal_body};
use proptest::prelude::*;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn body_parser_corpus_fixtures_never_panic() {
    let cases: &[&[u8]] = &[
        b"",
        b"FOCTETHB",
        b"FOCTETHB\x01\x01\x00\x20\x00\x01\x00",
        b"FOCTETHB\xFF\x01\x00\x20\x00\x01\x00",
        b"FOCTETHB\x01\x01\x01\x20\x00\x01\x00",
        &[0u8; 128],
    ];

    let recipient_priv = StaticSecret::random_from_rng(OsRng);
    for data in cases {
        let _ = open_body(data, recipient_priv.to_bytes());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn body_parser_never_panics_on_random_input(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let _ = open_body(&data, recipient_priv.to_bytes());
    }

    #[test]
    fn body_seal_open_roundtrip_property(payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let recipient_priv = StaticSecret::random_from_rng(OsRng);
        let recipient_pub = PublicKey::from(&recipient_priv).to_bytes();

        let envelope = seal_body(&payload, recipient_pub, b"prop-kid").expect("seal");
        let plain = open_body(&envelope, recipient_priv.to_bytes()).expect("open");
        prop_assert_eq!(plain, payload);
    }
}
