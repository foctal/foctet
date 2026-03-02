use foctet_core::{
    Direction, Frame, FrameHeader, TrafficKeys, decrypt_frame, encrypt_frame,
    frame::{PROFILE_X25519_HKDF_XCHACHA20POLY1305, flags},
    payload::{Tlv, decode_tlvs, encode_tlvs, tlv_type},
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn frame_parser_never_panics_on_random_input(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = Frame::from_bytes(&data);
    }

    #[test]
    fn frame_roundtrip_holds_for_generated_header(
        stream_id in any::<u32>(),
        seq in any::<u64>(),
        ct in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let header = FrameHeader::new(flags::ACK_REQUIRED, PROFILE_X25519_HKDF_XCHACHA20POLY1305, 7, stream_id, seq, ct.len() as u32);
        let mut bytes = Vec::with_capacity(22 + ct.len());
        bytes.extend_from_slice(&header.encode());
        bytes.extend_from_slice(&ct);

        let parsed = Frame::from_bytes(&bytes).expect("frame parse");
        prop_assert_eq!(parsed.header, header);
        prop_assert_eq!(parsed.ciphertext, ct);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_holds(
        stream_id in any::<u32>(),
        seq in any::<u64>(),
        payload in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let keys = TrafficKeys { key_id: 3, c2s: [0x11; 32], s2c: [0x22; 32] };
        let frame = encrypt_frame(&keys, Direction::C2S, 0, stream_id, seq, &payload).expect("encrypt");
        let plain = decrypt_frame(&keys, Direction::C2S, &frame).expect("decrypt");
        prop_assert_eq!(plain, payload);
    }

    #[test]
    fn tlv_parser_never_panics_and_roundtrips(
        a in proptest::collection::vec(any::<u8>(), 0..128),
        b in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let tlvs = vec![
            Tlv::application_data(&a).expect("tlv app"),
            Tlv::new(tlv_type::ACK_HINT, b.clone()).expect("tlv ack"),
        ];
        let enc = encode_tlvs(&tlvs).expect("encode tlv");
        let dec = decode_tlvs(&enc).expect("decode tlv");
        prop_assert_eq!(dec, tlvs);

        let _ = decode_tlvs(&a);
    }
}
