#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = foctet_core::Frame::from_bytes(data);
    if let Ok(tlvs) = foctet_core::payload::decode_tlvs(data) {
        let encoded = foctet_core::payload::encode_tlvs(&tlvs).unwrap();
        assert_eq!(encoded, data);
    }
});
