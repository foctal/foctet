#![no_main]
use foctet_archive::{
    streaming::{StreamingLimits, decrypt_stream},
    threshold::RecoveryShare,
};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    let _ = RecoveryShare::from_bytes(bytes);
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = foctet_storage_wire::TextRecord::parse(text, 4096);
    }
    let limits = StreamingLimits {
        chunk_bytes: 1024,
        total_bytes: 4096,
        frames: 8,
    };
    let writer = foctet_core::IdentityKeyPair::from_secret_key_bytes([7; 32]);
    let _ = decrypt_stream(
        &mut &bytes[..],
        &mut std::io::sink(),
        [9; 32],
        b"fuzz",
        foctet_core::PeerIdentity::new(writer.public_key()),
        &limits,
    );
});
