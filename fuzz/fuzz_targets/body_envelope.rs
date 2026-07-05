#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzzes the one-shot body-envelope parser/AEAD path with a fixed recipient key.
// Authentication will fail, but the header parsing and key-unwrap paths run over
// attacker-controlled bytes.
fuzz_target!(|data: &[u8]| {
    let recipient_secret_key = [0x42u8; 32];
    let _ = foctet_core::open_body(data, recipient_secret_key);
});
