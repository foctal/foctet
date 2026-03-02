#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = [0u8; 32];
    let _ = foctet_archive::decrypt_archive_to_bytes(data, key);
    let _ = foctet_archive::decrypt_split_archive_to_bytes(data, &[], key);
});
