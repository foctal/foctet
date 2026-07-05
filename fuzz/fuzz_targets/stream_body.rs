#![no_main]

use libfuzzer_sys::fuzz_target;

use foctet_core::{BodyEnvelopeLimits, StreamFrameDecoder, StreamOpener};

// Fuzzes the streaming-body header parser and the incremental frame decoder.
fuzz_target!(|data: &[u8]| {
    let limits = BodyEnvelopeLimits::default();
    let recipient_secret_key = [0x42u8; 32];

    // Stream-header parse + content-key unwrap.
    let _ = StreamOpener::new(recipient_secret_key, data, b"", &limits);

    // Incremental frame reassembly over the same bytes.
    let mut decoder = StreamFrameDecoder::new(&limits);
    decoder.push(data);
    while let Ok(Some(_)) = decoder.decode_next() {}
});
