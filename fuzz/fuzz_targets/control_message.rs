#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzzes the control-plane message parser, which decodes attacker-controlled
// bytes from the wire (ClientHello / ServerHello / Rekey / Error).
fuzz_target!(|data: &[u8]| {
    let _ = foctet_core::ControlMessage::decode(data);
});
