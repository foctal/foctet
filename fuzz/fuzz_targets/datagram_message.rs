#![no_main]

use libfuzzer_sys::fuzz_target;

use foctet_core::{DatagramEndpoint, Direction, KeyHandle, MessageEndpoint, derive_traffic_keys};

// Fuzzes the datagram and message frame decoders (header parse + AEAD open) with
// fixed traffic keys.
fuzz_target!(|data: &[u8]| {
    let Ok(keys) = derive_traffic_keys(&[0x11u8; 32], &[0x22u8; 32], 0) else {
        return;
    };
    let keys = KeyHandle::new(keys);

    let mut datagram = DatagramEndpoint::dangerously_from_shared_keys_without_nonce_ownership(
        keys.clone(),
        Direction::S2C,
        Direction::C2S,
    );
    let _ = datagram.open(data);

    let mut message = MessageEndpoint::dangerously_from_shared_keys_without_nonce_ownership(
        keys,
        Direction::S2C,
        Direction::C2S,
    );
    let _ = message.open(data);
});
