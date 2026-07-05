#![no_main]

use libfuzzer_sys::fuzz_target;

use foctet_core::{ControlMessage, RekeyThresholds, Session, SessionAuthConfig};

// Fuzzes the handshake/rekey state machine: any decodable control message is fed
// to a fresh responder and initiator, exercising state transitions and the
// transcript/auth checks against hostile input.
fuzz_target!(|data: &[u8]| {
    let Ok(msg) = ControlMessage::decode(data) else {
        return;
    };
    let mut responder = Session::new_responder_with_auth(
        RekeyThresholds::default(),
        SessionAuthConfig::unauthenticated_for_testing(),
    );
    let _ = responder.handle_control(&msg);

    let (mut initiator, _hello) = Session::new_initiator_with_auth(
        RekeyThresholds::default(),
        SessionAuthConfig::unauthenticated_for_testing(),
    );
    let _ = initiator.handle_control(&msg);
});
