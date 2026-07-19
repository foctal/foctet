#![no_main]

use foctet_core::{RekeyThresholds, Session, SessionAuthConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|operations: &[u8]| {
    let (mut client, hello) = Session::new_initiator_with_auth(
        RekeyThresholds::default(),
        SessionAuthConfig::unauthenticated_for_testing(),
    );
    let mut server = Session::new_responder_with_auth(
        RekeyThresholds::default(),
        SessionAuthConfig::unauthenticated_for_testing(),
    );
    let Ok(reply) = server.handle_control(&hello) else {
        return;
    };
    let Some(reply) = reply else {
        return;
    };
    if client.handle_control(&reply).is_err() {
        return;
    }

    for operation in operations.iter().copied().take(64) {
        let (sender, receiver) = if operation & 1 == 0 {
            (&mut client, &mut server)
        } else {
            (&mut server, &mut client)
        };
        let Ok(prepared) = sender.prepare_rekey() else {
            continue;
        };
        let control = prepared.control_message().clone();
        match (operation >> 1) % 4 {
            0 => {
                let _ = sender.cancel_prepared_rekey(prepared);
            }
            1 => {
                if receiver.handle_control(&control).is_ok() {
                    let _ = sender.commit_rekey(prepared);
                } else {
                    sender.terminate();
                }
            }
            2 => {
                // Model ambiguous delivery: the sender must become terminal.
                sender.terminate();
                drop(prepared);
            }
            _ => {
                // Duplicate/reordered controls exercise sticky terminal state.
                let _ = receiver.handle_control(&control);
                let _ = receiver.handle_control(&control);
                drop(prepared);
            }
        }
    }
});
