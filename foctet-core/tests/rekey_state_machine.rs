use foctet_core::{CoreError, RekeyThresholds, Session, SessionAuthConfig, SessionState};
use proptest::prelude::*;

fn active_pair() -> (Session, Session) {
    let auth = SessionAuthConfig::unauthenticated_for_testing();
    let (mut client, hello) =
        Session::new_initiator_with_auth(RekeyThresholds::default(), auth.clone());
    let mut server = Session::new_responder_with_auth(RekeyThresholds::default(), auth);
    let reply = server
        .handle_control(&hello)
        .expect("valid client hello")
        .expect("server reply");
    client.handle_control(&reply).expect("valid server hello");
    (client, server)
}

proptest! {
    #[test]
    fn rekey_model_never_silently_diverges(actions in prop::collection::vec(any::<u8>(), 0..64)) {
        let (mut client, mut server) = active_pair();
        for action in actions {
            if client.state() == SessionState::Closed || server.state() == SessionState::Closed {
                break;
            }
            let (sender, receiver) = if action & 1 == 0 {
                (&mut client, &mut server)
            } else {
                (&mut server, &mut client)
            };
            let Ok(prepared) = sender.prepare_rekey() else {
                continue;
            };
            let message = prepared.control_message().clone();
            match (action >> 1) % 3 {
                0 => sender.cancel_prepared_rekey(prepared).expect("proven rejection cancels"),
                1 => {
                    receiver.handle_control(&message).expect("peer applies delivered control");
                    sender.commit_rekey(prepared).expect("sender commits delivered control");
                    prop_assert_eq!(sender.active_keys().map(|keys| keys.key_id), receiver.active_keys().map(|keys| keys.key_id));
                }
                _ => {
                    sender.terminate();
                    drop(prepared);
                    prop_assert_eq!(sender.state(), SessionState::Closed);
                    prop_assert!(matches!(sender.prepare_rekey(), Err(CoreError::TransportTerminal)));
                }
            }
        }
    }
}
