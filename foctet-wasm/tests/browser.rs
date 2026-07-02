//! In-browser integration tests for the WASM SDK.
//!
//! These run inside a real browser engine (not Node, not native), so they
//! catch wasm-runtime-only failures that native unit tests cannot — e.g. the
//! `std::time::Instant::now()` abort that once crashed the `FoctetSession`
//! handshake at runtime while every native test stayed green.
//!
//! Run headlessly from the workspace root:
//!
//! ```bash
//! wasm-pack test --headless --chrome foctet-wasm
//! ```

#![cfg(target_arch = "wasm32")]

use foctet_wasm::{
    FoctetSession, KeyPair, WasmAuthConfig, WasmIdentityKeyPair, open_body_js,
    open_body_with_context_js, seal_body_js, seal_body_with_context_js,
};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn body_envelope_roundtrip() {
    let kp = KeyPair::generate();
    let plaintext = b"browser body envelope roundtrip";

    let Ok(envelope) = seal_body_js(plaintext, &kp.public_key(), b"browser-key") else {
        panic!("seal_body failed");
    };
    let Ok(opened) = open_body_js(&envelope, &kp.secret_key()) else {
        panic!("open_body failed");
    };
    assert_eq!(opened, plaintext);
}

#[wasm_bindgen_test]
fn context_binding_is_enforced() {
    let kp = KeyPair::generate();
    let plaintext = b"browser context binding";

    let Ok(envelope) =
        seal_body_with_context_js(plaintext, &kp.public_key(), b"browser-key", b"ctx-a")
    else {
        panic!("seal_body_with_context failed");
    };

    // Wrong context must fail authentication.
    assert!(open_body_with_context_js(&envelope, &kp.secret_key(), b"ctx-b").is_err());

    // The sealing context opens.
    let Ok(opened) = open_body_with_context_js(&envelope, &kp.secret_key(), b"ctx-a") else {
        panic!("open with matching context failed");
    };
    assert_eq!(opened, plaintext);
}

/// Drives the full authenticated handshake between two in-page sessions.
fn establish(
    mut initiator: FoctetSession,
    mut responder: FoctetSession,
) -> (FoctetSession, FoctetSession) {
    let hello = initiator
        .initial_handshake_message()
        .expect("initiator hello");
    let Ok(Some(server_hello)) = responder.handle_handshake_message(&hello) else {
        panic!("responder handshake failed");
    };
    let Ok(none) = initiator.handle_handshake_message(&server_hello) else {
        panic!("initiator handshake failed");
    };
    assert!(none.is_none());
    assert!(initiator.is_established());
    assert!(responder.is_established());
    (initiator, responder)
}

#[wasm_bindgen_test]
fn authenticated_session_handshake_and_messages() {
    let client_id = WasmIdentityKeyPair::generate();
    let server_id = WasmIdentityKeyPair::generate();

    let Ok(client_auth) = WasmAuthConfig::authenticated(&client_id, &server_id.public_key()) else {
        panic!("client auth config");
    };
    let Ok(server_auth) = WasmAuthConfig::authenticated(&server_id, &client_id.public_key()) else {
        panic!("server auth config");
    };

    let (mut client, mut server) = establish(
        FoctetSession::new_initiator(&client_auth),
        FoctetSession::new_responder(&server_auth),
    );
    assert!(client.peer_authenticated());
    assert!(server.peer_authenticated());

    // Messages both ways.
    let Ok(sealed) = client.seal_message(0, 0, b"hello from the browser client") else {
        panic!("client seal failed");
    };
    let Ok(decoded) = server.open_message(&sealed) else {
        panic!("server open failed");
    };
    assert_eq!(decoded.plaintext(), b"hello from the browser client");

    let Ok(reply) = server.seal_message(0, 0, b"hello from the browser server") else {
        panic!("server seal failed");
    };
    let Ok(decoded) = client.open_message(&reply) else {
        panic!("client open failed");
    };
    assert_eq!(decoded.plaintext(), b"hello from the browser server");

    // A replayed message must be rejected.
    assert!(server.open_message(&sealed).is_err());
}

#[wasm_bindgen_test]
fn datagram_session_roundtrip() {
    let auth = WasmAuthConfig::unauthenticated_for_testing();
    let (mut client, mut server) = establish(
        FoctetSession::new_datagram_initiator(&auth, 1200),
        FoctetSession::new_datagram_responder(&auth, 1200),
    );

    let Ok(datagram) = client.seal_datagram(0, 0, b"browser datagram payload") else {
        panic!("seal_datagram failed");
    };
    let Ok(decoded) = server.open_datagram(&datagram) else {
        panic!("open_datagram failed");
    };
    assert_eq!(decoded.plaintext(), b"browser datagram payload");

    // Wrong-mode call fails: a datagram session cannot seal messages.
    assert!(client.seal_message(0, 0, b"nope").is_err());
}
