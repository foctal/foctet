use std::{fs, path::PathBuf};

use serde_json::Value;

fn root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn load_json(name: &str) -> Value {
    let p = root_dir().join("test-vectors").join(name);
    let s = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {}: {e}", p.display()))
}

fn is_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn assert_hex_field(v: &Value, key: &str) {
    let s = v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be string"));
    assert!(
        s.len().is_multiple_of(2),
        "{key} must be even-length hex string"
    );
    assert!(is_hex(s), "{key} must be hex string");
}

fn assert_hex_len(v: &Value, key: &str, bytes: usize) {
    assert_hex_field(v, key);
    let s = v[key].as_str().expect("hex field");
    assert_eq!(s.len(), bytes * 2, "{key} must be {bytes} bytes");
}

#[test]
fn frame_vector_schema_is_valid() {
    let v = load_json("frame-v0.json");
    assert_hex_len(&v, "shared_secret_hex", 32);
    assert_hex_len(&v, "session_salt_hex", 32);
    assert_hex_field(&v, "frame_hex");
    assert_hex_field(&v, "plaintext_hex");
}

#[test]
fn handshake_vector_schema_is_valid() {
    let v = load_json("handshake-v0.json");
    for key in [
        "client_private_hex",
        "server_private_hex",
        "client_public_hex",
        "server_public_hex",
        "session_salt_hex",
        "shared_secret_hex",
        "key_c2s_hex",
        "key_s2c_hex",
    ] {
        assert_hex_len(&v, key, 32);
    }
}

#[test]
fn archive_vector_schema_is_valid() {
    let v = load_json("archive-v0.json");
    assert_hex_len(&v, "recipient_private_hex", 32);
    assert_hex_field(&v, "payload_hex");
    assert_hex_field(&v, "single_archive_hex");
    assert_hex_field(&v, "manifest_hex");

    let parts = v["parts_hex"]
        .as_array()
        .expect("parts_hex must be array of hex strings");
    assert!(!parts.is_empty(), "parts_hex must not be empty");
    for part in parts {
        let s = part.as_str().expect("each parts_hex item must be a string");
        assert!(
            s.len().is_multiple_of(2),
            "each parts_hex item must be even-length hex"
        );
        assert!(is_hex(s), "each parts_hex item must be hex");
    }
}
