use std::{fs, path::PathBuf};

use foctet::{archive, core};
use serde_json::Value;
use x25519_dalek::{PublicKey, StaticSecret};

fn root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn load_json(name: &str) -> Value {
    let p = root_dir().join("test-vectors").join(name);
    let s = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {}: {e}", p.display()))
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex length must be even");
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16).expect("hex hi") as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).expect("hex lo") as u8;
        out.push((hi << 4) | lo);
    }
    out
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex_decode(s);
    assert_eq!(v.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

#[test]
fn frame_vector_matches() {
    let v = load_json("frame-v0.json");
    let shared_secret = hex32(v["shared_secret_hex"].as_str().expect("shared_secret_hex"));
    let session_salt = hex32(v["session_salt_hex"].as_str().expect("session_salt_hex"));
    let frame_bytes = hex_decode(v["frame_hex"].as_str().expect("frame_hex"));
    let expected_plaintext = hex_decode(v["plaintext_hex"].as_str().expect("plaintext_hex"));

    let keys = core::derive_traffic_keys(&shared_secret, &session_salt, 0x07).expect("derive keys");
    let frame = core::Frame::from_bytes(&frame_bytes).expect("parse frame");
    frame
        .header
        .validate_v0()
        .expect("validate draft v0 header");
    assert_eq!(frame.header.magic, core::DRAFT_MAGIC);
    assert_eq!(frame.header.version, core::WIRE_VERSION_V0);
    assert_eq!(
        frame.header.profile_id,
        core::PROFILE_X25519_HKDF_XCHACHA20POLY1305
    );
    let plaintext =
        core::decrypt_frame(&keys, core::Direction::C2S, &frame).expect("decrypt frame");

    assert_eq!(plaintext, expected_plaintext);

    let mut tampered = frame_bytes.clone();
    let last = tampered
        .last_mut()
        .expect("vector frame ciphertext should not be empty");
    *last ^= 0x01;
    let tampered_frame = core::Frame::from_bytes(&tampered).expect("parse tampered frame bytes");
    let err = core::decrypt_frame(&keys, core::Direction::C2S, &tampered_frame)
        .expect_err("tampered ciphertext must fail");
    assert!(matches!(err, core::CoreError::Aead));
}

#[test]
fn handshake_vector_matches() {
    let v = load_json("handshake-v0.json");

    let client_priv = hex32(
        v["client_private_hex"]
            .as_str()
            .expect("client_private_hex"),
    );
    let server_priv = hex32(
        v["server_private_hex"]
            .as_str()
            .expect("server_private_hex"),
    );
    let expected_client_pub = hex32(v["client_public_hex"].as_str().expect("client_public_hex"));
    let expected_server_pub = hex32(v["server_public_hex"].as_str().expect("server_public_hex"));
    let session_salt = hex32(v["session_salt_hex"].as_str().expect("session_salt_hex"));
    let expected_shared = hex32(v["shared_secret_hex"].as_str().expect("shared_secret_hex"));
    let expected_c2s = hex32(v["key_c2s_hex"].as_str().expect("key_c2s_hex"));
    let expected_s2c = hex32(v["key_s2c_hex"].as_str().expect("key_s2c_hex"));

    let client_secret = StaticSecret::from(client_priv);
    let server_secret = StaticSecret::from(server_priv);
    let client_pub = PublicKey::from(&client_secret).to_bytes();
    let server_pub = PublicKey::from(&server_secret).to_bytes();
    let shared = client_secret
        .diffie_hellman(&PublicKey::from(server_pub))
        .to_bytes();

    assert_eq!(client_pub, expected_client_pub);
    assert_eq!(server_pub, expected_server_pub);
    assert_eq!(shared, expected_shared);

    let keys = core::derive_traffic_keys(&shared, &session_salt, 1).expect("derive traffic keys");
    assert_eq!(keys.c2s, expected_c2s);
    assert_eq!(keys.s2c, expected_s2c);
    assert_ne!(keys.c2s, keys.s2c, "directional keys must be different");
}

#[test]
fn archive_vectors_match() {
    let v = load_json("archive-v0.json");

    let recipient_priv = hex32(
        v["recipient_private_hex"]
            .as_str()
            .expect("recipient_private_hex"),
    );
    let payload = hex_decode(v["payload_hex"].as_str().expect("payload_hex"));
    let single_archive = hex_decode(
        v["single_archive_hex"]
            .as_str()
            .expect("single_archive_hex"),
    );
    let manifest = hex_decode(v["manifest_hex"].as_str().expect("manifest_hex"));

    let part_values = v["parts_hex"].as_array().expect("parts_hex array");
    let parts = part_values
        .iter()
        .map(|x| hex_decode(x.as_str().expect("part hex")))
        .collect::<Vec<_>>();
    let part_refs = parts.iter().map(|p| p.as_slice()).collect::<Vec<_>>();

    let dec_single =
        archive::decrypt_archive_to_bytes(&single_archive, recipient_priv).expect("decrypt single");
    assert_eq!(dec_single, payload);

    let dec_split = archive::decrypt_split_archive_to_bytes(&manifest, &part_refs, recipient_priv)
        .expect("decrypt split");
    assert_eq!(dec_split, payload);

    let mut tampered_single = single_archive.clone();
    let single_last = tampered_single
        .last_mut()
        .expect("single archive vector should not be empty");
    *single_last ^= 0x80;
    archive::decrypt_archive_to_bytes(&tampered_single, recipient_priv)
        .expect_err("tampered single archive must fail");

    let mut tampered_manifest = manifest.clone();
    let man_last = tampered_manifest
        .last_mut()
        .expect("manifest vector should not be empty");
    *man_last ^= 0x40;
    archive::decrypt_split_archive_to_bytes(&tampered_manifest, &part_refs, recipient_priv)
        .expect_err("tampered manifest must fail");
}
