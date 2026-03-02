use std::{fs, path::PathBuf};

use foctet::{archive, core};
use x25519_dalek::{PublicKey, StaticSecret};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn json_line(k: &str, v: &str, comma: bool) -> String {
    if comma {
        format!("  \"{}\": \"{}\",\n", k, v)
    } else {
        format!("  \"{}\": \"{}\"\n", k, v)
    }
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out_dir = root.join("test-vectors");
    fs::create_dir_all(&out_dir).expect("create test-vectors dir");

    // frame vector
    let shared_secret = [0x11u8; 32];
    let session_salt = [0x22u8; 32];
    let keys = core::derive_traffic_keys(&shared_secret, &session_salt, 0x07).expect("derive keys");
    let plaintext = b"foctet-frame-vector-v0";
    let frame = core::encrypt_frame(
        &keys,
        core::Direction::C2S,
        core::frame::flags::ACK_REQUIRED,
        0x1122_3344,
        42,
        plaintext,
    )
    .expect("encrypt frame");
    let frame_bytes = frame.to_bytes();

    let mut frame_json = String::new();
    frame_json.push_str("{\n");
    frame_json.push_str(&json_line("shared_secret_hex", &hex(&shared_secret), true));
    frame_json.push_str(&json_line("session_salt_hex", &hex(&session_salt), true));
    frame_json.push_str(&json_line("frame_hex", &hex(&frame_bytes), true));
    frame_json.push_str(&json_line("plaintext_hex", &hex(plaintext), false));
    frame_json.push_str("}\n");
    fs::write(out_dir.join("frame-v0.json"), frame_json).expect("write frame vector");

    // handshake vector
    let client_priv = [0x31u8; 32];
    let server_priv = [0x52u8; 32];
    let client_secret = StaticSecret::from(client_priv);
    let server_secret = StaticSecret::from(server_priv);
    let client_pub = PublicKey::from(&client_secret).to_bytes();
    let server_pub = PublicKey::from(&server_secret).to_bytes();
    let shared = client_secret
        .diffie_hellman(&PublicKey::from(server_pub))
        .to_bytes();
    let hs_salt = [0xA5u8; 32];
    let hs_keys = core::derive_traffic_keys(&shared, &hs_salt, 1).expect("derive hs keys");

    let mut hs_json = String::new();
    hs_json.push_str("{\n");
    hs_json.push_str(&json_line("client_private_hex", &hex(&client_priv), true));
    hs_json.push_str(&json_line("server_private_hex", &hex(&server_priv), true));
    hs_json.push_str(&json_line("client_public_hex", &hex(&client_pub), true));
    hs_json.push_str(&json_line("server_public_hex", &hex(&server_pub), true));
    hs_json.push_str(&json_line("session_salt_hex", &hex(&hs_salt), true));
    hs_json.push_str(&json_line("shared_secret_hex", &hex(&shared), true));
    hs_json.push_str(&json_line("key_c2s_hex", &hex(&hs_keys.c2s), true));
    hs_json.push_str(&json_line("key_s2c_hex", &hex(&hs_keys.s2c), false));
    hs_json.push_str("}\n");
    fs::write(out_dir.join("handshake-v0.json"), hs_json).expect("write handshake vector");

    // archive single/split vectors
    let recipient_priv = [0x77u8; 32];
    let recipient_secret = StaticSecret::from(recipient_priv);
    let recipient_pub = PublicKey::from(&recipient_secret).to_bytes();
    let payload: Vec<u8> = (0..(32 * 1024 + 123)).map(|i| (i % 251) as u8).collect();

    let options = archive::ArchiveOptions {
        chunk_size: 128 * 1024,
        file_name: Some("vector.bin".into()),
        content_type: Some("application/octet-stream".into()),
        created_at_unix: Some(1_700_000_777),
    };

    let (single_archive, _) =
        archive::create_archive_from_bytes(&payload, &[recipient_pub], options.clone())
            .expect("create single archive");

    let split =
        archive::create_split_archive_from_bytes(&payload, &[recipient_pub], options, 10 * 1024)
            .expect("create split archive");

    let mut archive_json = String::new();
    archive_json.push_str("{\n");
    archive_json.push_str(&json_line(
        "recipient_private_hex",
        &hex(&recipient_priv),
        true,
    ));
    archive_json.push_str(&json_line("payload_hex", &hex(&payload), true));
    archive_json.push_str(&json_line(
        "single_archive_hex",
        &hex(&single_archive),
        true,
    ));
    archive_json.push_str(&json_line("manifest_hex", &hex(&split.manifest), true));
    archive_json.push_str("  \"parts_hex\": [\n");
    for (i, part) in split.parts.iter().enumerate() {
        let comma = if i + 1 == split.parts.len() { "" } else { "," };
        archive_json.push_str(&format!("    \"{}\"{}\n", hex(part), comma));
    }
    archive_json.push_str("  ]\n");
    archive_json.push_str("}\n");
    fs::write(out_dir.join("archive-v0.json"), archive_json).expect("write archive vector");

    println!("wrote vectors to {}", out_dir.display());
}
