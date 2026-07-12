//! Generates seed inputs for the fuzz targets in `fuzz/fuzz_targets/`.
//!
//! Each seed is a *valid* input for its target (well-formed frames, envelopes,
//! archives, control messages) so the fuzzer starts from deep, structurally
//! meaningful states instead of discovering the wire formats from scratch.
//! The recipient/traffic keys match the fixed keys hard-coded in the fuzz
//! targets, so AEAD-open and key-unwrap paths succeed on the seeds themselves.
//!
//! Output goes to `fuzz/seeds/<target>/*.bin` (committed; CI copies them into
//! the working corpus before each run). Sealing uses random ephemerals, so
//! regenerated seeds differ byte-for-byte — that is fine; they only need to be
//! valid, not reproducible.
//!
//! Run from the workspace root:
//!
//! ```bash
//! cargo run -p foctet --example gen_fuzz_seeds
//! ```

use std::{error::Error, fs, path::PathBuf};

use foctet::{archive, core};
use x25519_dalek::{PublicKey, StaticSecret};

fn seed_dir(target: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fuzz/seeds")
        .join(target);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_seed(target: &str, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let path = seed_dir(target)?.join(format!("{name}.bin"));
    fs::write(&path, bytes)?;
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Fixed keys matching the fuzz targets.
    let body_recipient_secret = [0x42u8; 32]; // body_envelope / stream_body
    let archive_recipient_secret = [0x00u8; 32]; // archive_parser
    let traffic_ikm = [0x11u8; 32]; // datagram_message
    let traffic_salt = [0x22u8; 32];

    let body_recipient_public =
        PublicKey::from(&StaticSecret::from(body_recipient_secret)).to_bytes();
    let archive_recipient_public =
        PublicKey::from(&StaticSecret::from(archive_recipient_secret)).to_bytes();

    // ---- frame_parser: one valid encrypted data frame ----
    let keys = core::derive_traffic_keys(&traffic_ikm, &traffic_salt, 0)?;
    let data_frame = core::encrypt_frame(
        &keys,
        core::Direction::C2S,
        0,
        0,
        0,
        b"fuzz seed data frame payload",
    )?;
    write_seed("frame_parser", "data_frame", &data_frame.to_bytes())?;

    // ---- control_message + handshake: real handshake control messages ----
    let (mut initiator, client_hello) = core::Session::new_initiator_with_auth(
        core::RekeyThresholds::default(),
        core::SessionAuthConfig::unauthenticated_for_testing(),
    );
    let mut responder = core::Session::new_responder_with_auth(
        core::RekeyThresholds::default(),
        core::SessionAuthConfig::unauthenticated_for_testing(),
    );
    let server_hello = responder
        .handle_control(&client_hello)?
        .ok_or("responder must produce a server hello")?;
    initiator.handle_control(&server_hello)?;
    let prepared = initiator.prepare_rekey()?;
    let rekey = prepared.control_message().clone();
    initiator.commit_rekey(prepared)?;

    for (name, msg) in [
        ("client_hello", &client_hello),
        ("server_hello", &server_hello),
        ("rekey", &rekey),
    ] {
        let encoded = msg.encode();
        write_seed("control_message", name, &encoded)?;
        write_seed("handshake", name, &encoded)?;
    }

    // ---- body_envelope: envelope sealed to the target's fixed recipient ----
    let envelope = core::seal_body(
        b"fuzz seed body envelope plaintext",
        body_recipient_public,
        b"fuzz-seed-key-id",
    )?;
    write_seed("body_envelope", "sealed_body", &envelope)?;

    // ---- stream_body: header || chunk0 || final chunk, one wire blob ----
    let limits = core::BodyEnvelopeLimits::default();
    let (mut sealer, header) =
        core::StreamSealer::new(body_recipient_public, b"fuzz-seed-key-id", b"", &limits)?;
    let mut stream_wire = header;
    stream_wire.extend_from_slice(&sealer.seal_chunk(b"fuzz seed stream chunk zero", false)?);
    stream_wire.extend_from_slice(&sealer.seal_chunk(b"fuzz seed final chunk", true)?);
    write_seed("stream_body", "sealed_stream", &stream_wire)?;

    // ---- datagram_message: sealed datagram + message frames ----
    // The fuzz target opens with inbound = S2C, so seal with outbound = S2C.
    let dgram_keys =
        core::KeyHandle::new(core::derive_traffic_keys(&traffic_ikm, &traffic_salt, 0)?);
    let mut datagram_sealer = core::DatagramEndpoint::new(
        dgram_keys.clone(),
        core::Direction::C2S,
        core::Direction::S2C,
    );
    write_seed(
        "datagram_message",
        "sealed_datagram",
        &datagram_sealer.seal(0, 0, b"fuzz seed datagram payload")?,
    )?;
    let mut message_sealer =
        core::MessageEndpoint::new(dgram_keys, core::Direction::C2S, core::Direction::S2C);
    write_seed(
        "datagram_message",
        "sealed_message",
        &message_sealer.seal(0, 0, b"fuzz seed message payload")?,
    )?;

    // ---- archive_parser: single archive + split-archive manifest and part ----
    let (single, _meta) = archive::create_archive_from_bytes(
        b"fuzz seed archive plaintext",
        &[archive_recipient_public],
        archive::ArchiveOptions::default(),
    )?;
    write_seed("archive_parser", "single_archive", &single)?;

    let split = archive::create_split_archive_from_bytes(
        b"fuzz seed split archive plaintext",
        &[archive_recipient_public],
        archive::ArchiveOptions::default(),
        16,
    )?;
    write_seed("archive_parser", "split_manifest", &split.manifest)?;
    if let Some(part) = split.parts.first() {
        write_seed("archive_parser", "split_part", part)?;
    }

    println!("fuzz seeds generated under fuzz/seeds/");
    Ok(())
}
