#![cfg(feature = "threshold")]
use foctet_archive::{ArchiveLimits, streaming::*, threshold::*};
use foctet_core::{IdentityKeyPair, PeerIdentity};
fn bytes(value: &serde_json::Value) -> Vec<u8> {
    value
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn frozen_recovery_and_stream_vectors() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/recovery-stream-v1.json")).unwrap();
    let writer =
        IdentityKeyPair::from_secret_key_bytes(bytes(&v["writer_secret_hex"]).try_into().unwrap());
    let pin = PeerIdentity::new(writer.public_key());
    let shares: Vec<_> = v["shares_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| RecoveryShare::from_bytes(&bytes(s)).unwrap())
        .collect();
    let plain = recover_threshold_archive(
        &bytes(&v["archive_hex"]),
        shares[0].recovery_set(),
        &shares[..2],
        pin,
        &ArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(plain, bytes(&v["plaintext_hex"]));
    let file = bytes(&v["stream_hex"]);
    let mut out = Vec::new();
    decrypt_stream(
        &mut &file[..],
        &mut out,
        bytes(&v["recipient_secret_hex"]).try_into().unwrap(),
        v["context_utf8"].as_str().unwrap().as_bytes(),
        pin,
        &StreamingLimits::default(),
    )
    .unwrap();
    assert_eq!(out, plain);
}
