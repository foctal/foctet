//! Store a signed record in a blind KV service and verify it on retrieval.

use foctet_core::{BodyEnvelopeLimits, IdentityKeyPair, PeerIdentity, StorageRecord};
use foctet_storage_wire::{MAX_TEXT_BYTES, TextRecord};
use futures_util::StreamExt;
use getrandom::SysRng;
use rand_core::UnwrapErr;
use reqwest::{Client, StatusCode};
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let base = std::env::var("VAULT_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".into());
    let client = Client::new();
    let recipient = StaticSecret::random_from_rng(&mut UnwrapErr(SysRng));
    let writer = IdentityKeyPair::generate();
    let pin = PeerIdentity::new(writer.public_key());
    let limits = BodyEnvelopeLimits::default();
    let record = StorageRecord::new(b"vault-items", b"example-item", 1);
    let url = format!("{base}/vault/example-item");
    let value = TextRecord::seal(
        b"example value",
        PublicKey::from(&recipient).to_bytes(),
        b"account-v1",
        record,
        &writer,
        &limits,
    )?;
    let response = client
        .put(&url)
        .body(value.as_str().to_owned())
        .send()
        .await?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err(format!("store returned {}", response.status()).into());
    }

    let mut stream = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > MAX_TEXT_BYTES - bytes.len() {
            return Err("stored record exceeds the client budget".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let stored = TextRecord::parse(std::str::from_utf8(&bytes)?, MAX_TEXT_BYTES)?;
    let opened = stored.open(recipient.to_bytes(), record, pin, &limits)?;
    assert_eq!(opened, b"example value");
    let newer = StorageRecord::new(b"vault-items", b"example-item", 2);
    assert!(
        stored
            .open(recipient.to_bytes(), newer, pin, &limits)
            .is_err()
    );
    println!("Verified the stored record and rejected a stale revision.");
    Ok(())
}
