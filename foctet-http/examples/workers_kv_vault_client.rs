// Zero-knowledge KV vault client.
//
// The client seals each vault item with `foctet_core::storage`, binding the
// record's namespace / id / version into the AEAD, then stores the opaque blob
// in a blind Cloudflare Workers + KV backend (see `examples/workers-kv-vault`).
// The Worker holds no key: confidentiality and record integrity live entirely
// on the client. Transport is plain HTTP here because the payload is already
// end-to-end encrypted; add TLS in production.

use foctet_core::{StorageRecord, open_storage_record, seal_storage_record};
use reqwest::{Client, StatusCode};
use x25519_dalek::{PublicKey, StaticSecret};

// Demo account key. In a real client this is derived from the user's master
// password (e.g. Argon2id) and never leaves the device.
const ACCOUNT_SECRET_KEY: [u8; 32] = [0x55; 32];
const ACCOUNT_KID: &[u8] = b"account-v1";
const NAMESPACE: &[u8] = b"vault-items";
const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8787";

#[tokio::main]
async fn main() {
    // Override with a deployed Worker URL, e.g.
    // VAULT_URL=https://<name>.<account>.workers.dev
    let base_url = std::env::var("VAULT_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    let client = Client::new();
    let account_public = PublicKey::from(&StaticSecret::from(ACCOUNT_SECRET_KEY)).to_bytes();

    let record_id = "login-github";
    let version = 1u64;
    let record = StorageRecord::new(NAMESPACE, record_id.as_bytes(), version);
    let secret = b"github password: correct horse battery staple";
    let url = format!("{base_url}/vault/{record_id}");

    // 1. Seal client-side and upload the opaque blob. The Worker never sees a key.
    let sealed = seal_storage_record(secret, account_public, ACCOUNT_KID, record).expect("seal");
    let put = client
        .put(&url)
        .body(sealed.clone())
        .send()
        .await
        .expect("put request");
    assert_eq!(put.status(), StatusCode::NO_CONTENT, "put failed");
    println!("stored {} ciphertext bytes to {url}", sealed.len());

    // 2. Fetch it back and open with the matching descriptor.
    let got = client.get(&url).send().await.expect("get request");
    assert_eq!(got.status(), StatusCode::OK, "get failed");
    let blob = got.bytes().await.expect("read body").to_vec();
    let opened = open_storage_record(&blob, ACCOUNT_SECRET_KEY, record).expect("open");
    assert_eq!(opened, secret);
    println!("opened: {}", String::from_utf8_lossy(&opened));

    // 3. Substitution defense: the same blob must not open under a different
    //    record descriptor, so a malicious store cannot answer a query for one
    //    record with another record's ciphertext.
    let wrong_record = StorageRecord::new(NAMESPACE, b"login-elsewhere", version);
    if open_storage_record(&blob, ACCOUNT_SECRET_KEY, wrong_record).is_ok() {
        println!("UNEXPECTED: blob opened under the wrong record descriptor");
        std::process::exit(1);
    }
    println!("substitution correctly rejected (wrong record id fails to open)");

    // 4. Rollback defense: the stale blob must not open under a newer expected
    //    version, so a store cannot serve an old ciphertext undetected.
    let newer_version = StorageRecord::new(NAMESPACE, record_id.as_bytes(), version + 1);
    if open_storage_record(&blob, ACCOUNT_SECRET_KEY, newer_version).is_ok() {
        println!("UNEXPECTED: stale blob opened under a newer version");
        std::process::exit(1);
    }
    println!("rollback correctly rejected (stale version fails to open)");
}
