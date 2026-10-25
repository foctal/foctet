//! Public synthetic fixtures for cross-runtime integration tests. Never use these keys.
use foctet_core::{BodyEnvelopeLimits, IdentityKeyPair, StorageRecord};
use foctet_storage_wire::{Dialect, TextRecord, TextStore};
use x25519_dalek::{PublicKey, StaticSecret};
fn main() {
    let writer = IdentityKeyPair::from_secret_key_bytes([42; 32]);
    let secret = [23; 32];
    let public = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
    let records: Vec<_> = (1..=2)
        .map(|version| {
            TextRecord::seal(
                b"worker database secret",
                public,
                b"kid",
                StorageRecord::new(b"test", b"item", version),
                &writer,
                &BodyEnvelopeLimits::default(),
            )
            .unwrap()
            .as_str()
            .to_owned()
        })
        .collect();
    let store = TextStore::new(Dialect::Mysql);
    let text = TextRecord::parse(&records[1], 1024 * 1024).unwrap();
    let plan = store.compare_and_swap([0; 32], Some(1), &text).unwrap();
    println!(
        "{}",
        serde_json::json!({"records": records, "secret": secret, "writer": writer.public_key(), "sql": plan.sql, "args": plan.args})
    );
}
