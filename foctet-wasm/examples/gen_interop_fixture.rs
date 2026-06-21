//! Generates the cross-language interop fixture consumed by the Node test.
//!
//! Run with `cargo run -p foctet-wasm --example gen_interop_fixture` and save the
//! JSON output to `foctet-wasm/tests/interop_vector.json`. The Node interop test
//! opens these Rust-produced envelopes to prove wire compatibility across the
//! Rust/WASM boundary.

use foctet_core::{BodyEnvelopeLimits, seal_body, seal_body_with_context};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn main() {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    let key_id = b"interop-kid";
    let plaintext = b"hello from rust";
    let context = b"foctet-http-ctx-v1|POST|/pay";

    let envelope = seal_body(plaintext, public, key_id).expect("seal");
    let context_envelope =
        seal_body_with_context(plaintext, public, key_id, context, &BodyEnvelopeLimits::default())
            .expect("seal with context");

    println!(
        concat!(
            "{{\n",
            "  \"secret\": \"{}\",\n",
            "  \"public\": \"{}\",\n",
            "  \"key_id\": \"{}\",\n",
            "  \"plaintext\": \"{}\",\n",
            "  \"envelope\": \"{}\",\n",
            "  \"context\": \"{}\",\n",
            "  \"context_envelope\": \"{}\"\n",
            "}}"
        ),
        hex(&secret.to_bytes()),
        hex(&public),
        String::from_utf8_lossy(key_id),
        String::from_utf8_lossy(plaintext),
        hex(&envelope),
        String::from_utf8_lossy(context),
        hex(&context_envelope),
    );
}
