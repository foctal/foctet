#![no_main]

use foctet_http::{ContextCarrier, http};
use libfuzzer_sys::fuzz_target;

// Exercises the exact carrier-header boundary used by the Workers adapter.
// The runtime-specific Durable Object storage path is covered by Wrangler E2E.
fuzz_target!(|data: &[u8]| {
    let mut headers = http::HeaderMap::new();
    let names = [
        "x-foctet-message-id",
        "x-foctet-timestamp",
        "x-foctet-expiry",
        "x-foctet-idempotency-key",
        "x-foctet-request-message-id",
    ];
    for (index, chunk) in data.chunks(32).take(names.len() * 2).enumerate() {
        if let Ok(value) = http::HeaderValue::from_bytes(chunk) {
            headers.append(names[index % names.len()], value);
        }
    }
    let _ = ContextCarrier::from_headers(&headers);
});
