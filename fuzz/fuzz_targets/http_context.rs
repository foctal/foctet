#![no_main]

use foctet_http::{ContextBinding, ContextCarrier, ProtectedContext, http};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut request = http::Request::builder()
        .method("POST")
        .uri("https://example.invalid/fuzz?mode=context")
        .body(())
        .expect("static request");
    let value = &data[..data.len().min(16 * 1024)];
    if let Ok(value) = http::HeaderValue::from_bytes(value) {
        request.headers_mut().append("x-fuzz-bound", value);
    }
    let carrier = ContextCarrier {
        message_id: [0x42; 16],
        timestamp_secs: 100,
        expiry_secs: 200,
        idempotency_key: std::str::from_utf8(value).ok().map(str::to_owned),
        request_message_id: None,
    };
    let (parts, _) = request.into_parts();
    let binding = ContextBinding::default().with_bound_headers(&["x-fuzz-bound"]);
    if let Ok(context) = ProtectedContext::for_request(&parts, carrier, binding) {
        let _ = context.validate_freshness(150, 5);
        let _ = context.to_aad_bytes();
    }
});
