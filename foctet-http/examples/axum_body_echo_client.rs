// Protected-context echo client: it uses the production-recommended
// `seal_request_with_context` / `open_response_with_context` path. The request
// carrier (message-id/timestamp/expiry) travels in `x-foctet-*` headers and is
// bound into the AEAD together with the method/path/query, so a captured
// request cannot be replayed onto a different route or re-sent after expiry.
//
// Only the body bytes are encrypted; the surrounding HTTP metadata stays
// visible. Authenticate the outer transport (TLS) separately.

use foctet_http::{
    ContextBinding, ContextCarrier, DEFAULT_CONTEXT_TTL_SECS, DEFAULT_MAX_CLOCK_SKEW_SECS,
    HttpOpenOptions, HttpOpener, HttpSealOptions, HttpSealer,
    http::{self},
    unix_now_secs,
};
use reqwest::Client;
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET_KEY: [u8; 32] = [0x11; 32];
const CLIENT_SECRET_KEY: [u8; 32] = [0x22; 32];
const SERVER_URL: &str = "http://127.0.0.1:3000/foctet";

#[tokio::main]
async fn main() {
    let client = Client::new();
    let sealer = HttpSealer::new(HttpSealOptions::new(
        demo_public_key(SERVER_SECRET_KEY),
        b"demo-server-kid",
    ));
    let opener = HttpOpener::new(HttpOpenOptions::new(CLIENT_SECRET_KEY));

    let now = unix_now_secs();
    let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS);
    // Remember our request id so we can confirm the response answers it.
    let request_message_id = carrier.message_id;

    let plaintext_request = b"hello axum".to_vec();
    let encrypted_request = sealer
        .seal_request_with_context(
            http::Request::builder()
                .method("POST")
                .uri(SERVER_URL)
                .body(plaintext_request)
                .expect("build request"),
            carrier,
            ContextBinding::default(),
        )
        .expect("seal request");

    let mut request_builder = client.post(SERVER_URL);
    for (name, value) in encrypted_request.headers() {
        request_builder = request_builder.header(name, value);
    }

    let response = request_builder
        .body(encrypted_request.body().clone())
        .send()
        .await
        .expect("send request");

    let status = response.status();
    let version = response.version();
    let headers = response.headers().clone();
    let body = response.bytes().await.expect("read response body").to_vec();

    let mut response_builder = http::Response::builder().status(status);
    response_builder = response_builder.version(version);

    for (name, value) in &headers {
        response_builder = response_builder.header(name, value);
    }

    let decrypted_response = opener
        .open_response_with_context(
            response_builder.body(body).expect("build response"),
            unix_now_secs(),
            DEFAULT_MAX_CLOCK_SKEW_SECS,
        )
        .expect("open response");

    // The response carrier echoes the request id it answers.
    let response_carrier =
        ContextCarrier::from_headers(decrypted_response.headers()).expect("response carrier");
    let answered = response_carrier.request_message_id == Some(request_message_id);

    println!("status: {}", decrypted_response.status());
    println!("answers our request id: {answered}");
    println!(
        "x-foctet-example: {}",
        decrypted_response
            .headers()
            .get("x-foctet-example")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<missing>")
    );
    println!(
        "x-foctet-scope: {}",
        decrypted_response
            .headers()
            .get("x-foctet-scope")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<missing>")
    );
    println!(
        "plaintext body: {}",
        String::from_utf8_lossy(decrypted_response.body())
    );
    println!("note: request path, method, and headers are still outer HTTP metadata.");
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
