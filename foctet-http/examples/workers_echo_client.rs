use foctet_http::{
    ContextBinding, ContextCarrier, DEFAULT_CONTEXT_TTL_SECS, HttpOpenOptions, HttpOpener,
    HttpSealOptions, HttpSealer,
    http::{self},
};
use reqwest::Client;
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET_KEY: [u8; 32] = [0x11; 32];
const CLIENT_SECRET_KEY: [u8; 32] = [0x22; 32];
const WORKERS_URL: &str = "http://127.0.0.1:8787/foctet";

#[tokio::main]
async fn main() {
    let client = Client::new();
    let sealer = HttpSealer::new(HttpSealOptions::new(
        demo_public_key(SERVER_SECRET_KEY),
        b"demo-server-kid",
    ));
    let opener = HttpOpener::new(HttpOpenOptions::new(CLIENT_SECRET_KEY));

    let plaintext_request = b"hello workers".to_vec();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs();
    let encrypted_request = sealer
        .seal_request_with_context(
            http::Request::builder()
                .method("POST")
                .uri(WORKERS_URL)
                .body(plaintext_request)
                .expect("build request"),
            ContextCarrier::generate(now_secs, DEFAULT_CONTEXT_TTL_SECS),
            ContextBinding::default(),
        )
        .expect("seal request");

    let mut request_builder = client.post(WORKERS_URL);
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
        .open_response(response_builder.body(body).expect("build response"))
        .expect("open response");

    println!("status: {}", decrypted_response.status());
    println!(
        "plaintext body: {}",
        String::from_utf8_lossy(decrypted_response.body())
    );

    let mut replay_builder = client.post(WORKERS_URL);
    for (name, value) in encrypted_request.headers() {
        replay_builder = replay_builder.header(name, value);
    }
    let replay = replay_builder
        .body(encrypted_request.body().clone())
        .send()
        .await
        .expect("replay request");
    let replay_status = replay.status();
    let replay_body = replay.bytes().await.expect("read replay response");
    assert_eq!(
        replay_status,
        reqwest::StatusCode::CONFLICT,
        "{replay_body:?}"
    );
    println!("replay status: {replay_status}");
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
