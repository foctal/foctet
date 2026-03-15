use foctet_http::{
    HttpOpenOptions, HttpOpener, HttpSealOptions, HttpSealer,
    http::{self},
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

    let plaintext_request = b"hello axum".to_vec();
    let encrypted_request = sealer
        .seal_request(
            http::Request::builder()
                .method("POST")
                .uri(SERVER_URL)
                .body(plaintext_request)
                .expect("build request"),
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
        .open_response(response_builder.body(body).expect("build response"))
        .expect("open response");

    println!("status: {}", decrypted_response.status());
    println!(
        "x-foctet-example: {}",
        decrypted_response
            .headers()
            .get("x-foctet-example")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<missing>")
    );
    println!(
        "plaintext body: {}",
        String::from_utf8_lossy(decrypted_response.body())
    );
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
