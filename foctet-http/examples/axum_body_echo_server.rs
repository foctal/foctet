use axum::{
    Router,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use foctet_http::axum::{open_axum_request_body, seal_axum_response_body};
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET_KEY: [u8; 32] = [0x11; 32];
const CLIENT_SECRET_KEY: [u8; 32] = [0x22; 32];
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/foctet", post(handle_foctet));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("bind listener");

    println!("axum demo server listening on http://127.0.0.1:3000/foctet");
    println!("demo keys are hardcoded for local examples only. do not use in production.");

    axum::serve(listener, app).await.expect("serve app");
}

async fn handle_foctet(request: Request) -> Result<Response, StatusCode> {
    let opened = open_axum_request_body(request, SERVER_SECRET_KEY, MAX_BODY_BYTES)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let transformed = opened
        .body()
        .iter()
        .map(u8::to_ascii_uppercase)
        .collect::<Vec<u8>>();

    let plaintext_response = http::Response::builder()
        .status(StatusCode::OK)
        .header("x-foctet-example", "axum")
        .body(transformed)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let encrypted = seal_axum_response_body(
        plaintext_response,
        demo_public_key(CLIENT_SECRET_KEY),
        b"demo-client-kid",
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(encrypted.into_response())
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
