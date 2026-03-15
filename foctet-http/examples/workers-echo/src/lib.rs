use foctet_http::workers::{open_worker_request, seal_worker_response_body};
use worker::{Context, Env, Error, Request, Response, Result, event};
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET_KEY: [u8; 32] = [0x11; 32];
const CLIENT_SECRET_KEY: [u8; 32] = [0x22; 32];

#[event(fetch)]
pub async fn fetch(request: Request, _env: Env, _ctx: Context) -> Result<Response> {
    if request.path() != "/foctet" {
        return Response::error("Not Found", 404);
    }

    let opened = open_worker_request(request, SERVER_SECRET_KEY)
        .await
        .map_err(|err| Error::RustError(err.to_string()))?;

    let transformed = opened
        .plaintext
        .into_iter()
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<u8>>();

    seal_worker_response_body(
        &transformed,
        demo_public_key(CLIENT_SECRET_KEY),
        b"demo-client-kid",
    )
    .map_err(|err| Error::RustError(err.to_string()))
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
