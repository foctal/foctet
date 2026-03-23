use foctet_http::{
    HttpOpenOptions, HttpSealOptions,
    workers::{WorkersOpener, WorkersSealer},
};
use worker::{Context, Env, Error, Request, Response, Result, event};
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET_KEY: [u8; 32] = [0x11; 32];
const CLIENT_SECRET_KEY: [u8; 32] = [0x22; 32];

#[event(fetch)]
pub async fn fetch(request: Request, _env: Env, _ctx: Context) -> Result<Response> {
    if request.path() != "/foctet" {
        return Response::error("Not Found", 404);
    }

    let opener = WorkersOpener::new(HttpOpenOptions::new(SERVER_SECRET_KEY));
    let opened = opener
        .open_request(request)
        .await
        .map_err(|err| Error::RustError(err.to_string()))?;

    let transformed = opened
        .plaintext
        .into_iter()
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<u8>>();

    let sealer = WorkersSealer::new(HttpSealOptions::new(
        demo_public_key(CLIENT_SECRET_KEY),
        b"demo-client-kid",
    ));
    let mut response = sealer
        .seal_response_body(&transformed)
        .map_err(|err| Error::RustError(err.to_string()))?;
    response
        .headers_mut()
        .set("x-foctet-scope", "body-only")
        .map_err(|err| Error::RustError(err.to_string()))?;
    Ok(response)
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
