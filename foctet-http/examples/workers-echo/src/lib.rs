use foctet_http::{
    ContextBinding, DEFAULT_MAX_CLOCK_SKEW_SECS, HttpOpenOptions, HttpSealOptions,
    workers::{
        DurableObjectReplayStore, WorkersOpener, WorkersSealer, check_and_insert_in_durable_object,
        expire_durable_object_replay_entry,
    },
};
use worker::wasm_bindgen;
use worker::{
    Context, DurableObject, Env, Error, Request, Response, Result, State, durable_object, event,
};
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET_KEY: [u8; 32] = [0x11; 32];
const CLIENT_SECRET_KEY: [u8; 32] = [0x22; 32];

#[event(fetch)]
pub async fn fetch(request: Request, _env: Env, _ctx: Context) -> Result<Response> {
    if request.path() != "/foctet" {
        return Response::error("Not Found", 404);
    }

    let opener = WorkersOpener::new(HttpOpenOptions::new(SERVER_SECRET_KEY));
    let namespace = _env.durable_object("FOCTET_REPLAY")?;
    let replay_store = DurableObjectReplayStore::new(namespace, "foctet-replay-v1");
    let now_secs = worker::Date::now().as_millis() / 1_000;
    let opened = opener
        .open_request_with_async_store(
            request,
            &replay_store,
            now_secs,
            DEFAULT_MAX_CLOCK_SKEW_SECS,
            ContextBinding::default(),
        )
        .await
        .map_err(|err| Error::RustError(err.to_string()))?;

    let transformed = opened
        .into_body()
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

/// One durable object per message ID; its alarm deletes the replay marker when
/// that request's protected-context expiry is reached.
#[durable_object]
pub struct FoctetReplay {
    state: State,
}

impl DurableObject for FoctetReplay {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, request: Request) -> Result<Response> {
        check_and_insert_in_durable_object(&self.state.storage(), request).await
    }

    async fn alarm(&self) -> Result<Response> {
        expire_durable_object_replay_entry(&self.state.storage()).await
    }
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
