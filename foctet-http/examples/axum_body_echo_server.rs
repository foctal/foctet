// Protected-context echo server: it uses the production-recommended
// `open_request_with_context` / `seal_response_with_context` path, which binds
// the HTTP method/path/query/message-id/timestamp/expiry into the AEAD and
// enforces single use through a `ReplayStore`. A replayed request is rejected
// with HTTP 409. This demo keeps an in-memory store; deploy a durable store
// (`RedisReplayStore`) for multi-instance or serverless targets.
//
// Only the body bytes are encrypted; the surrounding HTTP metadata stays
// visible. Authenticate the outer transport (TLS) separately.

use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use foctet_http::{
    BodyEnvelopeLimits, ContextBinding, ContextCarrier, DEFAULT_CONTEXT_TTL_SECS,
    DEFAULT_MAX_CLOCK_SKEW_SECS, HttpOpenOptions, HttpSealOptions, InMemoryReplayStore,
    axum::{AxumError, AxumOpener, AxumSealer, open_request_stream},
    unix_now_secs,
};
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET_KEY: [u8; 32] = [0x11; 32];
const CLIENT_SECRET_KEY: [u8; 32] = [0x22; 32];
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Shared application state: the opener authenticates and decrypts request
/// bodies, the replay store enforces single use, and the sealer encrypts
/// responses back to the client.
struct AppState {
    opener: AxumOpener,
    sealer: AxumSealer,
    store: InMemoryReplayStore,
}

#[tokio::main]
async fn main() {
    let state = Arc::new(AppState {
        opener: AxumOpener::new(HttpOpenOptions::new(SERVER_SECRET_KEY), MAX_BODY_BYTES),
        sealer: AxumSealer::new(HttpSealOptions::new(
            demo_public_key(CLIENT_SECRET_KEY),
            b"demo-client-kid",
        )),
        store: InMemoryReplayStore::new(),
    });

    // `/foctet-elsewhere` is wired to the *same* handler purely so the client's
    // `--wrong-path` negative test can deliver a request sealed for `/foctet`
    // onto a different route: the handler still runs, but the path bound into
    // the AEAD no longer matches, so opening fails closed with HTTP 401.
    let app = Router::new()
        .route("/foctet", post(handle_foctet))
        .route("/foctet-elsewhere", post(handle_foctet))
        // Streaming-upload route: decrypts a chunked body chunk by chunk and
        // rejects a truncated upload with 400. Driven by the client's
        // `--stream` / `--stream-truncated` flags.
        .route("/foctet-stream", post(handle_foctet_stream))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("bind listener");

    println!("axum demo server listening on http://127.0.0.1:3000/foctet");
    println!("demo keys are hardcoded for local examples only. do not use in production.");
    println!(
        "this example protects HTTP bodies only. authenticate the outer transport separately."
    );

    axum::serve(listener, app).await.expect("serve app");
}

async fn handle_foctet(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, AxumError> {
    let now = unix_now_secs();

    // Authenticate the bound context, enforce freshness, then single use.
    // A replayed request returns HTTP 409 via `AxumError`'s `IntoResponse`.
    let opened = state
        .opener
        .open_request_with_context(
            request,
            &state.store,
            now,
            DEFAULT_MAX_CLOCK_SKEW_SECS,
            ContextBinding::default(),
        )
        .await?;

    // The carrier headers survive opening, so we can answer the request's
    // message id and let the client correlate the response.
    let request_carrier = ContextCarrier::from_headers(opened.headers())?;

    let transformed = opened
        .body()
        .iter()
        .map(u8::to_ascii_uppercase)
        .collect::<Vec<u8>>();

    let plaintext_response = http::Response::builder()
        .status(StatusCode::OK)
        .header("x-foctet-example", "axum")
        .body(transformed)
        .expect("build response");

    let response_carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS)
        .answering(request_carrier.message_id);
    let encrypted = state
        .sealer
        .seal_response_with_context(plaintext_response, response_carrier)?;

    Ok(encrypted)
}

/// Streaming upload handler.
///
/// `open_request_stream` reassembles the Foctet stream frames from the chunked
/// HTTP body, authenticates the bound context and enforces single use when the
/// stream header arrives, and invokes the callback per decrypted chunk without
/// buffering the whole body. If the body ends before the authenticated final
/// chunk (truncated or cancelled upload), it returns `HttpError::StreamIncomplete`,
/// which `AxumError`'s `IntoResponse` maps to HTTP 400.
async fn handle_foctet_stream(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, AxumError> {
    let now = unix_now_secs();
    let limits = BodyEnvelopeLimits::default();
    let mut chunk_count = 0usize;
    let mut total_bytes = 0usize;

    open_request_stream(
        request,
        SERVER_SECRET_KEY,
        &state.store,
        now,
        DEFAULT_MAX_CLOCK_SKEW_SECS,
        ContextBinding::default(),
        &limits,
        |plaintext| {
            chunk_count += 1;
            total_bytes += plaintext.len();
            println!(
                "stream: decrypted chunk {chunk_count} ({} bytes)",
                plaintext.len()
            );
            Ok(())
        },
    )
    .await?;

    println!("stream: reassembled {total_bytes} bytes over {chunk_count} chunks");
    Ok((
        StatusCode::OK,
        format!("received {total_bytes} bytes in {chunk_count} chunks"),
    )
        .into_response())
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
