// Protected-context echo client: it uses the production-recommended
// `seal_request_with_context` / `open_response_with_context` path. The request
// carrier (message-id/timestamp/expiry) travels in `x-foctet-*` headers and is
// bound into the AEAD together with the method/path/query, so a captured
// request cannot be replayed onto a different route or re-sent after expiry.
//
// Only the body bytes are encrypted; the surrounding HTTP metadata stays
// visible. Authenticate the outer transport (TLS) separately.

use foctet_http::{
    BodyEnvelopeLimits, ContextBinding, ContextCarrier, DEFAULT_CONTEXT_TTL_SECS,
    DEFAULT_MAX_CLOCK_SKEW_SECS, HttpOpenOptions, HttpOpener, HttpSealOptions, HttpSealer,
    HttpStreamSealer,
    http::{self},
    unix_now_secs,
};
use reqwest::Client;
use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_SECRET_KEY: [u8; 32] = [0x11; 32];
const CLIENT_SECRET_KEY: [u8; 32] = [0x22; 32];
const SERVER_URL: &str = "http://127.0.0.1:3000/foctet";
// A different route on the same server, used by `--wrong-path` to deliver a
// request sealed for `/foctet` onto another path (the AEAD binds the path, so
// the server rejects it with 401).
const SERVER_URL_ALT: &str = "http://127.0.0.1:3000/foctet-elsewhere";
// Streaming-upload route, used by `--stream` / `--stream-truncated`.
const SERVER_URL_STREAM: &str = "http://127.0.0.1:3000/foctet-stream";

#[tokio::main]
async fn main() {
    let client = Client::new();
    let sealer = HttpSealer::new(HttpSealOptions::new(
        demo_public_key(SERVER_SECRET_KEY),
        b"demo-server-kid",
    ));
    let opener = HttpOpener::new(HttpOpenOptions::new(CLIENT_SECRET_KEY));

    // `--replay` re-sends the identical sealed request; the server's ReplayStore
    // must reject the second one with HTTP 409 (single-use message id).
    let replay = std::env::args().any(|arg| arg == "--replay");
    // `--wrong-path` posts a request sealed for `/foctet` to `/foctet-elsewhere`;
    // the path is bound into the AEAD, so the server must reject it with 401.
    let wrong_path = std::env::args().any(|arg| arg == "--wrong-path");
    // `--expired` seals with an already-elapsed expiry (fresh timestamp skew, but
    // past `expiry_secs`); the server must reject it with 401.
    let expired = std::env::args().any(|arg| arg == "--expired");
    // `--stream` uploads a chunked streaming body decrypted per chunk (200);
    // `--stream-truncated` drops the authenticated final chunk so the server
    // rejects the truncated upload with 400.
    let stream = std::env::args().any(|arg| arg == "--stream");
    let stream_truncated = std::env::args().any(|arg| arg == "--stream-truncated");
    if stream || stream_truncated {
        run_streaming(&client, stream_truncated).await;
        return;
    }

    let now = unix_now_secs();
    // For `--expired`, backdate the carrier so `now` is already past its expiry
    // while the timestamp still passes the clock-skew check.
    let carrier = if expired {
        let age = DEFAULT_CONTEXT_TTL_SECS + DEFAULT_MAX_CLOCK_SKEW_SECS + 10;
        ContextCarrier::generate(now.saturating_sub(age), DEFAULT_CONTEXT_TTL_SECS)
    } else {
        ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS)
    };
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

    // Capture the sealed request (headers + body) so we can optionally re-send the
    // exact same bytes to demonstrate replay rejection.
    let sealed_headers = encrypted_request.headers().clone();
    let sealed_body = encrypted_request.body().clone();

    let send_sealed_to = |client: &Client, url: &str| {
        let mut request_builder = client.post(url);
        for (name, value) in &sealed_headers {
            request_builder = request_builder.header(name, value);
        }
        request_builder.body(sealed_body.clone()).send()
    };
    let send_sealed = |client: &Client| send_sealed_to(client, SERVER_URL);

    // `--wrong-path` / `--expired` are single-shot negative tests: the one request
    // must be rejected with 401, and there is no encrypted response to open.
    if wrong_path || expired {
        let (label, url) = if wrong_path {
            ("wrong-path", SERVER_URL_ALT)
        } else {
            ("expired", SERVER_URL)
        };
        let response = send_sealed_to(&client, url).await.expect("send request");
        let status = response.status();
        println!("{label} status: {status}");
        if status == reqwest::StatusCode::UNAUTHORIZED {
            println!("{label} correctly rejected with 401 Unauthorized");
        } else {
            println!("UNEXPECTED: {label} was not rejected with 401");
            std::process::exit(1);
        }
        return;
    }

    let response = send_sealed(&client).await.expect("send request");

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

    if replay {
        let replayed = send_sealed(&client).await.expect("send replay");
        let replay_status = replayed.status();
        println!("replay status: {replay_status}");
        if replay_status == reqwest::StatusCode::CONFLICT {
            println!("replay correctly rejected with 409 Conflict");
        } else {
            println!("UNEXPECTED: replay was not rejected with 409");
            std::process::exit(1);
        }
    }
}

/// Uploads a chunked streaming body to `/foctet-stream`, sealing one Foctet
/// stream frame per HTTP chunk. With `truncate`, the authenticated final frame
/// is dropped so the server rejects the truncated upload with HTTP 400.
///
/// The streaming response direction is out of scope here: the server replies
/// with a plain acknowledgement, so this exercises the upload path only.
async fn run_streaming(client: &Client, truncate: bool) {
    let limits = BodyEnvelopeLimits::default();
    let now = unix_now_secs();
    let carrier = ContextCarrier::generate(now, DEFAULT_CONTEXT_TTL_SECS);

    // Build the request parts (method/path bound into the stream header), then
    // seal one frame per plaintext chunk.
    let base = http::Request::builder()
        .method("POST")
        .uri(SERVER_URL_STREAM)
        .body(())
        .expect("build request");
    let (mut parts, ()) = base.into_parts();
    let (mut sealer, header) = HttpStreamSealer::for_request(
        &parts,
        &carrier,
        ContextBinding::default(),
        demo_public_key(SERVER_SECRET_KEY),
        b"demo-server-kid",
        &limits,
    )
    .expect("stream sealer");
    carrier
        .apply_to_headers(&mut parts.headers)
        .expect("apply carrier");

    let mut frames: Vec<Vec<u8>> = vec![header];
    let plaintext_chunks: [&[u8]; 3] = [b"streamed ", b"axum ", b"upload"];
    for (index, chunk) in plaintext_chunks.iter().enumerate() {
        let is_final = index == plaintext_chunks.len() - 1;
        frames.push(sealer.seal_chunk(chunk, is_final).expect("seal chunk"));
    }
    if truncate {
        // Drop the authenticated FINAL frame so the server never sees the end.
        frames.pop();
    }

    // A stream body makes reqwest send one HTTP chunk per frame (chunked
    // transfer-encoding), so the server decrypts as chunks arrive.
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(
        frames.into_iter().map(Ok::<Vec<u8>, std::io::Error>),
    ));
    let mut request_builder = client.post(SERVER_URL_STREAM);
    for (name, value) in &parts.headers {
        request_builder = request_builder.header(name, value);
    }
    let response = request_builder
        .body(body)
        .send()
        .await
        .expect("send stream");
    let status = response.status();

    if truncate {
        println!("stream-truncated status: {status}");
        if status == reqwest::StatusCode::BAD_REQUEST {
            println!("truncated stream correctly rejected with 400 Bad Request");
        } else {
            println!("UNEXPECTED: truncated stream was not rejected with 400");
            std::process::exit(1);
        }
    } else {
        let text = response.text().await.unwrap_or_default();
        println!("stream status: {status}");
        println!("server: {text}");
        if status != reqwest::StatusCode::OK {
            println!("UNEXPECTED: stream upload was not accepted with 200");
            std::process::exit(1);
        }
    }
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
