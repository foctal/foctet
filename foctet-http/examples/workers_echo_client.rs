use foctet_http::{
    ContextBinding, ContextCarrier, DEFAULT_CONTEXT_TTL_SECS, HttpOpenOptions, HttpOpener,
    HttpSealOptions, HttpSealer,
    http::{self},
};
use reqwest::{Client, StatusCode};
use x25519_dalek::{PublicKey, StaticSecret};

// Server key generations. The Worker's opener keyring holds v2 (current) and v1
// (retiring); `retired` is a key the Worker does not hold, used to exercise
// failure handling.
const SERVER_SECRET_KEY_V1: [u8; 32] = [0x11; 32];
const SERVER_SECRET_KEY_V2: [u8; 32] = [0x33; 32];
const SERVER_SECRET_KEY_RETIRED: [u8; 32] = [0x44; 32];
const CLIENT_SECRET_KEY: [u8; 32] = [0x22; 32];
const DEFAULT_WORKERS_URL: &str = "http://127.0.0.1:8787/foctet";

/// Which server key the client seals the request to, selected by the
/// `SERVER_KEY_VERSION` environment variable.
struct ServerKeyChoice {
    public_key: [u8; 32],
    key_id: &'static [u8],
    /// Whether the Worker is expected to accept (open) this key.
    accepted: bool,
}

fn select_server_key() -> ServerKeyChoice {
    match std::env::var("SERVER_KEY_VERSION").as_deref() {
        // Retiring key: still in the Worker's keyring during the overlap window.
        Ok("v1") => ServerKeyChoice {
            public_key: demo_public_key(SERVER_SECRET_KEY_V1),
            key_id: b"server-v1",
            accepted: true,
        },
        // A key the Worker does not hold: authentication fails -> 401.
        Ok("retired") => ServerKeyChoice {
            public_key: demo_public_key(SERVER_SECRET_KEY_RETIRED),
            key_id: b"server-retired",
            accepted: false,
        },
        // Current key (default).
        _ => ServerKeyChoice {
            public_key: demo_public_key(SERVER_SECRET_KEY_V2),
            key_id: b"server-v2",
            accepted: true,
        },
    }
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Override with a deployed Worker URL to run against a real environment,
    // e.g. WORKERS_URL=https://<name>.<account>.workers.dev/foctet
    let workers_url =
        std::env::var("WORKERS_URL").unwrap_or_else(|_| DEFAULT_WORKERS_URL.to_string());
    let server_key = select_server_key();
    println!(
        "sealing to server kid={} (expected accepted={})",
        String::from_utf8_lossy(server_key.key_id),
        server_key.accepted
    );

    let client = Client::new();
    let sealer = HttpSealer::new(HttpSealOptions::new(
        server_key.public_key,
        server_key.key_id,
    ));
    let opener = HttpOpener::new(HttpOpenOptions::new(CLIENT_SECRET_KEY));

    let plaintext_request = b"hello workers".to_vec();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs();
    let ttl_secs = std::env::var("CONTEXT_TTL_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_CONTEXT_TTL_SECS);
    let mut request_carrier = ContextCarrier::generate(now_secs, ttl_secs);
    if let Ok(value) = std::env::var("FIXED_MESSAGE_ID_BYTE") {
        let byte = u8::from_str_radix(&value, 16)
            .expect("FIXED_MESSAGE_ID_BYTE must be a two-digit hexadecimal byte");
        request_carrier.message_id = [byte; 16];
    }
    let request_message_id = request_carrier.message_id;
    let encrypted_request = sealer
        .seal_request_with_context(
            http::Request::builder()
                .method("POST")
                .uri(workers_url.as_str())
                .body(plaintext_request)
                .expect("build request"),
            request_carrier,
            ContextBinding::default(),
        )
        .expect("seal request");

    if let Ok(count) = std::env::var("RACE_REQUESTS").map(|value| {
        value
            .parse::<usize>()
            .expect("RACE_REQUESTS must be an integer")
    }) {
        let responses = futures_util::future::join_all(
            (0..count).map(|_| send(&client, workers_url.as_str(), &encrypted_request)),
        )
        .await;
        let accepted = responses
            .iter()
            .filter(|response| response.status() == StatusCode::OK)
            .count();
        let replayed = responses
            .iter()
            .filter(|response| response.status() == StatusCode::CONFLICT)
            .count();
        assert_eq!(accepted, 1, "exactly one racing request must be accepted");
        assert_eq!(replayed, count - 1, "all other requests must be replays");
        println!("race accepted={accepted} replayed={replayed}");
        return;
    }

    let response = send(&client, workers_url.as_str(), &encrypted_request).await;
    let status = response.status();
    let version = response.version();
    let headers = response.headers().clone();
    let body = response.bytes().await.expect("read response body").to_vec();

    if let Ok(expected) = std::env::var("EXPECTED_STATUS") {
        let expected = expected
            .parse::<u16>()
            .expect("EXPECTED_STATUS must be an integer");
        assert_eq!(status.as_u16(), expected, "{body:?}");
        println!("status: {status} (expected)");
        return;
    }

    if !server_key.accepted {
        // Failure handling: a request sealed to a key the Worker does not hold
        // fails authentication (before the replay store) and is answered 401.
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body:?}");
        println!("status: {status} (rejected as expected)");
        let replay = send(&client, workers_url.as_str(), &encrypted_request).await;
        // Authentication runs before the replay store, so a rejected request
        // never consumes a replay slot: the retry is still 401, not 409.
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        println!("replay status: {} (still rejected)", replay.status());
        return;
    }

    let mut response_builder = http::Response::builder().status(status).version(version);
    for (name, value) in &headers {
        response_builder = response_builder.header(name, value);
    }
    let decrypted_response = opener
        .open_response_with_context(
            response_builder.body(body).expect("build response"),
            request_message_id,
            now_secs,
            DEFAULT_CONTEXT_TTL_SECS,
        )
        .expect("open response");

    println!("status: {}", decrypted_response.status());
    println!(
        "plaintext body: {}",
        String::from_utf8_lossy(decrypted_response.body())
    );

    let replay = send(&client, workers_url.as_str(), &encrypted_request).await;
    let replay_status = replay.status();
    let replay_body = replay.bytes().await.expect("read replay response");
    assert_eq!(replay_status, StatusCode::CONFLICT, "{replay_body:?}");
    println!("replay status: {replay_status}");
}

/// Sends a sealed request, copying its headers and body onto a fresh POST.
async fn send(client: &Client, url: &str, request: &http::Request<Vec<u8>>) -> reqwest::Response {
    let mut builder = client.post(url);
    for (name, value) in request.headers() {
        builder = builder.header(name, value);
    }
    builder
        .body(request.body().clone())
        .send()
        .await
        .expect("send request")
}

fn demo_public_key(secret_key: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret_key)).to_bytes()
}
