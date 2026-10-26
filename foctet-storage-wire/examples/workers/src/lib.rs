//! Local unauthenticated regression fixture; never deploy as an application.
mod websocket;
use foctet_http::{HttpOpenOptions, workers::WorkersOpener};
use foctet_storage_wire::{
    MAX_TEXT_BYTES, TextRecord,
    database::{AsyncTextStore, TextDriver},
    workers::{D1Driver, LibsqlDriver},
};
use serde_json::{Value, json};
use worker::{Context, Env, Request, Response, Result, event};

#[cfg(not(feature = "sdk-http"))]
#[event(fetch)]
pub async fn fetch(request: Request, env: Env, _ctx: Context) -> Result<Response> {
    handle(request, env).await
}
#[cfg(feature = "sdk-http")]
#[event(fetch)]
pub async fn fetch(
    request: worker::HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<worker::HttpResponse> {
    handle(request.try_into()?, env).await?.try_into()
}
fn error<E: std::fmt::Display>(e: E) -> worker::Error {
    worker::Error::RustError(e.to_string())
}
async fn records<D: TextDriver>(driver: D, data: Value) -> Result<Response> {
    let mut store = AsyncTextStore::new(driver, 4096).map_err(error)?;
    let key = [data["key"].as_u64().unwrap_or(0) as u8; 32];
    let value = match data["action"].as_str().unwrap_or("") {
        "init" => {
            store.initialize().await.map_err(error)?;
            json!(true)
        }
        "get" => {
            let version = data["version"]
                .as_str()
                .ok_or_else(|| error("missing version"))?
                .parse()
                .map_err(error)?;
            json!(
                store
                    .get(key, version)
                    .await
                    .map_err(error)?
                    .map(|v| v.as_str().to_owned())
            )
        }
        "cas" => {
            let version = data["version"]
                .as_str()
                .map(str::parse::<u64>)
                .transpose()
                .map_err(error)?;
            let text = TextRecord::parse(
                data["text"].as_str().ok_or_else(|| error("missing text"))?,
                4096,
            )
            .map_err(error)?;
            json!(
                store
                    .compare_and_swap(key, version, &text)
                    .await
                    .map_err(error)?
            )
        }
        _ => return Response::error("Unknown action", 400),
    };
    Response::from_json(&value)
}
async fn handle(mut request: Request, env: Env) -> Result<Response> {
    if request.path() == "/websocket" {
        return websocket::check().await;
    }
    if request.path() == "/body-limit" {
        let mut limits = HttpOpenOptions::new([1; 32]);
        // Deliberately tiny aggregate input budget for the negative test.
        let body_limits = foctet_core::BodyEnvelopeLimits {
            max_header_bytes: 32,
            max_payload_len: 32,
            ..Default::default()
        };
        limits = limits.with_limits(body_limits);
        return match WorkersOpener::new(limits).open_request_body(request).await {
            Ok(_) => Response::error("Unexpected open", 500),
            Err(e) => Response::error("Rejected", e.status_code()),
        };
    }
    if request.path() == "/hyperdrive-socket" {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut socket = env.hyperdrive("DB_SOCKET")?.connect()?;
        let mut header = [0u8; 4];
        socket.read_exact(&mut header).await.map_err(error)?;
        let len =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        if header[3] != 0 || len == 0 || len > 4096 {
            return Response::error("Invalid handshake", 502);
        }
        let mut packet = vec![0; len];
        socket.read_exact(&mut packet).await.map_err(error)?;
        socket.shutdown().await.map_err(error)?;
        return Response::from_json(&json!(packet[0] == 10));
    }
    let data: Value = request.json().await?;
    if request.path() == "/verify" {
        let text = TextRecord::parse(
            data["text"].as_str().ok_or_else(|| error("missing text"))?,
            4096,
        )
        .map_err(error)?;
        let version = data["version"]
            .as_str()
            .ok_or_else(|| error("missing version"))?
            .parse()
            .map_err(error)?;
        let writer = foctet_core::IdentityKeyPair::from_secret_key_bytes([42; 32]);
        return match text.open(
            [23; 32],
            foctet_core::StorageRecord::new(b"test", b"item", version),
            foctet_core::PeerIdentity::new(writer.public_key()),
            &Default::default(),
        ) {
            Ok(plaintext) => Response::from_bytes(plaintext),
            Err(_) => Response::error("Authentication failed", 401),
        };
    }
    if request.path() == "/config" {
        let valid = LibsqlDriver::new(
            data["url"].as_str().unwrap_or(""),
            data["token"].as_str().unwrap_or("").to_owned(),
            4096,
            std::time::Duration::from_secs(3),
        )
        .is_ok();
        return Response::from_json(&json!(valid));
    }
    match data["backend"].as_str().unwrap_or("") {
        "d1" => records(D1Driver::new(env.d1("DB")?), data).await,
        "libsql" => {
            let url = env
                .var(if data["fault"] == true {
                    "LIBSQL_BAD_URL"
                } else {
                    "LIBSQL_URL"
                })?
                .to_string();
            let driver =
                LibsqlDriver::new(&url, String::new(), 4096, std::time::Duration::from_secs(3))
                    .map_err(error)?;
            records(driver, data).await
        }
        "kv" | "r2" => {
            let text = data["text"].as_str().ok_or_else(|| error("missing text"))?;
            TextRecord::parse(text, MAX_TEXT_BYTES).map_err(error)?;
            let returned = if data["backend"] == "kv" {
                let kv = env.kv("KV")?;
                kv.put("record", text)?.execute().await?;
                kv.get("record")
                    .text()
                    .await?
                    .ok_or_else(|| error("missing value"))?
            } else {
                let bucket = env.bucket("BUCKET")?;
                bucket
                    .put("record", text.as_bytes().to_vec())
                    .execute()
                    .await?;
                bucket
                    .get("record")
                    .execute()
                    .await?
                    .ok_or_else(|| error("missing object"))?
                    .body()
                    .ok_or_else(|| error("missing body"))?
                    .text()
                    .await?
            };
            Response::from_json(&returned)
        }
        _ => Response::error("Unknown backend", 400),
    }
}
