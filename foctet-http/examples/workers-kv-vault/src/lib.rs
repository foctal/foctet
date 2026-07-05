//! Zero-knowledge KV vault: a blind storage Worker.
//!
//! This Worker holds no key and never decrypts. It only moves opaque
//! `application/foctet` blobs in and out of Cloudflare KV, keyed by record id:
//!
//! - `PUT /vault/:id`    — store the request body bytes under `id`.
//! - `GET /vault/:id`    — return the stored bytes (404 if absent).
//! - `DELETE /vault/:id` — remove the record.
//!
//! Confidentiality and integrity come entirely from the client, which seals each
//! value with `foctet_core::storage::seal_storage_record` — binding the record's
//! namespace / id / version into the AEAD — before it ever reaches this Worker.
//! A compromised Worker or KV store therefore cannot read a value, nor swap one
//! record's ciphertext for another or roll back to a stale version without the
//! client's open failing.

use worker::{Context, Env, Method, Request, Response, Result, event};

#[event(fetch)]
pub async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let id = match req.path().strip_prefix("/vault/") {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return Response::error("Not Found", 404),
    };

    let kv = env.kv("VAULT_KV")?;
    match req.method() {
        Method::Put => {
            // Store opaque ciphertext; the Worker cannot read it.
            let bytes = req.bytes().await?;
            kv.put_bytes(&id, &bytes)?.execute().await?;
            Ok(Response::empty()?.with_status(204))
        }
        Method::Get => match kv.get(&id).bytes().await? {
            Some(bytes) => {
                let mut response = Response::from_bytes(bytes)?;
                response
                    .headers_mut()
                    .set("content-type", "application/foctet")?;
                Ok(response)
            }
            None => Response::error("Not Found", 404),
        },
        Method::Delete => {
            kv.delete(&id).await?;
            Ok(Response::empty()?.with_status(204))
        }
        _ => Response::error("Method Not Allowed", 405),
    }
}
