//! Blind KV storage for signed TEXT records. The client holds the keys and
//! verifies the writer and expected revision. These local demo routes are public.
use futures_util::StreamExt;
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
            let mut stream = req.stream()?;
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                if chunk.len() > 1024 * 1024 - bytes.len() {
                    return Response::error("Record too large", 413);
                }
                bytes.extend_from_slice(&chunk);
            }
            kv.put_bytes(&id, &bytes)?.execute().await?;
            Ok(Response::empty()?.with_status(204))
        }
        Method::Get => match kv.get(&id).bytes().await? {
            Some(bytes) => {
                let mut response = Response::from_bytes(bytes)?;
                response
                    .headers_mut()
                    .set("content-type", "text/plain; charset=utf-8")?;
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
