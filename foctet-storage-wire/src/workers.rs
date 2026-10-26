//! Optional workers-rs implementations for D1 and remote libSQL over Fetch.
//! These drivers store only opaque signed TEXT. No private endpoint keys are used.
use crate::hrana::parse_pipeline;
use crate::{
    Dialect, MAX_TEXT_BYTES, Statement,
    database::{DriverError, QueryResult, TextDriver},
};
use futures_util::StreamExt;
use serde_json::json;
use std::time::Duration;
use worker::{
    AbortController, CacheMode, D1Database, Fetch, Headers, Method, Request, RequestInit,
    RequestRedirect, Url,
};
use zeroize::Zeroizing;

/// A primary D1 binding. This driver uses the base binding, not a replica session.
/// Response buffering belongs to the SDK; keep application request/record quotas.
pub struct D1Driver {
    database: D1Database,
}
impl D1Driver {
    /// Wraps a binding without applying schema changes.
    pub fn new(database: D1Database) -> Self {
        Self { database }
    }
}
impl TextDriver for D1Driver {
    fn dialect(&self) -> Dialect {
        Dialect::Libsql
    }
    async fn execute(&mut self, statement: Statement) -> Result<QueryResult, DriverError> {
        let args: Vec<_> = statement
            .args
            .iter()
            .map(|s| worker::wasm_bindgen::JsValue::from_str(s))
            .collect();
        let query = self
            .database
            .prepare(statement.sql)
            .bind(&args)
            .map_err(|_| DriverError::Failed)?;
        if statement.sql.starts_with("SELECT ") {
            let rows = query
                .raw::<String>()
                .await
                .map_err(|_| DriverError::Failed)?;
            Ok(QueryResult {
                rows,
                affected_rows: 0,
            })
        } else {
            let result = query.run().await.map_err(|_| DriverError::Failed)?;
            if !result.success() {
                return Err(DriverError::Failed);
            }
            let changes = result
                .meta()
                .map_err(|_| DriverError::Failed)?
                .and_then(|meta| meta.changes)
                .ok_or(DriverError::Failed)?;
            Ok(QueryResult {
                rows: vec![],
                affected_rows: changes as u64,
            })
        }
    }
}

/// Remote libSQL Hrana v2 through workers-rs Fetch. HTTPS is required except
/// literal loopback HTTP for local tests. Redirects, URL credentials and query
/// strings are rejected. Each statement closes its remote pipeline.
/// No Debug implementation exposes the token; Rust-owned tokens are zeroized.
pub struct LibsqlDriver {
    endpoint: Url,
    token: Zeroizing<String>,
    max_response_bytes: usize,
    timeout: Duration,
}
impl LibsqlDriver {
    /// Creates a bounded client without network I/O. `max_record_bytes` must
    /// match or exceed the AsyncTextStore record budget. Timeout covers headers
    /// and body streaming; cancellation aborts Fetch. No write is retried.
    pub fn new(
        url: &str,
        token: String,
        max_record_bytes: usize,
        timeout: Duration,
    ) -> Result<Self, DriverError> {
        let token = Zeroizing::new(token);
        if max_record_bytes == 0
            || max_record_bytes > MAX_TEXT_BYTES
            || timeout.as_millis() == 0
            || timeout > Duration::from_secs(300)
        {
            return Err(DriverError::Failed);
        }
        let url = url
            .strip_prefix("libsql://")
            .map(|rest| format!("https://{rest}"))
            .unwrap_or_else(|| url.to_owned());
        let base = Url::parse(&url).map_err(|_| DriverError::Failed)?;
        let local = matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(base.scheme() == "https" || (base.scheme() == "http" && local))
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !matches!(base.path(), "" | "/")
            || token.contains(['\r', '\n'])
        {
            return Err(DriverError::Failed);
        }
        Ok(Self {
            endpoint: base.join("/v2/pipeline").map_err(|_| DriverError::Failed)?,
            token,
            max_response_bytes: max_record_bytes + 16 * 1024,
            timeout,
        })
    }
}
struct AbortOnDrop(Option<AbortController>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(controller) = self.0.take() {
            controller.abort();
        }
    }
}
impl TextDriver for LibsqlDriver {
    fn dialect(&self) -> Dialect {
        Dialect::Libsql
    }
    async fn execute(&mut self, statement: Statement) -> Result<QueryResult, DriverError> {
        let headers = Headers::new();
        headers
            .set("content-type", "application/json")
            .map_err(|_| DriverError::Failed)?;
        if !self.token.is_empty() {
            headers
                .set("authorization", &format!("Bearer {}", self.token.as_str()))
                .map_err(|_| DriverError::Failed)?;
        }
        let args: Vec<_> = statement
            .args
            .into_iter()
            .map(|value| json!({"type":"text","value":value}))
            .collect();
        let body = json!({"requests":[{"type":"execute","stmt":{"sql":statement.sql,"args":args,"want_rows":true}},{"type":"close"}]}).to_string();
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_redirect(RequestRedirect::Manual)
            .with_cache(CacheMode::NoStore)
            .with_body(Some(body.into()));
        let request = Request::new_with_init(self.endpoint.as_str(), &init)
            .map_err(|_| DriverError::Failed)?;
        let controller = AbortController::default();
        let cancel = controller.signal();
        let deadline =
            worker::web_sys::AbortSignal::timeout_with_u32(self.timeout.as_millis() as u32);
        let signals = worker::js_sys::Array::new();
        signals.push(cancel.as_ref());
        signals.push(deadline.as_ref());
        let signal = worker::AbortSignal::from(worker::web_sys::AbortSignal::any(signals.as_ref()));
        let _guard = AbortOnDrop(Some(controller));
        {
            let mut response = Fetch::Request(request)
                .send_with_signal(&signal)
                .await
                .map_err(|_| DriverError::Failed)?;
            if response.status_code() != 200 {
                return Err(DriverError::Failed);
            }
            let mut bytes = Vec::new();
            let mut stream = response.stream().map_err(|_| DriverError::Failed)?;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| DriverError::Failed)?;
                if chunk.len() > self.max_response_bytes.saturating_sub(bytes.len()) {
                    return Err(DriverError::Failed);
                }
                bytes.extend_from_slice(&chunk);
            }
            if signal.aborted() {
                return Err(DriverError::Failed);
            }
            parse_pipeline(serde_json::from_slice(&bytes).map_err(|_| DriverError::Failed)?)
        }
    }
}
