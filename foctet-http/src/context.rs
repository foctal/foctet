//! Versioned HTTP protected-context schema.
//!
//! A Foctet body envelope on its own is a stateless, replayable one-shot
//! ciphertext: opening it only proves the bytes were sealed for the recipient,
//! not *which request* they belonged to. This module binds the surrounding HTTP
//! context into the envelope's AEAD associated data (via
//! [`foctet_core::seal_body_with_context`] / [`foctet_core::open_body_with_context`])
//! so a captured envelope cannot be replayed onto a different request or
//! operation, and pairs it with a [`crate::ReplayStore`] for single-use
//! enforcement.
//!
//! # What is bound
//!
//! The associated data authenticates a canonical, domain-separated,
//! length-delimited encoding of:
//!
//! - protocol label + version + direction (request vs response),
//! - method, path, query (and optionally authority),
//! - response status (responses only),
//! - a sender-chosen unique message ID, timestamp, and expiry,
//! - an optional idempotency key,
//! - for responses, the request message ID it answers.
//!
//! Method/path/query/status are derived from the HTTP message itself, so they
//! are not transmitted as extra fields; the sender-chosen carrier values
//! (message ID, timestamp, expiry, idempotency key) travel in `x-foctet-*`
//! headers. The opener recomputes the same associated data from the received
//! message plus the carrier headers; any mismatch fails authentication.
//!
//! Time is always supplied by the caller (`now_secs`) so this module is usable
//! on `wasm32` targets such as Cloudflare Workers where `SystemTime` is
//! unavailable.

use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};

use crate::HttpError;

/// Domain-separation label and version for the protected-context encoding.
pub const CONTEXT_DOMAIN_V1: &[u8] = b"foctet-http-ctx-v1";

/// Header carrying the hex-encoded 16-byte message ID.
pub const MSG_ID_HEADER: &str = "x-foctet-msg-id";
/// Header carrying the decimal Unix-seconds timestamp.
pub const TIMESTAMP_HEADER: &str = "x-foctet-timestamp";
/// Header carrying the decimal Unix-seconds absolute expiry.
pub const EXPIRY_HEADER: &str = "x-foctet-expiry";
/// Header carrying an optional application idempotency key.
pub const IDEMPOTENCY_HEADER: &str = "x-foctet-idempotency-key";
/// Response-only header carrying the hex-encoded request message ID answered.
pub const REQUEST_MSG_ID_HEADER: &str = "x-foctet-req-msg-id";

/// Length of the random message ID in bytes.
pub const MESSAGE_ID_LEN: usize = 16;

/// Suggested default protected-context time-to-live, in seconds.
pub const DEFAULT_CONTEXT_TTL_SECS: u64 = 300;

/// Suggested default tolerance for clock skew between peers, in seconds.
pub const DEFAULT_MAX_CLOCK_SKEW_SECS: u64 = 30;

/// Direction discriminator bound into the associated data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextDirection {
    /// Client-to-server request.
    Request,
    /// Server-to-client response.
    Response,
}

impl ContextDirection {
    fn tag(self) -> u8 {
        match self {
            ContextDirection::Request => 1,
            ContextDirection::Response => 2,
        }
    }
}

/// Controls which optional, mismatch-prone fields are bound.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContextBinding {
    /// Bind the request/response authority (host\[:port\]) into the context.
    ///
    /// Off by default: the authority a client places in the request URI and the
    /// authority a server reconstructs (from the `Host` header) frequently
    /// differ, which would cause spurious authentication failures. Enable only
    /// when both peers are guaranteed to derive byte-identical, normalized
    /// authorities. Method, path, query, message ID, and expiry already prevent
    /// route substitution and replay without it.
    pub bind_authority: bool,
    /// Header names to additionally bind into the request context, in this
    /// order. Each header's presence and raw value bytes are authenticated,
    /// so adding, removing, or modifying a bound header fails authentication.
    /// Only the header's *first* value is bound (multi-value headers are not
    /// disambiguated). Empty by default — preserves the exact associated-data
    /// bytes of a [`ContextBinding`] that doesn't bind any headers, so this is
    /// purely opt-in. Currently applies to **requests only**; see
    /// [`ProtectedContext::for_request`].
    pub bound_headers: &'static [&'static str],
}

impl ContextBinding {
    /// Returns the default binding policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether the authority is bound.
    ///
    /// # Authority normalization (read before enabling)
    ///
    /// The authority is bound as **raw bytes**: `example.com`,
    /// `EXAMPLE.COM`, `example.com:443`, and a punycoded form are four
    /// different values, and any client/server disagreement fails
    /// authentication. HTTP infrastructure routinely rewrites this value
    /// (proxies adding default ports, clients title-casing `Host`, HTTP/2
    /// `:authority` vs HTTP/1.1 `Host` differences), so before enabling,
    /// both peers MUST derive the authority through the same normalization:
    ///
    /// 1. lowercase the host,
    /// 2. IDNA/punycode-encode it (bind the `xn--…` form, never the Unicode
    ///    form),
    /// 3. strip the port when it is the scheme default (`:443` for https,
    ///    `:80` for http) and keep it otherwise,
    /// 4. on the server, reconstruct from the same source the client bound
    ///    (the request-target/`:authority` when present, else `Host`) —
    ///    **before** any reverse-proxy rewriting, or configure the expected
    ///    external authority statically instead of trusting headers.
    ///
    /// If you cannot guarantee all four, leave this off: method, path,
    /// query, message ID, and expiry already prevent route substitution and
    /// replay, and an unverifiable authority binding only produces spurious
    /// failures (or, worse, pressure to disable protection entirely).
    pub fn with_authority(mut self, bind_authority: bool) -> Self {
        self.bind_authority = bind_authority;
        self
    }

    /// Sets the additional header names to bind into the request context.
    pub fn with_bound_headers(mut self, headers: &'static [&'static str]) -> Self {
        self.bound_headers = headers;
        self
    }
}

/// Sender-chosen values that travel in `x-foctet-*` headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextCarrier {
    /// Unique per-message identifier (anti-replay key).
    pub message_id: [u8; MESSAGE_ID_LEN],
    /// Unix-seconds timestamp the message was sealed.
    pub timestamp_secs: u64,
    /// Absolute Unix-seconds time after which the message must be rejected.
    pub expiry_secs: u64,
    /// Optional application idempotency key.
    pub idempotency_key: Option<String>,
    /// For responses, the request message ID being answered.
    pub request_message_id: Option<[u8; MESSAGE_ID_LEN]>,
}

impl ContextCarrier {
    /// Builds a fresh carrier with a random message ID and `now + ttl` expiry.
    pub fn generate(now_secs: u64, ttl_secs: u64) -> Self {
        let salt = foctet_core::random_session_salt();
        let mut message_id = [0u8; MESSAGE_ID_LEN];
        message_id.copy_from_slice(&salt[..MESSAGE_ID_LEN]);
        Self {
            message_id,
            timestamp_secs: now_secs,
            expiry_secs: now_secs.saturating_add(ttl_secs),
            idempotency_key: None,
            request_message_id: None,
        }
    }

    /// Sets the optional idempotency key.
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Sets the request message ID this response answers.
    pub fn answering(mut self, request_message_id: [u8; MESSAGE_ID_LEN]) -> Self {
        self.request_message_id = Some(request_message_id);
        self
    }

    /// Writes the carrier values into HTTP headers.
    pub fn apply_to_headers(&self, headers: &mut HeaderMap) -> Result<(), HttpError> {
        insert_str(headers, MSG_ID_HEADER, &to_hex(&self.message_id))?;
        insert_str(headers, TIMESTAMP_HEADER, &self.timestamp_secs.to_string())?;
        insert_str(headers, EXPIRY_HEADER, &self.expiry_secs.to_string())?;
        if let Some(idem) = &self.idempotency_key {
            insert_str(headers, IDEMPOTENCY_HEADER, idem)?;
        }
        if let Some(req_id) = &self.request_message_id {
            insert_str(headers, REQUEST_MSG_ID_HEADER, &to_hex(req_id))?;
        }
        Ok(())
    }

    /// Parses the carrier values from HTTP headers.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, HttpError> {
        let message_id = parse_hex_id(get_str(headers, MSG_ID_HEADER)?)
            .ok_or(HttpError::InvalidContext("message id"))?;
        let timestamp_secs = get_str(headers, TIMESTAMP_HEADER)?
            .parse::<u64>()
            .map_err(|_| HttpError::InvalidContext("timestamp"))?;
        let expiry_secs = get_str(headers, EXPIRY_HEADER)?
            .parse::<u64>()
            .map_err(|_| HttpError::InvalidContext("expiry"))?;

        let idempotency_key = match headers.get(IDEMPOTENCY_HEADER) {
            Some(value) => Some(
                value
                    .to_str()
                    .map_err(|_| HttpError::InvalidContext("idempotency key"))?
                    .to_string(),
            ),
            None => None,
        };

        let request_message_id = match headers.get(REQUEST_MSG_ID_HEADER) {
            Some(value) => {
                let s = value
                    .to_str()
                    .map_err(|_| HttpError::InvalidContext("request message id"))?;
                Some(parse_hex_id(s).ok_or(HttpError::InvalidContext("request message id"))?)
            }
            None => None,
        };

        Ok(Self {
            message_id,
            timestamp_secs,
            expiry_secs,
            idempotency_key,
            request_message_id,
        })
    }
}

/// Canonical HTTP protected context bound into a body envelope's associated data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedContext {
    direction: ContextDirection,
    method: Option<String>,
    authority: Option<String>,
    path: String,
    query: Option<String>,
    status: Option<u16>,
    carrier: ContextCarrier,
    /// `(header name, value bytes)` for each name in `binding.bound_headers`
    /// that was present on the message; absent headers are still bound (as a
    /// "not present" marker) so a header's removal also fails authentication.
    bound_headers: Vec<(&'static str, Option<Vec<u8>>)>,
}

impl ProtectedContext {
    /// Builds the request context from `http` request parts and a carrier.
    pub fn for_request(
        parts: &http::request::Parts,
        carrier: ContextCarrier,
        binding: ContextBinding,
    ) -> Self {
        let authority = if binding.bind_authority {
            request_authority(parts)
        } else {
            None
        };
        let bound_headers = binding
            .bound_headers
            .iter()
            .map(|&name| (name, parts.headers.get(name).map(|v| v.as_bytes().to_vec())))
            .collect();
        Self {
            direction: ContextDirection::Request,
            method: Some(parts.method.as_str().to_ascii_uppercase()),
            authority,
            path: parts.uri.path().to_string(),
            query: parts.uri.query().map(|q| q.to_string()),
            status: None,
            carrier,
            bound_headers,
        }
    }

    /// Builds the response context from `http` response parts and a carrier.
    ///
    /// The request path/query bound on the request side are not visible to the
    /// response side, so response binding authenticates direction, status,
    /// timestamp/expiry, the response message ID, and (when set) the request
    /// message ID being answered.
    pub fn for_response(parts: &http::response::Parts, carrier: ContextCarrier) -> Self {
        Self {
            direction: ContextDirection::Response,
            method: None,
            authority: None,
            path: String::new(),
            query: None,
            status: Some(parts.status.as_u16()),
            carrier,
            bound_headers: Vec::new(),
        }
    }

    /// Returns the carrier values for this context.
    pub fn carrier(&self) -> &ContextCarrier {
        &self.carrier
    }

    /// Validates the timestamp/expiry against `now_secs` with `max_skew_secs`
    /// tolerance for clock differences.
    pub fn validate_freshness(&self, now_secs: u64, max_skew_secs: u64) -> Result<(), HttpError> {
        if self.carrier.expiry_secs <= self.carrier.timestamp_secs {
            return Err(HttpError::InvalidContext("expiry not after timestamp"));
        }
        if self.carrier.timestamp_secs > now_secs.saturating_add(max_skew_secs) {
            return Err(HttpError::ContextTimestampInFuture);
        }
        if now_secs > self.carrier.expiry_secs.saturating_add(max_skew_secs) {
            return Err(HttpError::ContextExpired);
        }
        Ok(())
    }

    /// Produces the canonical associated-data bytes for this context.
    pub fn to_aad_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(CONTEXT_DOMAIN_V1);
        out.push(self.direction.tag());

        push_field(
            &mut out,
            b'M',
            self.method.as_deref().unwrap_or("").as_bytes(),
        );
        push_optional(&mut out, b'A', self.authority.as_deref().map(str::as_bytes));
        push_field(&mut out, b'P', self.path.as_bytes());
        push_optional(&mut out, b'Q', self.query.as_deref().map(str::as_bytes));

        match self.status {
            Some(status) => {
                out.push(1);
                out.extend_from_slice(&status.to_be_bytes());
            }
            None => out.push(0),
        }

        out.extend_from_slice(&self.carrier.timestamp_secs.to_be_bytes());
        out.extend_from_slice(&self.carrier.expiry_secs.to_be_bytes());
        out.extend_from_slice(&self.carrier.message_id);

        match &self.carrier.request_message_id {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id);
            }
            None => out.push(0),
        }

        push_optional(
            &mut out,
            b'I',
            self.carrier.idempotency_key.as_deref().map(str::as_bytes),
        );

        for (name, value) in &self.bound_headers {
            out.push(b'H');
            push_field(&mut out, b'N', name.as_bytes());
            push_optional(&mut out, b'V', value.as_deref());
        }

        out
    }
}

/// Returns the current time in Unix seconds.
///
/// Convenience for native (non-`wasm32`) callers; on `wasm32` targets such as
/// Cloudflare Workers, obtain the time from the runtime and pass it explicitly.
#[cfg(not(target_arch = "wasm32"))]
pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn request_authority(parts: &http::request::Parts) -> Option<String> {
    if let Some(authority) = parts.uri.authority() {
        return Some(authority.as_str().to_ascii_lowercase());
    }
    parts
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
}

fn push_field(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_optional(out: &mut Vec<u8>, tag: u8, bytes: Option<&[u8]>) {
    match bytes {
        Some(b) => {
            out.push(1);
            push_field(out, tag, b);
        }
        None => out.push(0),
    }
}

fn insert_str(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), HttpError> {
    let header_value = HeaderValue::from_str(value).map_err(|_| HttpError::InvalidContext(name))?;
    headers.insert(HeaderName::from_static(name), header_value);
    Ok(())
}

fn get_str<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, HttpError> {
    headers
        .get(name)
        .ok_or(HttpError::MissingContext(name))?
        .to_str()
        .map_err(|_| HttpError::InvalidContext(name))
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn parse_hex_id(value: &str) -> Option<[u8; MESSAGE_ID_LEN]> {
    if value.len() != MESSAGE_ID_LEN * 2 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = [0u8; MESSAGE_ID_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Request, Response, StatusCode};

    #[test]
    fn carrier_header_roundtrip() {
        let carrier = ContextCarrier::generate(1000, 60)
            .with_idempotency_key("idem-123")
            .answering([7u8; MESSAGE_ID_LEN]);
        let mut headers = HeaderMap::new();
        carrier.apply_to_headers(&mut headers).expect("apply");
        let parsed = ContextCarrier::from_headers(&headers).expect("parse");
        assert_eq!(parsed, carrier);
    }

    #[test]
    fn distinct_routes_produce_distinct_aad() {
        let carrier = ContextCarrier::generate(1000, 60);
        let pay = Request::builder()
            .method("POST")
            .uri("https://api.example.com/pay")
            .body(())
            .expect("request");
        let refund = Request::builder()
            .method("POST")
            .uri("https://api.example.com/refund")
            .body(())
            .expect("request");
        let (pay_parts, _) = pay.into_parts();
        let (refund_parts, _) = refund.into_parts();
        let binding = ContextBinding::default();
        let pay_aad =
            ProtectedContext::for_request(&pay_parts, carrier.clone(), binding).to_aad_bytes();
        let refund_aad =
            ProtectedContext::for_request(&refund_parts, carrier, binding).to_aad_bytes();
        assert_ne!(pay_aad, refund_aad);
    }

    #[test]
    fn freshness_rejects_expired_and_future() {
        let carrier = ContextCarrier::generate(1000, 60);
        let req = Request::builder().uri("/x").body(()).expect("request");
        let (parts, _) = req.into_parts();
        let ctx = ProtectedContext::for_request(&parts, carrier, ContextBinding::default());

        ctx.validate_freshness(1030, 5).expect("within window");
        assert!(matches!(
            ctx.validate_freshness(2000, 5),
            Err(HttpError::ContextExpired)
        ));
        assert!(matches!(
            ctx.validate_freshness(900, 5),
            Err(HttpError::ContextTimestampInFuture)
        ));
    }

    #[test]
    fn bound_header_change_produces_distinct_aad() {
        let carrier = ContextCarrier::generate(1000, 60);
        let binding = ContextBinding::default().with_bound_headers(&["x-tenant-id"]);

        let tenant_a = Request::builder()
            .uri("/x")
            .header("x-tenant-id", "tenant-a")
            .body(())
            .expect("request");
        let tenant_b = Request::builder()
            .uri("/x")
            .header("x-tenant-id", "tenant-b")
            .body(())
            .expect("request");
        let no_header = Request::builder().uri("/x").body(()).expect("request");

        let (a_parts, _) = tenant_a.into_parts();
        let (b_parts, _) = tenant_b.into_parts();
        let (none_parts, _) = no_header.into_parts();

        let a_aad =
            ProtectedContext::for_request(&a_parts, carrier.clone(), binding).to_aad_bytes();
        let b_aad =
            ProtectedContext::for_request(&b_parts, carrier.clone(), binding).to_aad_bytes();
        let none_aad = ProtectedContext::for_request(&none_parts, carrier, binding).to_aad_bytes();

        assert_ne!(a_aad, b_aad, "different header values must diverge");
        assert_ne!(a_aad, none_aad, "missing the bound header must diverge");
    }

    #[test]
    fn unbound_header_changes_do_not_affect_aad() {
        // Without `with_bound_headers`, an arbitrary header is not part of the
        // protected context at all.
        let carrier = ContextCarrier::generate(1000, 60);
        let binding = ContextBinding::default();

        let with_header = Request::builder()
            .uri("/x")
            .header("x-tenant-id", "tenant-a")
            .body(())
            .expect("request");
        let without_header = Request::builder().uri("/x").body(()).expect("request");

        let (with_parts, _) = with_header.into_parts();
        let (without_parts, _) = without_header.into_parts();

        let with_aad =
            ProtectedContext::for_request(&with_parts, carrier.clone(), binding).to_aad_bytes();
        let without_aad =
            ProtectedContext::for_request(&without_parts, carrier, binding).to_aad_bytes();
        assert_eq!(with_aad, without_aad);
    }

    #[test]
    fn response_status_is_bound() {
        let carrier = ContextCarrier::generate(1000, 60).answering([1u8; MESSAGE_ID_LEN]);
        let ok = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .expect("response");
        let created = Response::builder()
            .status(StatusCode::CREATED)
            .body(())
            .expect("response");
        let (ok_parts, _) = ok.into_parts();
        let (created_parts, _) = created.into_parts();
        let ok_aad = ProtectedContext::for_response(&ok_parts, carrier.clone()).to_aad_bytes();
        let created_aad = ProtectedContext::for_response(&created_parts, carrier).to_aad_bytes();
        assert_ne!(ok_aad, created_aad);
    }
}
