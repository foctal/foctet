use foctet_core::{
    BodyEnvelopeError, BodyEnvelopeLimits, open_body_with_context, seal_body_with_context,
};
use foctet_http::{
    ContextCarrier, DEFAULT_CONTEXT_TTL_SECS, DEFAULT_MAX_CLOCK_SKEW_SECS, HttpError,
    MESSAGE_ID_LEN, ProtectedContext, http,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use wasm_bindgen::prelude::*;

use crate::{WasmError, to_key};

const CONTENT_TYPE_HEADER: &str = "content-type";
const CONTENT_TYPE_VALUE: &str = "application/foctet";
const SCOPE_HEADER: &str = "x-foctet-scope";
const BODY_ONLY_SCOPE: &str = "body-only";
const MSG_ID_HEADER: &str = "x-foctet-msg-id";
const TIMESTAMP_HEADER: &str = "x-foctet-timestamp";
const EXPIRY_HEADER: &str = "x-foctet-expiry";
const IDEMPOTENCY_HEADER: &str = "x-foctet-idempotency-key";
const REQUEST_MSG_ID_HEADER: &str = "x-foctet-req-msg-id";

#[derive(Debug)]
pub(crate) enum WasmHttpError {
    BadMessageIdLength,
    InvalidMessageId,
    InvalidTimestamp,
    InvalidExpiry,
    BadHeaderName(String),
    BadHeaderValue(String),
    InvalidMethod(String),
    InvalidUri(String),
    InvalidStatus(u16),
    Envelope(BodyEnvelopeError),
    Http(HttpError),
    Key(WasmError),
}

impl core::fmt::Display for WasmHttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WasmHttpError::BadMessageIdLength => write!(f, "expected a 16-byte Foctet message id"),
            WasmHttpError::InvalidMessageId => write!(f, "invalid Foctet message id"),
            WasmHttpError::InvalidTimestamp => write!(f, "invalid Foctet context timestamp"),
            WasmHttpError::InvalidExpiry => write!(f, "invalid Foctet context expiry"),
            WasmHttpError::BadHeaderName(name) => write!(f, "invalid HTTP header name: {name}"),
            WasmHttpError::BadHeaderValue(name) => {
                write!(f, "invalid HTTP header value for header: {name}")
            }
            WasmHttpError::InvalidMethod(method) => write!(f, "invalid HTTP method: {method}"),
            WasmHttpError::InvalidUri(uri) => write!(f, "invalid HTTP URI: {uri}"),
            WasmHttpError::InvalidStatus(status) => write!(f, "invalid HTTP status: {status}"),
            WasmHttpError::Envelope(err) => write!(f, "{err}"),
            WasmHttpError::Http(err) => write!(f, "{err}"),
            WasmHttpError::Key(err) => write!(f, "{err}"),
        }
    }
}

impl From<BodyEnvelopeError> for WasmHttpError {
    fn from(err: BodyEnvelopeError) -> Self {
        WasmHttpError::Envelope(err)
    }
}

impl From<HttpError> for WasmHttpError {
    fn from(err: HttpError) -> Self {
        WasmHttpError::Http(err)
    }
}

impl From<WasmError> for WasmHttpError {
    fn from(err: WasmError) -> Self {
        WasmHttpError::Key(err)
    }
}

fn to_js(err: WasmHttpError) -> JsError {
    JsError::new(&err.to_string())
}

fn to_message_id(bytes: &[u8]) -> Result<[u8; MESSAGE_ID_LEN], WasmHttpError> {
    <[u8; MESSAGE_ID_LEN]>::try_from(bytes).map_err(|_| WasmHttpError::BadMessageIdLength)
}

fn parse_message_id_hex(value: &str) -> Result<[u8; MESSAGE_ID_LEN], WasmHttpError> {
    if value.len() != MESSAGE_ID_LEN * 2 {
        return Err(WasmHttpError::InvalidMessageId);
    }
    let bytes = value.as_bytes();
    let mut out = [0u8; MESSAGE_ID_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[2 * i]).ok_or(WasmHttpError::InvalidMessageId)?;
        let lo = hex_val(bytes[2 * i + 1]).ok_or(WasmHttpError::InvalidMessageId)?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn header_map(headers: &[(String, String)]) -> Result<HeaderMap, WasmHttpError> {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| WasmHttpError::BadHeaderName(name.clone()))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| WasmHttpError::BadHeaderValue(name.clone()))?;
        out.append(header_name, header_value);
    }
    Ok(out)
}

fn request_parts(
    method: &str,
    uri: &str,
    headers: &[(String, String)],
) -> Result<http::request::Parts, WasmHttpError> {
    let method = http::Method::from_bytes(method.as_bytes())
        .map_err(|_| WasmHttpError::InvalidMethod(method.to_string()))?;
    let uri = uri
        .parse::<http::Uri>()
        .map_err(|_| WasmHttpError::InvalidUri(uri.to_string()))?;
    let mut builder = http::Request::builder().method(method).uri(uri);
    for (name, value) in header_map(headers)?.iter() {
        builder = builder.header(name, value);
    }
    let (parts, _) = builder
        .body(())
        .expect("method, URI, and headers were validated before building")
        .into_parts();
    Ok(parts)
}

fn response_parts(status: u16) -> Result<http::response::Parts, WasmHttpError> {
    let response = http::Response::builder()
        .status(status)
        .body(())
        .map_err(|_| WasmHttpError::InvalidStatus(status))?;
    let (parts, _) = response.into_parts();
    Ok(parts)
}

fn seal_with_aad(
    plaintext: &[u8],
    recipient_public_key: &[u8],
    recipient_key_id: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, WasmHttpError> {
    let key = to_key(recipient_public_key)?;
    Ok(seal_body_with_context(
        plaintext,
        key,
        recipient_key_id,
        aad,
        &BodyEnvelopeLimits::default(),
    )?)
}

fn open_with_aad(
    envelope: &[u8],
    recipient_secret_key: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, WasmHttpError> {
    let key = to_key(recipient_secret_key)?;
    Ok(open_body_with_context(
        envelope,
        key,
        aad,
        &BodyEnvelopeLimits::default(),
    )?)
}

/// Sender-chosen HTTP protected-context values carried in `x-foctet-*` headers.
#[wasm_bindgen(js_name = HttpContextCarrier)]
#[derive(Clone, Debug)]
pub struct WasmHttpContextCarrier {
    inner: ContextCarrier,
}

#[wasm_bindgen(js_class = HttpContextCarrier)]
impl WasmHttpContextCarrier {
    /// Generates a fresh carrier with a random message ID and `now + ttl` expiry.
    #[wasm_bindgen(js_name = generate)]
    pub fn generate(now_secs: u64, ttl_secs: u64) -> Self {
        Self {
            inner: ContextCarrier::generate(now_secs, ttl_secs),
        }
    }

    /// Builds a carrier from received `x-foctet-*` header values.
    #[wasm_bindgen(js_name = fromHeaderValues)]
    pub fn from_header_values(
        message_id_hex: &str,
        timestamp_secs: &str,
        expiry_secs: &str,
        idempotency_key: Option<String>,
        request_message_id_hex: Option<String>,
    ) -> Result<Self, JsError> {
        let message_id = parse_message_id_hex(message_id_hex).map_err(to_js)?;
        let timestamp_secs = timestamp_secs
            .parse::<u64>()
            .map_err(|_| to_js(WasmHttpError::InvalidTimestamp))?;
        let expiry_secs = expiry_secs
            .parse::<u64>()
            .map_err(|_| to_js(WasmHttpError::InvalidExpiry))?;
        let request_message_id = match request_message_id_hex {
            Some(value) => Some(parse_message_id_hex(&value).map_err(to_js)?),
            None => None,
        };
        Ok(Self {
            inner: ContextCarrier {
                message_id,
                timestamp_secs,
                expiry_secs,
                idempotency_key,
                request_message_id,
            },
        })
    }

    /// Builds a carrier from explicit field values.
    #[wasm_bindgen(constructor)]
    pub fn new(message_id: &[u8], timestamp_secs: u64, expiry_secs: u64) -> Result<Self, JsError> {
        Ok(Self {
            inner: ContextCarrier {
                message_id: to_message_id(message_id).map_err(to_js)?,
                timestamp_secs,
                expiry_secs,
                idempotency_key: None,
                request_message_id: None,
            },
        })
    }

    /// Sets the optional application idempotency key.
    #[wasm_bindgen(js_name = setIdempotencyKey)]
    pub fn set_idempotency_key(&mut self, key: Option<String>) {
        self.inner.idempotency_key = key;
    }

    /// Sets the request message ID answered by a response.
    #[wasm_bindgen(js_name = setRequestMessageId)]
    pub fn set_request_message_id(&mut self, message_id: Option<Vec<u8>>) -> Result<(), JsError> {
        self.inner.request_message_id = match message_id {
            Some(id) => Some(to_message_id(&id).map_err(to_js)?),
            None => None,
        };
        Ok(())
    }

    /// Returns the raw 16-byte message ID.
    #[wasm_bindgen(getter, js_name = messageId)]
    pub fn message_id(&self) -> Vec<u8> {
        self.inner.message_id.to_vec()
    }

    /// Returns the Unix-seconds timestamp.
    #[wasm_bindgen(getter, js_name = timestampSecs)]
    pub fn timestamp_secs(&self) -> u64 {
        self.inner.timestamp_secs
    }

    /// Returns the Unix-seconds absolute expiry.
    #[wasm_bindgen(getter, js_name = expirySecs)]
    pub fn expiry_secs(&self) -> u64 {
        self.inner.expiry_secs
    }

    /// Returns the optional application idempotency key.
    #[wasm_bindgen(getter, js_name = idempotencyKey)]
    pub fn idempotency_key(&self) -> Option<String> {
        self.inner.idempotency_key.clone()
    }

    /// Returns the optional answered request message ID.
    #[wasm_bindgen(getter, js_name = requestMessageId)]
    pub fn request_message_id(&self) -> Option<Vec<u8>> {
        self.inner.request_message_id.map(|id| id.to_vec())
    }

    /// Returns the `x-foctet-msg-id` header value.
    #[wasm_bindgen(getter, js_name = messageIdHeaderValue)]
    pub fn message_id_header_value(&self) -> String {
        hex(&self.inner.message_id)
    }

    /// Returns the `x-foctet-timestamp` header value.
    #[wasm_bindgen(getter, js_name = timestampHeaderValue)]
    pub fn timestamp_header_value(&self) -> String {
        self.inner.timestamp_secs.to_string()
    }

    /// Returns the `x-foctet-expiry` header value.
    #[wasm_bindgen(getter, js_name = expiryHeaderValue)]
    pub fn expiry_header_value(&self) -> String {
        self.inner.expiry_secs.to_string()
    }

    /// Returns the `x-foctet-req-msg-id` header value, if set.
    #[wasm_bindgen(getter, js_name = requestMessageIdHeaderValue)]
    pub fn request_message_id_header_value(&self) -> Option<String> {
        self.inner.request_message_id.map(|id| hex(&id))
    }
}

/// Request-side HTTP protected context.
#[wasm_bindgen(js_name = HttpRequestContext)]
#[derive(Clone, Debug)]
pub struct WasmHttpRequestContext {
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    carrier: WasmHttpContextCarrier,
    bind_authority: bool,
    bound_header_names: Vec<String>,
}

#[wasm_bindgen(js_class = HttpRequestContext)]
impl WasmHttpRequestContext {
    /// Creates a request context from normalized HTTP request metadata.
    #[wasm_bindgen(constructor)]
    pub fn new(method: String, uri: String, carrier: &WasmHttpContextCarrier) -> Self {
        Self {
            method,
            uri,
            headers: Vec::new(),
            carrier: carrier.clone(),
            bind_authority: false,
            bound_header_names: Vec::new(),
        }
    }

    /// Adds one request header visible to context binding.
    #[wasm_bindgen(js_name = setHeader)]
    pub fn set_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    /// Controls whether request authority is bound into the context.
    #[wasm_bindgen(js_name = setBindAuthority)]
    pub fn set_bind_authority(&mut self, value: bool) {
        self.bind_authority = value;
    }

    /// Adds a request header name to the protected-context binding policy.
    #[wasm_bindgen(js_name = bindHeader)]
    pub fn bind_header(&mut self, name: String) {
        self.bound_header_names.push(name);
    }

    /// Produces the canonical associated-data bytes for this request context.
    #[wasm_bindgen(js_name = aadBytes)]
    pub fn aad_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.aad_inner().map_err(to_js)
    }

    /// Validates the timestamp/expiry for this request context.
    #[wasm_bindgen(js_name = validateFreshness)]
    pub fn validate_freshness(&self, now_secs: u64, max_skew_secs: u64) -> Result<(), JsError> {
        let context = self.protected_context().map_err(to_js)?;
        context
            .validate_freshness(now_secs, max_skew_secs)
            .map_err(WasmHttpError::from)
            .map_err(to_js)
    }

    /// Seals a request body bound to this HTTP protected context.
    #[wasm_bindgen(js_name = sealBody)]
    pub fn seal_body(
        &self,
        plaintext: &[u8],
        recipient_public_key: &[u8],
        recipient_key_id: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let aad = self.aad_inner().map_err(to_js)?;
        seal_with_aad(plaintext, recipient_public_key, recipient_key_id, &aad).map_err(to_js)
    }

    /// Opens a request body bound to this HTTP protected context.
    #[wasm_bindgen(js_name = openBody)]
    pub fn open_body(
        &self,
        envelope: &[u8],
        recipient_secret_key: &[u8],
        now_secs: u64,
        max_skew_secs: u64,
    ) -> Result<Vec<u8>, JsError> {
        self.validate_freshness(now_secs, max_skew_secs)?;
        let aad = self.aad_inner().map_err(to_js)?;
        open_with_aad(envelope, recipient_secret_key, &aad).map_err(to_js)
    }
}

impl WasmHttpRequestContext {
    fn protected_context(&self) -> Result<ProtectedContext, WasmHttpError> {
        let parts = request_parts(&self.method, &self.uri, &self.headers)?;
        Ok(ProtectedContext::for_request_with_header_binding(
            &parts,
            self.carrier.inner.clone(),
            self.bind_authority,
            self.bound_header_names.iter(),
        ))
    }

    fn aad_inner(&self) -> Result<Vec<u8>, WasmHttpError> {
        Ok(self.protected_context()?.to_aad_bytes())
    }
}

/// Response-side HTTP protected context.
#[wasm_bindgen(js_name = HttpResponseContext)]
#[derive(Clone, Debug)]
pub struct WasmHttpResponseContext {
    status: u16,
    carrier: WasmHttpContextCarrier,
}

#[wasm_bindgen(js_class = HttpResponseContext)]
impl WasmHttpResponseContext {
    /// Creates a response context from the HTTP status and carrier fields.
    #[wasm_bindgen(constructor)]
    pub fn new(status: u16, carrier: &WasmHttpContextCarrier) -> Self {
        Self {
            status,
            carrier: carrier.clone(),
        }
    }

    /// Produces the canonical associated-data bytes for this response context.
    #[wasm_bindgen(js_name = aadBytes)]
    pub fn aad_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.aad_inner().map_err(to_js)
    }

    /// Validates the timestamp/expiry for this response context.
    #[wasm_bindgen(js_name = validateFreshness)]
    pub fn validate_freshness(&self, now_secs: u64, max_skew_secs: u64) -> Result<(), JsError> {
        let context = self.protected_context().map_err(to_js)?;
        context
            .validate_freshness(now_secs, max_skew_secs)
            .map_err(WasmHttpError::from)
            .map_err(to_js)
    }

    /// Seals a response body bound to this HTTP protected context.
    #[wasm_bindgen(js_name = sealBody)]
    pub fn seal_body(
        &self,
        plaintext: &[u8],
        recipient_public_key: &[u8],
        recipient_key_id: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let aad = self.aad_inner().map_err(to_js)?;
        seal_with_aad(plaintext, recipient_public_key, recipient_key_id, &aad).map_err(to_js)
    }

    /// Opens a response body bound to this HTTP protected context.
    #[wasm_bindgen(js_name = openBody)]
    pub fn open_body(
        &self,
        envelope: &[u8],
        recipient_secret_key: &[u8],
        now_secs: u64,
        max_skew_secs: u64,
    ) -> Result<Vec<u8>, JsError> {
        self.validate_freshness(now_secs, max_skew_secs)?;
        let aad = self.aad_inner().map_err(to_js)?;
        open_with_aad(envelope, recipient_secret_key, &aad).map_err(to_js)
    }
}

impl WasmHttpResponseContext {
    fn protected_context(&self) -> Result<ProtectedContext, WasmHttpError> {
        let parts = response_parts(self.status)?;
        Ok(ProtectedContext::for_response(
            &parts,
            self.carrier.inner.clone(),
        ))
    }

    fn aad_inner(&self) -> Result<Vec<u8>, WasmHttpError> {
        Ok(self.protected_context()?.to_aad_bytes())
    }
}

/// Foctet HTTP media type.
#[wasm_bindgen(js_name = httpContentType)]
pub fn http_content_type() -> String {
    CONTENT_TYPE_VALUE.to_string()
}

/// Advisory Foctet protection-scope header name.
#[wasm_bindgen(js_name = httpScopeHeader)]
pub fn http_scope_header() -> String {
    SCOPE_HEADER.to_string()
}

/// Advisory Foctet body-only protection-scope value.
#[wasm_bindgen(js_name = httpBodyOnlyScope)]
pub fn http_body_only_scope() -> String {
    BODY_ONLY_SCOPE.to_string()
}

/// HTTP `Content-Type` header name.
#[wasm_bindgen(js_name = httpContentTypeHeader)]
pub fn http_content_type_header() -> String {
    CONTENT_TYPE_HEADER.to_string()
}

/// Header carrying the hex-encoded Foctet message ID.
#[wasm_bindgen(js_name = httpMessageIdHeader)]
pub fn http_message_id_header() -> String {
    MSG_ID_HEADER.to_string()
}

/// Header carrying the Unix-seconds timestamp.
#[wasm_bindgen(js_name = httpTimestampHeader)]
pub fn http_timestamp_header() -> String {
    TIMESTAMP_HEADER.to_string()
}

/// Header carrying the Unix-seconds absolute expiry.
#[wasm_bindgen(js_name = httpExpiryHeader)]
pub fn http_expiry_header() -> String {
    EXPIRY_HEADER.to_string()
}

/// Header carrying the optional application idempotency key.
#[wasm_bindgen(js_name = httpIdempotencyHeader)]
pub fn http_idempotency_header() -> String {
    IDEMPOTENCY_HEADER.to_string()
}

/// Response-only header carrying the answered request message ID.
#[wasm_bindgen(js_name = httpRequestMessageIdHeader)]
pub fn http_request_message_id_header() -> String {
    REQUEST_MSG_ID_HEADER.to_string()
}

/// Suggested default protected-context TTL in seconds.
#[wasm_bindgen(js_name = defaultHttpContextTtlSecs)]
pub fn default_http_context_ttl_secs() -> u64 {
    DEFAULT_CONTEXT_TTL_SECS
}

/// Suggested default protected-context clock-skew tolerance in seconds.
#[wasm_bindgen(js_name = defaultHttpMaxClockSkewSecs)]
pub fn default_http_max_clock_skew_secs() -> u64 {
    DEFAULT_MAX_CLOCK_SKEW_SECS
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
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
    use crate::KEY_LEN;
    use foctet_http::ContextBinding;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn request_aad_matches_foctet_http() {
        let carrier = WasmHttpContextCarrier {
            inner: ContextCarrier::generate(1_000, 60).with_idempotency_key("idem-1"),
        };
        let mut wasm_ctx = WasmHttpRequestContext::new(
            "post".to_string(),
            "https://api.example.test/pay?currency=USD".to_string(),
            &carrier,
        );
        wasm_ctx.set_header("x-tenant-id".to_string(), "tenant-a".to_string());
        wasm_ctx.bind_header("x-tenant-id".to_string());

        let request = http::Request::builder()
            .method("post")
            .uri("https://api.example.test/pay?currency=USD")
            .header("x-tenant-id", "tenant-a")
            .body(())
            .expect("request");
        let (parts, _) = request.into_parts();
        let rust_aad = ProtectedContext::for_request(
            &parts,
            carrier.inner.clone(),
            ContextBinding::default().with_bound_headers(&["x-tenant-id"]),
        )
        .to_aad_bytes();

        assert_eq!(wasm_ctx.aad_inner().expect("wasm aad"), rust_aad);
    }

    #[test]
    fn request_context_seals_body_compatible_with_foctet_http() {
        let secret = StaticSecret::from([7u8; KEY_LEN]);
        let public = PublicKey::from(&secret).to_bytes();
        let carrier = WasmHttpContextCarrier {
            inner: ContextCarrier::generate(2_000, 60),
        };
        let wasm_ctx = WasmHttpRequestContext::new(
            "POST".to_string(),
            "https://example.test/x".to_string(),
            &carrier,
        );
        let envelope = wasm_ctx
            .seal_body(b"payload", &public, b"kid")
            .expect("seal");
        let opened = wasm_ctx
            .open_body(&envelope, &secret.to_bytes(), 2_000, 5)
            .expect("open");
        assert_eq!(opened, b"payload");

        let mut headers = HeaderMap::new();
        carrier
            .inner
            .apply_to_headers(&mut headers)
            .expect("carrier headers");
        let mut builder = http::Request::builder()
            .method("POST")
            .uri("https://example.test/x")
            .header(http::header::CONTENT_TYPE, CONTENT_TYPE_VALUE);
        for (name, value) in headers.iter() {
            builder = builder.header(name, value);
        }
        let request = builder.body(envelope).expect("request");
        let opener =
            foctet_http::HttpOpener::new(foctet_http::HttpOpenOptions::new(secret.to_bytes()));
        let store = foctet_http::InMemoryReplayStore::new();
        let opened_by_rust = opener
            .open_request_with_context(request, &store, 2_000, 5, ContextBinding::default())
            .expect("rust open");
        assert_eq!(opened_by_rust.body(), b"payload");
    }

    #[test]
    fn response_aad_requires_response_direction() {
        let mut carrier = ContextCarrier::generate(1_000, 60);
        carrier.request_message_id = Some([3u8; MESSAGE_ID_LEN]);
        let carrier = WasmHttpContextCarrier { inner: carrier };
        let response_ctx = WasmHttpResponseContext::new(201, &carrier);
        let request_ctx = WasmHttpRequestContext::new(
            "POST".to_string(),
            "https://example.test/x".to_string(),
            &carrier,
        );

        assert_ne!(
            response_ctx.aad_inner().expect("response aad"),
            request_ctx.aad_inner().expect("request aad")
        );
    }
}
