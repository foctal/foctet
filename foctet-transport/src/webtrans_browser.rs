//! Browser WebTransport **datagram** adapter (wasm32).
//!
//! [`BrowserWebTransportDatagrams`] implements [`crate::DatagramTransport`]
//! over the browser's `WebTransport.datagrams` duplex, so a Rust/wasm
//! application can run a [`crate::SecureDatagramChannel`] over real browser
//! WebTransport datagrams with no JavaScript glue beyond handing over the
//! datagram duplex object:
//!
//! ```javascript
//! const wt = new WebTransport("https://example.com:4433/foctet");
//! await wt.ready;
//! // pass `wt.datagrams` to the wasm side
//! ```
//!
//! ```rust,ignore
//! let transport = BrowserWebTransportDatagrams::new(datagrams_js_value)?;
//! let mut channel = SecureDatagramChannel::from_active_session(transport, &session)?;
//! channel.send_datagram(0, 0, b"hello").await?;
//! ```
//!
//! The handshake that produces the [`foctet_core::Session`] must run over a
//! **reliable** channel first (e.g. a WebTransport bidirectional stream or the
//! wasm `FoctetSession` message mode); see the rekey-over-datagram notes in
//! [`crate::datagram`].
//!
//! # Binding strategy
//!
//! The adapter binds the WebTransport datagram duplex **duck-typed** through
//! `js-sys` reflection (`readable`/`writable`/`maxDatagramSize`, standard
//! WHATWG stream reader/writer methods) instead of `web-sys`'s `WebTransport`
//! type, which is still gated behind the unstable-APIs cfg flag. Anything
//! shaped like `{ readable, writable, maxDatagramSize? }` works, which also
//! makes the adapter testable against in-page mock streams.

use js_sys::{Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::datagram::DatagramTransport;

/// Error from the browser WebTransport datagram adapter.
///
/// JavaScript error values are stringified: `JsValue` is neither `Send` nor
/// `Sync`, and the message is all the caller can act on anyway.
#[derive(Debug, thiserror::Error)]
#[error("browser webtransport datagram error: {0}")]
pub struct BrowserWebTransportError(String);

impl BrowserWebTransportError {
    fn from_js(context: &str, value: JsValue) -> Self {
        let detail = value
            .dyn_ref::<js_sys::Error>()
            .map(|e| String::from(e.message()))
            .or_else(|| value.as_string())
            .unwrap_or_else(|| format!("{value:?}"));
        Self(format!("{context}: {detail}"))
    }

    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

fn get(target: &JsValue, key: &str) -> Result<JsValue, BrowserWebTransportError> {
    Reflect::get(target, &JsValue::from_str(key))
        .map_err(|e| BrowserWebTransportError::from_js(key, e))
}

fn call0(target: &JsValue, method: &str) -> Result<JsValue, BrowserWebTransportError> {
    let f: js_sys::Function = get(target, method)?
        .dyn_into()
        .map_err(|_| BrowserWebTransportError::new(format!("`{method}` is not a function")))?;
    f.call0(target)
        .map_err(|e| BrowserWebTransportError::from_js(method, e))
}

fn call1(
    target: &JsValue,
    method: &str,
    arg: &JsValue,
) -> Result<JsValue, BrowserWebTransportError> {
    let f: js_sys::Function = get(target, method)?
        .dyn_into()
        .map_err(|_| BrowserWebTransportError::new(format!("`{method}` is not a function")))?;
    f.call1(target, arg)
        .map_err(|e| BrowserWebTransportError::from_js(method, e))
}

async fn await_promise(value: JsValue, context: &str) -> Result<JsValue, BrowserWebTransportError> {
    let promise: Promise = value
        .dyn_into()
        .map_err(|_| BrowserWebTransportError::new(format!("`{context}` is not a promise")))?;
    JsFuture::from(promise)
        .await
        .map_err(|e| BrowserWebTransportError::from_js(context, e))
}

/// A [`DatagramTransport`] over a browser `WebTransport.datagrams` duplex.
///
/// Construct with the JS `WebTransport.datagrams` object (or anything with the
/// same `{ readable, writable, maxDatagramSize? }` shape). The adapter locks
/// the readable's reader and the writable's writer for its lifetime.
#[derive(Debug)]
pub struct BrowserWebTransportDatagrams {
    reader: JsValue,
    writer: JsValue,
    max_datagram_size: Option<usize>,
}

impl BrowserWebTransportDatagrams {
    /// Wraps a `WebTransport.datagrams` duplex object.
    ///
    /// Reads `maxDatagramSize` once at construction (the browser may lower it
    /// later on path changes; Foctet fails closed with `FrameTooLarge` rather
    /// than fragmenting if a sealed datagram no longer fits — see the
    /// MTU/fragmentation policy in `SPEC.md`).
    pub fn new(datagrams: JsValue) -> Result<Self, BrowserWebTransportError> {
        let readable = get(&datagrams, "readable")?;
        let writable = get(&datagrams, "writable")?;
        if readable.is_undefined() || writable.is_undefined() {
            return Err(BrowserWebTransportError::new(
                "expected a WebTransport datagram duplex with `readable` and `writable`",
            ));
        }
        let reader = call0(&readable, "getReader")?;
        let writer = call0(&writable, "getWriter")?;
        let max_datagram_size = get(&datagrams, "maxDatagramSize")
            .ok()
            .and_then(|v| v.as_f64())
            .filter(|v| v.is_finite() && *v >= 1.0)
            .map(|v| v as usize);
        Ok(Self {
            reader,
            writer,
            max_datagram_size,
        })
    }
}

impl DatagramTransport for BrowserWebTransportDatagrams {
    type Error = BrowserWebTransportError;

    async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Self::Error> {
        let chunk = Uint8Array::from(datagram.as_slice());
        let pending = call1(&self.writer, "write", &chunk.into())?;
        await_promise(pending, "writer.write").await?;
        Ok(())
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>, Self::Error> {
        let pending = call0(&self.reader, "read")?;
        let result = await_promise(pending, "reader.read").await?;
        let done = get(&result, "done")?.as_bool().unwrap_or(false);
        if done {
            return Err(BrowserWebTransportError::new(
                "datagram readable stream closed",
            ));
        }
        let value = get(&result, "value")?;
        let bytes: Uint8Array = value
            .dyn_into()
            .map_err(|_| BrowserWebTransportError::new("datagram chunk is not a Uint8Array"))?;
        Ok(bytes.to_vec())
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.max_datagram_size
    }
}
