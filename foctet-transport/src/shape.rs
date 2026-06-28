//! Transport shapes and a unified secure-channel abstraction.
//!
//! Foctet protects three transport shapes, each with its own raw transport
//! trait:
//!
//! - **Byte stream** — a reliable, ordered byte stream
//!   ([`ByteStreamTransport`], i.e. `AsyncRead + AsyncWrite`), driven by
//!   [`crate::TokioTransportBuilder`] / [`crate::FuturesTransportBuilder`].
//! - **Message** — reliable, ordered, message-bounded units
//!   ([`crate::MessageTransport`]), via [`crate::SecureMessageChannel`].
//! - **Datagram** — MTU-bounded, loss/reorder-tolerant units
//!   ([`crate::DatagramTransport`]), via [`crate::SecureDatagramChannel`].
//!
//! Although the shapes differ on the wire, every Foctet secure channel exposes
//! the same application contract: send and receive whole **payloads**. The
//! [`SecureChannel`] trait captures that contract so application code (and the
//! shared conformance suite) can be written once and run over any shape.

/// Marker for a reliable, ordered **byte-stream** transport — the byte-stream
/// counterpart to [`crate::MessageTransport`] and [`crate::DatagramTransport`].
///
/// Any runtime-agnostic `futures_io` read/write stream is a byte-stream
/// transport; pair it with [`crate::FuturesTransportBuilder`] (or, for Tokio
/// streams, [`crate::TokioTransportBuilder`]) to obtain a [`SecureChannel`].
#[cfg(feature = "runtime-futures")]
pub trait ByteStreamTransport: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin {}

#[cfg(feature = "runtime-futures")]
impl<T> ByteStreamTransport for T where T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin {}

/// A Foctet secure channel, abstracted over the three transport shapes.
///
/// Each method moves one application payload, sealing/opening it with the
/// channel's traffic keys. The shapes' extra wire semantics (message vs datagram
/// boundaries, per-frame `stream_id`/`flags`) are not exposed here; reach for the
/// concrete channel type when you need them.
#[allow(async_fn_in_trait)]
pub trait SecureChannel {
    /// Error type returned by send/receive.
    type Error: std::error::Error;

    /// Seals and sends one application payload.
    async fn send_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error>;

    /// Receives and opens one application payload.
    async fn recv_payload(&mut self) -> Result<Vec<u8>, Self::Error>;
}

#[cfg(feature = "runtime-tokio")]
impl<T> SecureChannel for crate::TokioTransportChannel<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Error = foctet_core::CoreError;

    async fn send_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        self.send_application(payload).await
    }

    async fn recv_payload(&mut self) -> Result<Vec<u8>, Self::Error> {
        self.recv_application().await
    }
}

#[cfg(feature = "runtime-futures")]
impl<T> SecureChannel for crate::FuturesTransportChannel<T>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    type Error = foctet_core::CoreError;

    async fn send_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        self.send_application(payload).await
    }

    async fn recv_payload(&mut self) -> Result<Vec<u8>, Self::Error> {
        self.recv_application().await
    }
}

impl<T> SecureChannel for crate::message::SecureMessageChannel<T>
where
    T: crate::message::MessageTransport,
{
    type Error = crate::message::MessageChannelError<T::Error>;

    async fn send_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        self.send_message(0, 0, payload).await
    }

    async fn recv_payload(&mut self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.recv_message().await?.plaintext)
    }
}

impl<T> SecureChannel for crate::datagram::SecureDatagramChannel<T>
where
    T: crate::datagram::DatagramTransport,
{
    type Error = crate::datagram::DatagramChannelError<T::Error>;

    async fn send_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        self.send_datagram(0, 0, payload).await
    }

    async fn recv_payload(&mut self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.recv_datagram().await?.plaintext)
    }
}
