//! High-level Foctet integration helpers for WebSocket transports.
//!
//! Two shapes are supported:
//!
//! - **Byte stream over a multiplexed WebSocket** (the `*_secure_channel*`
//!   helpers below): a Foctet [`crate::TokioTransportChannel`] runs over a
//!   `websock-tungstenite-mux` bidirectional stream, treating the connection as
//!   an opaque byte stream.
//! - **Discrete messages over a raw WebSocket** ([`WebsockMessageTransport`]):
//!   each Foctet frame is one binary WebSocket message, preserving message
//!   boundaries. Pair it with [`crate::SecureMessageChannel`].
//!
//! # Multiplexing and backpressure (normative for these adapters)
//!
//! - **Raw (message) shape:** one WebSocket connection carries one Foctet
//!   session. Foctet's `stream_id` provides *logical* multiplexing inside that
//!   session (independent replay windows per `(key_id, stream_id)`), but all
//!   streams share the connection's ordering and flow control — a slow
//!   consumer stalls every logical stream (head-of-line blocking, as with any
//!   single WebSocket). Do not share one connection between independent
//!   sessions: frames from two sessions would be indistinguishable at the
//!   transport layer.
//! - **Mux shape:** `websock-tungstenite-mux` provides real per-stream
//!   multiplexing; each mux stream carries exactly one Foctet channel, and the
//!   mux layer owns fairness between streams.
//! - **Backpressure** is delegated to the WebSocket implementation: sends
//!   await the underlying socket's readiness (TCP flow control), and receives
//!   are pulled one message at a time — this adapter never buffers more than
//!   the single in-flight message per direction. Sender-side queueing above
//!   the socket (e.g. an unbounded channel feeding this adapter) reintroduces
//!   unbounded memory; if you add a queue, bound it. Oversized inbound
//!   messages are rejected by [`foctet_core::MessageConfig`]'s
//!   `max_message_size` before allocation, so a hostile peer cannot force
//!   unbounded buffering at the Foctet layer.

use futures_util::lock::Mutex;
use websock::{Error as WebsockError, Message, WebSocketConnection};

use crate::message::MessageTransport;

#[cfg(feature = "transport-websock-mux")]
use crate::{
    TokioTransportBuilder, TokioTransportChannel, TransportChannelError, TransportConfig,
    adapter::SplitIo,
};
#[cfg(feature = "transport-websock-mux")]
use foctet_core::{RekeyThresholds, Session, SessionAuthConfig};
#[cfg(feature = "transport-websock-mux")]
use websock_tungstenite_mux as websock_mux;

/// A [`MessageTransport`] over a raw (non-multiplexed) WebSocket connection.
///
/// Each Foctet frame travels as exactly one **binary** WebSocket message, so the
/// message-bounded shape of [`crate::SecureMessageChannel`] maps directly onto
/// WebSocket framing (unlike the byte-stream mux helpers in this module, which
/// treat the socket as an opaque stream).
///
/// It is generic over the `websock` crate's cross-platform
/// [`WebSocketConnection`] trait, so the same adapter works over the native
/// (`websock-tungstenite`) connection **and** the browser
/// (`websock-wasm`) WebSocket connection — a Rust/wasm front-end can run a
/// `SecureMessageChannel` over a browser `WebSocket` with no JavaScript glue.
///
/// Negotiate a [`foctet_core::Session`] first (for example over a Foctet control
/// stream or an out-of-band handshake), then wrap the connection:
///
/// ```rust,no_run
/// use foctet_core::Session;
/// use foctet_transport::{MessageChannelError, SecureMessageChannel};
/// use foctet_transport::websock::WebsockMessageTransport;
/// use websock::{Error, WebSocketConnection};
///
/// async fn send<C: WebSocketConnection>(
///     connection: C,
///     session: &Session,
/// ) -> Result<(), MessageChannelError<Error>> {
///     let transport = WebsockMessageTransport::new(connection);
///     let mut channel = SecureMessageChannel::from_active_session(transport, session)?;
///     channel.send_message(0, 0, b"hello").await
/// }
/// ```
///
/// Sends and receives are serialized through an internal async lock, matching
/// the sequential `&mut self` API of `SecureMessageChannel`. Incoming **text**
/// frames are rejected — Foctet messages are always binary.
pub struct WebsockMessageTransport<C> {
    conn: Mutex<C>,
}

impl<C> WebsockMessageTransport<C> {
    /// Wraps an established WebSocket connection as a message transport.
    pub fn new(connection: C) -> Self {
        Self {
            conn: Mutex::new(connection),
        }
    }

    /// Consumes the transport and returns the underlying connection.
    pub fn into_inner(self) -> C {
        self.conn.into_inner()
    }
}

impl<C> MessageTransport for WebsockMessageTransport<C>
where
    C: WebSocketConnection,
{
    type Error = WebsockError;

    async fn send_message(&self, message: Vec<u8>) -> Result<(), Self::Error> {
        let mut conn = self.conn.lock().await;
        WebSocketConnection::send(&mut *conn, Message::Binary(message.into())).await
    }

    async fn recv_message(&self) -> Result<Vec<u8>, Self::Error> {
        let mut conn = self.conn.lock().await;
        match WebSocketConnection::recv(&mut *conn).await? {
            Message::Binary(bytes) => Ok(bytes.to_vec()),
            Message::Text(_) => Err(WebsockError::Protocol(
                "expected a binary Foctet message but received a text frame".into(),
            )),
        }
    }

    fn max_message_size(&self) -> Option<usize> {
        None
    }
}

/// Opens a bidirectional WebSocket-mux stream and wraps it as a Foctet secure channel.
#[cfg(feature = "transport-websock-mux")]
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel(
    session_handle: &websock_mux::Session,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    open_secure_channel_with(session_handle, session, TransportConfig::default()).await
}

/// Opens a bidirectional WebSocket-mux stream and applies a custom transport config.
#[cfg(feature = "transport-websock-mux")]
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel_with(
    session_handle: &websock_mux::Session,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    let (send, recv) = session_handle
        .open_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .build_from_split(recv, send, session)
        .map_err(TransportChannelError::core)
}

/// Opens a bidirectional WebSocket-mux stream, runs the native Foctet handshake, and wraps it as a secure channel.
#[cfg(feature = "transport-websock-mux")]
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel_with_handshake(
    session_handle: &websock_mux::Session,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        session_handle,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Opens a bidirectional WebSocket-mux stream, runs the native Foctet handshake, and applies a custom transport config.
#[cfg(feature = "transport-websock-mux")]
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn open_secure_channel_with_handshake_and_config(
    session_handle: &websock_mux::Session,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        session_handle,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Opens a bidirectional WebSocket-mux stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
#[cfg(feature = "transport-websock-mux")]
pub async fn open_secure_channel_with_handshake_and_auth_config(
    session_handle: &websock_mux::Session,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    let (send, recv) = session_handle
        .open_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .establish_initiator_with_auth(SplitIo::from_split(recv, send), thresholds, auth)
        .await
        .map_err(TransportChannelError::core)
}

/// Accepts a bidirectional WebSocket-mux stream and wraps it as a Foctet secure channel.
#[cfg(feature = "transport-websock-mux")]
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel(
    session_handle: &websock_mux::Session,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    accept_secure_channel_with(session_handle, session, TransportConfig::default()).await
}

/// Accepts a bidirectional WebSocket-mux stream and applies a custom transport config.
#[cfg(feature = "transport-websock-mux")]
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel_with(
    session_handle: &websock_mux::Session,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    let (send, recv) = session_handle
        .accept_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .build_from_split(recv, send, session)
        .map_err(TransportChannelError::core)
}

/// Accepts a bidirectional WebSocket-mux stream, runs the native Foctet handshake, and wraps it as a secure channel.
#[cfg(feature = "transport-websock-mux")]
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel_with_handshake(
    session_handle: &websock_mux::Session,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        session_handle,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Accepts a bidirectional WebSocket-mux stream, runs the native Foctet handshake, and applies a custom transport config.
#[cfg(feature = "transport-websock-mux")]
#[cfg(feature = "dangerous-unauthenticated")]
pub async fn accept_secure_channel_with_handshake_and_config(
    session_handle: &websock_mux::Session,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        session_handle,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Accepts a bidirectional WebSocket-mux stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
#[cfg(feature = "transport-websock-mux")]
pub async fn accept_secure_channel_with_handshake_and_auth_config(
    session_handle: &websock_mux::Session,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<websock_mux::RecvStream, websock_mux::SendStream>>,
    TransportChannelError<websock::Error>,
> {
    let (send, recv) = session_handle
        .accept_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .establish_responder_with_auth(SplitIo::from_split(recv, send), thresholds, auth)
        .await
        .map_err(TransportChannelError::core)
}

// Native loopback integration test (real TCP/WebSocket); not built for wasm.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::SecureMessageChannel;
    use foctet_core::{RekeyThresholds, Session, SessionAuthConfig};
    use websock::{ClientBuilder, ServerBuilder};

    /// Drives a real native Foctet handshake so both sides share traffic keys.
    fn shared_session_keys() -> (Session, Session) {
        let (mut initiator, client_hello) = Session::new_initiator_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut responder = Session::new_responder_with_auth(
            RekeyThresholds::default(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let server_hello = responder
            .handle_control(&client_hello)
            .expect("responder handles client hello")
            .expect("responder returns a server hello");
        let none = initiator
            .handle_control(&server_hello)
            .expect("initiator finalizes");
        assert!(none.is_none(), "initiator must not reply to server hello");
        (initiator, responder)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn secure_message_channel_over_raw_websocket() {
        let (initiator, responder) = shared_session_keys();

        // Plain (non-TLS) WebSocket loopback on an ephemeral port.
        let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("valid loopback addr");
        let server = ServerBuilder::new()
            .with_addr(bind_addr)
            .build()
            .await
            .expect("build ws server");
        let addr = server.local_addr().expect("server addr");
        let accept = tokio::spawn(async move { server.accept().await });

        let client = ClientBuilder::new().build();
        let client_conn = client
            .connect(&format!("ws://{addr}/"))
            .await
            .expect("client connects");
        let server_conn = accept.await.expect("accept task joins").expect("accept");

        let mut client = SecureMessageChannel::from_active_session(
            WebsockMessageTransport::new(client_conn),
            &initiator,
        )
        .expect("client channel");
        let mut server = SecureMessageChannel::from_active_session(
            WebsockMessageTransport::new(server_conn),
            &responder,
        )
        .expect("server channel");

        // Client → server, one frame per WebSocket message.
        client
            .send_message(0, 0, b"hello over a raw websocket")
            .await
            .expect("client send");
        let opened = server.recv_message().await.expect("server recv");
        assert_eq!(opened.plaintext, b"hello over a raw websocket");

        // Server → client, exercising the reverse direction.
        server
            .send_message(0, 0, b"reply over a raw websocket")
            .await
            .expect("server send");
        let back = client.recv_message().await.expect("client recv");
        assert_eq!(back.plaintext, b"reply over a raw websocket");
    }
}
