//! Synthetic local socket bridge for dependency/runtime regression testing.
//! Production applications must also enforce inbound queue and lifetime quotas.
use foctet_core::{IdentityKeyPair, PeerIdentity, RekeyThresholds, Session, SessionAuthConfig};
use foctet_transport::{SecureMessageChannel, websock::WebsockMessageTransport};
use futures_util::StreamExt;
use websock::{Error, LocalBoxFuture, Message, WebSocketConnection};

struct Connection<'a> {
    socket: &'a worker::WebSocket,
    events: worker::EventStream<'a>,
}
impl WebSocketConnection for Connection<'_> {
    fn send<'a>(&'a mut self, message: Message) -> LocalBoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            match message {
                Message::Binary(bytes) => self.socket.send_with_bytes(bytes),
                Message::Text(text) => self.socket.send_with_str(text),
            }
            .map_err(|_| Error::Closed)
        })
    }
    fn recv<'a>(&'a mut self) -> LocalBoxFuture<'a, Result<Message, Error>> {
        Box::pin(async move {
            match self.events.next().await {
                Some(Ok(worker::WebsocketEvent::Message(message))) => {
                    if let Some(bytes) = message.bytes() {
                        Ok(Message::Binary(bytes.into()))
                    } else if let Some(text) = message.text() {
                        Ok(Message::Text(text))
                    } else {
                        Err(Error::Protocol("unsupported message".into()))
                    }
                }
                _ => Err(Error::Closed),
            }
        })
    }
    fn close<'a>(&'a mut self) -> LocalBoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            self.socket
                .close(Some(1000), None::<&str>)
                .map_err(|_| Error::Closed)
        })
    }
}

pub async fn check() -> worker::Result<worker::Response> {
    use foctet_transport::MessageTransport;
    let pair = worker::WebSocketPair::new()?;
    // Recent compatibility dates can deliver binary events as Blob by default.
    // MessageEvent::bytes expects ArrayBuffer, so select it before accepting.
    pair.client
        .as_ref()
        .set_binary_type(worker::web_sys::BinaryType::Arraybuffer);
    pair.server
        .as_ref()
        .set_binary_type(worker::web_sys::BinaryType::Arraybuffer);
    let client = Connection {
        socket: &pair.client,
        events: pair.client.events()?,
    };
    let server = Connection {
        socket: &pair.server,
        events: pair.server.events()?,
    };
    pair.client.accept()?;
    pair.server.accept()?;
    let client_id = IdentityKeyPair::from_secret_key_bytes([61; 32]);
    let server_id = IdentityKeyPair::from_secret_key_bytes([62; 32]);
    let client_pin = PeerIdentity::new(client_id.public_key());
    let server_pin = PeerIdentity::new(server_id.public_key());
    let (mut initiator, hello) = Session::new_initiator_with_auth(
        RekeyThresholds::default(),
        SessionAuthConfig::new()
            .with_local_identity(client_id)
            .with_peer_identity(server_pin),
    );
    let mut responder = Session::new_responder_with_auth(
        RekeyThresholds::default(),
        SessionAuthConfig::new()
            .with_local_identity(server_id)
            .with_peer_identity(client_pin),
    );
    let reply = responder
        .handle_control(&hello)
        .map_err(super::error)?
        .ok_or_else(|| super::error("missing handshake reply"))?;
    initiator.handle_control(&reply).map_err(super::error)?;
    let client = WebsockMessageTransport::with_max_message_size(client, 4096);
    let server = WebsockMessageTransport::with_max_message_size(server, 4096);
    {
        let mut sender =
            SecureMessageChannel::from_active_session(client, &initiator).map_err(super::error)?;
        let mut receiver =
            SecureMessageChannel::from_active_session(server, &responder).map_err(super::error)?;
        sender
            .send_message(0, 0, b"worker encrypted websocket")
            .await
            .map_err(super::error)?;
        let opened = receiver.recv_message().await.map_err(super::error)?;
        if opened.plaintext != b"worker encrypted websocket" {
            return worker::Response::error("Wrong plaintext", 500);
        }
        receiver
            .send_message(0, 0, b"authenticated reply")
            .await
            .map_err(super::error)?;
        let opened = sender.recv_message().await.map_err(super::error)?;
        if opened.plaintext != b"authenticated reply" {
            return worker::Response::error("Wrong reply", 500);
        }
    }
    // Use fresh listeners to verify that the adapter rejects text frames.
    let transport = WebsockMessageTransport::new(Connection {
        socket: &pair.server,
        events: pair.server.events()?,
    });
    pair.client.send_with_str("not a Foctet binary frame")?;
    if transport.recv_message().await.is_ok() {
        return worker::Response::error("Text accepted", 500);
    }
    pair.client.close(Some(1000), None::<&str>)?;
    drop(transport);
    worker::Response::from_json(&true)
}
