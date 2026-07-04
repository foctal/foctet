// Native raw-WebSocket message echo endpoint for the browser interop test
// (tests.md §3.3). A browser page drives the WASM `FoctetSession` as the
// handshake *initiator* over a browser `WebSocket`; the `server` role here is
// the *responder*. Each WebSocket binary message carries exactly one Foctet
// frame: first the handshake control messages, then sealed application
// messages.
//
// Unlike `websock_split` (which uses the multiplexed `websock-mux` byte-stream
// shape), this speaks the raw-message shape (`WebsockMessageTransport` +
// `SecureMessageChannel`) that the browser SDK produces with
// `sealMessage`/`openMessage`, so it is the native counterpart for a Rust/wasm
// front-end. The `client`/`loopback` roles drive the same wire format from
// native code, so the protocol can be smoke-tested without a browser.
//
// The demo keys are hardcoded for local examples only; each side pins the
// other's identity.

use std::error::Error;
use std::net::SocketAddr;

use clap::{Parser, ValueEnum};
use foctet_core::{
    ControlMessage, IdentityKeyPair, PeerIdentity, RekeyThresholds, Session, SessionAuthConfig,
};
use foctet_transport::websock::WebsockMessageTransport;
use foctet_transport::{MessageTransport, SecureMessageChannel};
use websock::{ClientBuilder, ServerBuilder, WebSocketConnection};

// Demo identities shared with the browser page (see examples/browser). The
// initiator (browser or `client` role) uses `CLIENT_SECRET`; the responder
// (`server` role) uses `SERVER_SECRET`. Each side pins the other's public key.
const CLIENT_SECRET: [u8; 32] = [0x41; 32];
const SERVER_SECRET: [u8; 32] = [0x61; 32];

/// How to run the example.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Role {
    /// Run a native client and server in one process (quick smoke test).
    #[default]
    Loopback,
    /// Run only the responder: bind `--addr` and serve browser/native clients.
    Server,
    /// Run only the native initiator: connect to a server at `--addr`.
    Client,
}

#[derive(Debug, Parser)]
struct Args {
    /// Which side to run. `loopback` (default) runs both natively in one
    /// process; use `server` for the browser test and `client` for a native
    /// initiator.
    #[arg(long, value_enum, default_value_t = Role::Loopback)]
    role: Role,
    /// Server: address to bind (`ws://`). Client: address to connect to.
    /// Ignored for `loopback`. Default `127.0.0.1:4460`.
    #[arg(long, default_value = "127.0.0.1:4460")]
    addr: SocketAddr,
    /// Client/loopback: number of application messages to send. Default `2`.
    #[arg(long, default_value_t = 2)]
    messages: usize,
}

fn client_auth() -> SessionAuthConfig {
    let client_identity = IdentityKeyPair::from_secret_key_bytes(CLIENT_SECRET);
    let server_public = IdentityKeyPair::from_secret_key_bytes(SERVER_SECRET).public_key();
    SessionAuthConfig::new()
        .with_local_identity(client_identity)
        .with_peer_identity(PeerIdentity::new(server_public))
        .require_peer_authentication(true)
}

fn server_auth() -> SessionAuthConfig {
    let server_identity = IdentityKeyPair::from_secret_key_bytes(SERVER_SECRET);
    let client_public = IdentityKeyPair::from_secret_key_bytes(CLIENT_SECRET).public_key();
    SessionAuthConfig::new()
        .with_local_identity(server_identity)
        .with_peer_identity(PeerIdentity::new(client_public))
        .require_peer_authentication(true)
}

/// Drives a handshake to completion over discrete WebSocket messages, decoding
/// each inbound control frame and sending any reply as one binary message.
async fn run_handshake<C>(
    transport: &WebsockMessageTransport<C>,
    session: &mut Session,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: WebSocketConnection,
{
    while session.active_keys().is_none() {
        let bytes = transport.recv_message().await?;
        let control = ControlMessage::decode(&bytes)?;
        if let Some(reply) = session.handle_control(&control)? {
            transport.send_message(reply.encode()).await?;
        }
    }
    Ok(())
}

/// Server side: responder handshake, then echo each sealed application message.
async fn serve_connection<C>(
    transport: WebsockMessageTransport<C>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: WebSocketConnection,
{
    let mut session = Session::new_responder_with_auth(RekeyThresholds::default(), server_auth());
    run_handshake(&transport, &mut session).await?;
    assert!(
        session.peer_authenticated(),
        "peer failed identity authentication"
    );
    println!("handshake complete; peer authenticated");

    let mut channel = SecureMessageChannel::from_active_session(transport, &session)?;
    loop {
        let opened = match channel.recv_message().await {
            Ok(message) => message,
            // A normal peer close ends the read loop.
            Err(_) => break,
        };
        let reply = format!(
            "websock-message echo: {}",
            String::from_utf8_lossy(&opened.plaintext)
        );
        channel
            .send_message(opened.header.stream_id, 0, reply.as_bytes())
            .await?;
        println!(
            "echoed {} byte(s) on stream {}",
            opened.plaintext.len(),
            opened.header.stream_id
        );
    }
    Ok(())
}

/// Client side: initiator handshake, then send `messages` sealed messages and
/// read each echo.
async fn run_client<C>(
    transport: WebsockMessageTransport<C>,
    messages: usize,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: WebSocketConnection,
{
    let (mut session, hello) =
        Session::new_initiator_with_auth(RekeyThresholds::default(), client_auth());
    transport.send_message(hello.encode()).await?;
    run_handshake(&transport, &mut session).await?;
    assert!(
        session.peer_authenticated(),
        "peer failed identity authentication"
    );

    let mut channel = SecureMessageChannel::from_active_session(transport, &session)?;
    for idx in 0..messages {
        let payload = format!("hello from native client {idx}");
        channel.send_message(0, 0, payload.as_bytes()).await?;
        let echo = channel.recv_message().await?;
        println!(
            "client message {idx} got: {}",
            String::from_utf8_lossy(&echo.plaintext)
        );
    }
    Ok(())
}

async fn connect_client(
    addr: SocketAddr,
) -> Result<WebsockMessageTransport<websock::Connection>, Box<dyn Error + Send + Sync>> {
    let connection = ClientBuilder::new()
        .build()
        .connect(&format!("ws://{addr}/"))
        .await?;
    Ok(WebsockMessageTransport::new(connection))
}

async fn run_server_role(addr: SocketAddr) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = ServerBuilder::new().with_addr(addr).build().await?;
    let bound = server.local_addr()?;
    println!("websock message server listening on ws://{bound}/ (Ctrl+C to stop)");
    println!("demo keys are hardcoded for local examples only. do not use in production.");
    loop {
        let connection = match server.accept().await {
            Ok(connection) => connection,
            Err(err) => {
                eprintln!("accept failed: {err}");
                continue;
            }
        };
        println!("accepted a WebSocket connection");
        let transport = WebsockMessageTransport::new(connection);
        match serve_connection(transport).await {
            Ok(()) => println!("connection finished"),
            Err(err) => eprintln!("error serving connection: {err}"),
        }
    }
}

async fn run_loopback(messages: usize) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = ServerBuilder::new()
        .with_addr("127.0.0.1:0".parse::<SocketAddr>()?)
        .build()
        .await?;
    let addr = server.local_addr()?;

    // The server connection type is not `Send`, so run both sides concurrently
    // on this task with `join!` rather than spawning.
    let server_side = async {
        let connection = server.accept().await?;
        serve_connection(WebsockMessageTransport::new(connection)).await
    };
    let client_side = async {
        let transport = connect_client(addr).await?;
        run_client(transport, messages).await
    };
    let (server_res, client_res) = tokio::join!(server_side, client_side);
    server_res?;
    client_res?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    match args.role {
        Role::Loopback => {
            run_loopback(args.messages).await?;
            println!("websock message loopback example finished");
        }
        Role::Server => run_server_role(args.addr).await?,
        Role::Client => {
            let transport = connect_client(args.addr).await?;
            run_client(transport, args.messages).await?;
            println!("websock message client finished");
        }
    }
    Ok(())
}
