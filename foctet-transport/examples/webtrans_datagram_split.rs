// WebTransport datagram example (tests.md §3.5). A browser page drives the WASM
// `FoctetSession` against the `server` role here, over a real `WebTransport`.
//
// Raw datagrams have no handshake of their own, so this follows the documented
// pattern: run the authenticated Foctet handshake over a *reliable* bidi
// WebTransport stream, then carry the sealed application data as
// loss/reorder-tolerant WebTransport datagrams (one Foctet datagram frame per
// transport datagram — the exact shape the browser SDK's
// `sealDatagram`/`openDatagram` produce). The `client`/`loopback` roles drive
// the same wire format natively, so the protocol can be smoke-tested without a
// browser.
//
// TLS: for a browser, generate a short-lived ECDSA P-256 dev cert with
// `devcert/generate.sh` and pass `--tls-cert devcert/localhost.crt --tls-key
// devcert/localhost.key`; the browser pins its SHA-256 from `devcert/localhost.hex`
// via `serverCertificateHashes`. With no `--tls-*` the example self-signs (fine
// for the native `client`/`loopback` roles).
//
// Demo identities are hardcoded for local examples only.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use ::webtrans::quinn::SessionError;
use ::webtrans::{ClientBuilder, ServerBuilder, Session as WebtransSession, tls};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use foctet_core::{
    ControlMessage, IdentityKeyPair, MAX_CONTROL_MESSAGE_LEN, PeerIdentity, RekeyThresholds,
    Session, SessionAuthConfig,
};
use foctet_transport::adapter::SplitIo;
use foctet_transport::{DatagramTransport, SecureDatagramChannel, TokioTransportBuilder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

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
    /// Server: UDP address to bind. Client: address to connect to. Ignored for
    /// `loopback` (ephemeral). Default `127.0.0.1:4470`.
    #[arg(long, default_value = "127.0.0.1:4470")]
    addr: SocketAddr,
    /// TLS certificate path (PEM/DER). Use together with `--tls-key`. Required
    /// for a browser client so it can pin the cert hash.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// TLS private key path (PEM/DER). Use together with `--tls-cert`.
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// Client/loopback: number of datagrams to send. Default `4`.
    #[arg(long, default_value_t = 4)]
    datagrams: usize,
    /// Test hook: drop the first outbound application datagram.
    #[arg(long, default_value_t = false)]
    drop_first_reply: bool,
    /// Test hook: emit outbound application datagrams in reversed pairs.
    #[arg(long, default_value_t = false)]
    reorder_reply_pairs: bool,
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

fn find_free_udp_addr() -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    let sock = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
    Ok(sock.local_addr()?)
}

fn resolve_cert_pair(
    args: &Args,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn Error + Send + Sync>> {
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Ok(tls::load_cert(cert, key)?),
        (None, None) => Ok(tls::generate_self_signed_pair_der(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ])?),
        _ => Err("both --tls-cert and --tls-key must be provided together".into()),
    }
}

/// Adapts a WebTransport session's datagram side to [`DatagramTransport`], so a
/// [`SecureDatagramChannel`] can seal/open Foctet datagram frames over it. The
/// session's own session-ID header is added/stripped by the webtrans layer, so
/// each datagram here carries exactly one Foctet frame.
struct WebtransDatagramTransport {
    session: Arc<WebtransSession>,
    drop_next: AtomicBool,
    reorder_pairs: bool,
    pending_reply: Mutex<Option<Vec<u8>>>,
}

impl DatagramTransport for WebtransDatagramTransport {
    type Error = SessionError;

    async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Self::Error> {
        if self.drop_next.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        if self.reorder_pairs {
            let pending = {
                let mut pending = self.pending_reply.lock().expect("reply buffer lock");
                match pending.take() {
                    Some(first) => Some(first),
                    None => {
                        *pending = Some(datagram);
                        return Ok(());
                    }
                }
            };
            self.session.send_datagram(Bytes::from(datagram))?;
            self.session
                .send_datagram(Bytes::from(pending.expect("present")))?;
            return Ok(());
        }
        self.session.send_datagram(Bytes::from(datagram))
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.session.read_datagram().await?.to_vec())
    }

    fn max_datagram_size(&self) -> Option<usize> {
        // The channel clamps its own default down to this reported maximum.
        Some(self.session.max_datagram_size())
    }
}

/// Server side: authenticate over one bidi stream, then echo sealed datagrams.
async fn serve(
    session: WebtransSession,
    drop_first_reply: bool,
    reorder_reply_pairs: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Handshake over a reliable bidi stream (byte-framed Foctet handshake).
    let (mut send, mut recv) = session.accept_bi().await?;
    let mut protocol = Session::new_responder_with_auth(RekeyThresholds::default(), server_auth());
    let hello = read_control(&mut recv).await?;
    let reply = protocol
        .handle_control(&hello)?
        .ok_or("responder did not produce ServerHello")?;
    write_control(&mut send, &reply).await?;
    assert!(
        protocol.peer_authenticated(),
        "peer failed identity authentication"
    );
    println!("handshake complete; peer authenticated");
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        loop {
            match read_control(&mut recv).await {
                Ok(control) => {
                    if control_tx.send(control).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    eprintln!("control stream ended: {error}");
                    break;
                }
            }
        }
    });

    let session = Arc::new(session);
    let transport = WebtransDatagramTransport {
        session: session.clone(),
        drop_next: AtomicBool::new(drop_first_reply),
        reorder_pairs: reorder_reply_pairs,
        pending_reply: Mutex::new(None),
    };
    let mut datagram = SecureDatagramChannel::from_active_session(transport, &protocol)?;
    loop {
        tokio::select! {
            incoming = datagram.recv_datagram() => {
                let incoming = match incoming {
                    Ok(message) => message,
                    Err(_) => break,
                };
                let reply = format!(
                    "webtrans datagram echo: {}",
                    String::from_utf8_lossy(&incoming.plaintext)
                );
                datagram.send_datagram(0, 0, reply.as_bytes()).await?;
                println!("echoed {} byte(s)", incoming.plaintext.len());
            }
            control = control_rx.recv() => {
                let control = match control {
                    Some(control) => control,
                    None => break,
                };
                protocol.handle_control(&control)?;
                datagram.rekey_from_session(&protocol)?;
                // Test-harness acknowledgement: this is outer transport
                // coordination, not a Foctet control message. It proves the
                // receiver adopted the key before the browser commits and
                // sends new-key datagrams on a separately ordered channel.
                send.write_u16(1).await?;
                send.write_all(&[0xac]).await?;
                send.flush().await?;
                println!("applied interleaved rekey control");
            }
        }
    }
    Ok(())
}

async fn read_control(
    recv: &mut webtrans::RecvStream,
) -> Result<ControlMessage, Box<dyn Error + Send + Sync>> {
    let len = recv.read_u16().await? as usize;
    if len == 0 || len > MAX_CONTROL_MESSAGE_LEN {
        return Err("invalid control length".into());
    }
    let mut encoded = vec![0u8; len];
    recv.read_exact(&mut encoded).await?;
    Ok(ControlMessage::decode(&encoded)?)
}

async fn write_control(
    send: &mut webtrans::SendStream,
    control: &ControlMessage,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let encoded = control.encode();
    send.write_u16(encoded.len() as u16).await?;
    send.write_all(&encoded).await?;
    send.flush().await?;
    Ok(())
}

/// Client side: authenticate over one bidi stream, then send `datagrams` sealed
/// datagrams and read each echo.
async fn run_client(
    session: WebtransSession,
    datagrams: usize,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (mut send, recv) = session.open_bi().await?;
    // Nudge the stream open so the server's `accept_bi` fires before we block.
    send.flush().await?;
    let channel = TokioTransportBuilder::new()
        .establish_initiator_with_auth(
            SplitIo::from_split(recv, send),
            RekeyThresholds::default(),
            client_auth(),
        )
        .await?;
    assert!(
        channel.session().peer_authenticated(),
        "peer failed identity authentication"
    );

    let session = Arc::new(session);
    let transport = WebtransDatagramTransport {
        session: session.clone(),
        drop_next: AtomicBool::new(false),
        reorder_pairs: false,
        pending_reply: Mutex::new(None),
    };
    let mut datagram = SecureDatagramChannel::from_active_session(transport, channel.session())?;
    for idx in 0..datagrams {
        let payload = format!("hello from native client {idx}");
        datagram.send_datagram(0, 0, payload.as_bytes()).await?;
        let echo = datagram.recv_datagram().await?;
        println!(
            "client datagram {idx} got: {}",
            String::from_utf8_lossy(&echo.plaintext)
        );
    }
    Ok(())
}

async fn connect_client(
    addr: SocketAddr,
    cert_chain: Vec<CertificateDer<'static>>,
) -> Result<WebtransSession, Box<dyn Error + Send + Sync>> {
    let client = ClientBuilder::new().with_server_certificates(cert_chain)?;
    let url = Url::parse(&format!("https://127.0.0.1:{}/", addr.port()))?;
    Ok(client.connect(url).await?)
}

async fn run_server_role(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (cert_chain, key) = resolve_cert_pair(args)?;
    let mut server = ServerBuilder::new()
        .with_addr(args.addr)
        .with_certificate(cert_chain, key)?;
    println!(
        "webtrans datagram server listening on https://{}/ (Ctrl+C to stop)",
        args.addr
    );
    println!("demo keys are hardcoded for local examples only. do not use in production.");
    loop {
        let request = match server.accept().await {
            Some(request) => request,
            None => break,
        };
        let session = match request.ok().await {
            Ok(session) => session,
            Err(err) => {
                eprintln!("session setup failed: {err}");
                continue;
            }
        };
        println!("accepted a WebTransport session");
        let drop_first_reply = args.drop_first_reply;
        let reorder_reply_pairs = args.reorder_reply_pairs;
        tokio::spawn(async move {
            match serve(session, drop_first_reply, reorder_reply_pairs).await {
                Ok(()) => println!("session finished"),
                Err(err) => eprintln!("error serving session: {err}"),
            }
        });
    }
    Ok(())
}

async fn run_loopback(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (cert_chain, key) = resolve_cert_pair(args)?;
    let addr = find_free_udp_addr()?;
    let datagrams = args.datagrams;

    let mut server = ServerBuilder::new()
        .with_addr(addr)
        .with_certificate(cert_chain.clone(), key)?;
    let server_side = async move {
        let request = server.accept().await.ok_or("server closed")?;
        let session = request.ok().await?;
        serve(session, false, false).await
    };
    let client_side = async move {
        let session = connect_client(addr, cert_chain).await?;
        run_client(session, datagrams).await
    };
    // The webtrans session type is not `Send`, so run both concurrently on this
    // task with `join!` rather than spawning.
    let (server_res, client_res) = tokio::join!(server_side, client_side);
    server_res?;
    client_res?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    match args.role {
        Role::Loopback => {
            run_loopback(&args).await?;
            println!("webtrans datagram loopback example finished");
        }
        Role::Server => run_server_role(&args).await?,
        Role::Client => {
            let (cert_chain, _key) = resolve_cert_pair(&args)?;
            let session = connect_client(args.addr, cert_chain).await?;
            run_client(session, args.datagrams).await?;
            println!("webtrans datagram client finished");
        }
    }
    Ok(())
}
