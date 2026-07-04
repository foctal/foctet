use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ::quinn as quinn_transport;
use clap::{Parser, ValueEnum};
use foctet_core::observe::{SessionEvent, SessionObserver};
use foctet_core::{IdentityKeyPair, PeerIdentity, RekeyThresholds, SessionAuthConfig};
use foctet_transport::adapter::SplitIo;
use foctet_transport::{TokioTransportBuilder, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;

const STREAM_COUNT: usize = 2;
const STREAM_TAG_LEN: usize = 4;

/// How to run the example.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Role {
    /// Run both peers in one process over the loopback (quick smoke test).
    #[default]
    Loopback,
    /// Run only the server: bind `--addr` and serve clients until Ctrl+C.
    Server,
    /// Run only the client: connect to a server at `--addr`.
    Client,
}

#[derive(Debug, Parser)]
struct Args {
    /// Which side to run. `loopback` (default) runs both in one process; use
    /// `server` and `client` in separate terminals / on two hosts.
    #[arg(long, value_enum, default_value_t = Role::Loopback)]
    role: Role,
    /// Server: address to bind. Client: address to connect to.
    /// Ignored for `loopback`. Default `127.0.0.1:4433`.
    #[arg(long, default_value = "127.0.0.1:4433")]
    addr: SocketAddr,
    /// TLS server name (SNI) the client validates against. Must match a cert SAN
    /// (the dev cert uses `localhost`). Default `localhost`.
    #[arg(long, default_value = "localhost")]
    server_name: String,
    /// TLS certificate path (PEM/DER). Required for `server`/`client` roles
    /// (server presents it; client trusts it). Use together with --tls-key on
    /// the server.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// TLS private key path (PEM/DER). Required for the `server` role.
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// Client only: present an identity the server did NOT pin, to demonstrate
    /// that identity-mismatch is rejected (the handshake must fail).
    #[arg(long, default_value_t = false)]
    wrong_identity: bool,
    /// Number of application messages to exchange per stream (request/reply
    /// round-trips). Raise it together with `--rekey-frames` to cross several
    /// DH-ratchet rekeys over a single live session. Default `1`.
    #[arg(long, default_value_t = 1)]
    messages: usize,
    /// Override `RekeyThresholds::max_frames` (frames sent before a rekey is
    /// triggered). Lower it (e.g. `--rekey-frames 4`) to force frequent rekeys
    /// for testing; unset keeps the library default. See §7 of `tests.md`.
    #[arg(long)]
    rekey_frames: Option<u64>,
}

fn auth_config_pair(idx: usize) -> (SessionAuthConfig, SessionAuthConfig) {
    let client_identity = IdentityKeyPair::from_secret_key_bytes([0x41 + idx as u8; 32]);
    let server_identity = IdentityKeyPair::from_secret_key_bytes([0x61 + idx as u8; 32]);
    let client = SessionAuthConfig::new()
        .with_local_identity(client_identity.clone())
        .with_peer_identity(PeerIdentity::new(server_identity.public_key()))
        .require_peer_authentication(true);
    let server = SessionAuthConfig::new()
        .with_local_identity(server_identity)
        .with_peer_identity(PeerIdentity::new(client_identity.public_key()))
        .require_peer_authentication(true);
    (client, server)
}

fn load_cert_chain(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error + Send + Sync>> {
    let data = std::fs::read(path)?;
    if path.extension().is_some_and(|ext| ext == "der") {
        return Ok(vec![CertificateDer::from(data)]);
    }

    let mut reader = std::io::BufReader::new(&data[..]);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("no certificate found in tls-cert".into());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn Error + Send + Sync>> {
    let data = std::fs::read(path)?;
    if path.extension().is_some_and(|ext| ext == "der") {
        return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(data)));
    }

    let mut reader = std::io::BufReader::new(&data[..]);
    let key = rustls_pemfile::private_key(&mut reader)?.ok_or("no private key found in tls-key")?;
    Ok(key)
}

fn resolve_cert_pair(
    args: &Args,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn Error + Send + Sync>> {
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Ok((load_cert_chain(cert)?, load_private_key(key)?)),
        (None, None) => {
            let cert = rcgen::generate_simple_self_signed(vec![
                "localhost".to_owned(),
                "127.0.0.1".to_owned(),
                "::1".to_owned(),
            ])?;
            let cert_der = CertificateDer::from(cert.cert);
            let key_der =
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
            Ok((vec![cert_der], key_der))
        }
        _ => Err("both --tls-cert and --tls-key must be provided together".into()),
    }
}

fn configure_server(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, Box<dyn Error + Send + Sync>> {
    let mut server_config = quinn_transport::ServerConfig::with_single_cert(cert_chain, key)?;
    let transport = Arc::get_mut(&mut server_config.transport)
        .expect("transport config must be uniquely owned");
    transport.max_concurrent_uni_streams(0_u8.into());
    Ok(server_config)
}

fn configure_client(
    cert_chain: &[CertificateDer<'static>],
) -> Result<quinn::ClientConfig, Box<dyn Error + Send + Sync>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in cert_chain {
        roots.add(cert.clone())?;
    }
    Ok(quinn_transport::ClientConfig::with_root_certificates(
        Arc::new(roots),
    )?)
}

fn is_graceful_quinn_close(err: &(dyn Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(item) = current {
        let msg = item.to_string();
        if msg.contains("ApplicationClosed")
            || msg.contains("ConnectionLost(ApplicationClosed")
            || msg.contains("error_code: 0")
            || msg.contains("NotConnected")
            || msg.contains("not connected")
        {
            return true;
        }
        current = item.source();
    }
    false
}

fn take_tagged_auth(
    auth_configs: &mut [Option<SessionAuthConfig>],
    tag: [u8; STREAM_TAG_LEN],
) -> Result<(usize, SessionAuthConfig), Box<dyn Error + Send + Sync>> {
    let idx = u32::from_be_bytes(tag) as usize;
    let Some(slot) = auth_configs.get_mut(idx) else {
        return Err(format!("received out-of-range stream tag {idx}").into());
    };
    let Some(auth) = slot.take() else {
        return Err(format!("received duplicate stream tag {idx}").into());
    };
    Ok((idx, auth))
}

fn rekey_thresholds(rekey_frames: Option<u64>) -> RekeyThresholds {
    let mut thresholds = RekeyThresholds::default();
    if let Some(max_frames) = rekey_frames {
        thresholds.max_frames = max_frames;
    }
    thresholds
}

/// Prints DH-ratchet rekey events so a live run can confirm that both sides'
/// keys actually rotate (see §7 of `tests.md`) — successful message delivery
/// alone would not distinguish a working ratchet from one that never fires.
struct RekeyLogger {
    side: &'static str,
    idx: usize,
}

impl SessionObserver for RekeyLogger {
    fn on_session_event(&self, event: SessionEvent) {
        match event {
            SessionEvent::RekeyInitiated {
                old_key_id,
                new_key_id,
            } => println!(
                "[{} stream {}] rekey initiated {old_key_id}->{new_key_id}",
                self.side, self.idx
            ),
            SessionEvent::RekeyApplied {
                old_key_id,
                new_key_id,
            } => println!(
                "[{} stream {}] rekey applied   {old_key_id}->{new_key_id}",
                self.side, self.idx
            ),
            _ => {}
        }
    }
}

async fn serve_connection(
    connection: quinn_transport::Connection,
    server_auth_configs: Vec<SessionAuthConfig>,
    messages: usize,
    thresholds: RekeyThresholds,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = TransportConfig::default().with_app_stream_id(1);
    let builder = TokioTransportBuilder::new().with_config(config);
    let mut server_auth_configs = server_auth_configs
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();
    let mut channels = Vec::with_capacity(server_auth_configs.len());

    // Read an explicit stream tag before building Foctet so accept order can vary safely.
    for _ in 0..server_auth_configs.len() {
        let (send, mut recv) = match connection.accept_bi().await {
            Ok(parts) => parts,
            Err(err) if is_graceful_quinn_close(&err) => return Ok(()),
            Err(err) => return Err(Box::new(err)),
        };
        let mut tag = [0u8; STREAM_TAG_LEN];
        recv.read_exact(&mut tag).await?;
        let (idx, auth) = take_tagged_auth(&mut server_auth_configs, tag)?;
        let channel = builder
            .establish_responder_with_auth(
                SplitIo::from_split(recv, send),
                thresholds.clone(),
                auth,
            )
            .await?;
        channels.push((idx, channel));
    }

    let mut tasks = JoinSet::new();
    for (idx, mut channel) in channels {
        tasks.spawn(async move {
            assert!(channel.session().peer_authenticated());
            channel.session_mut().set_observer(Arc::new(RekeyLogger {
                side: "server",
                idx,
            }));
            for msg_idx in 0..messages {
                let incoming = channel.recv_application().await?;
                let reply = format!(
                    "quinn stream {idx} message {msg_idx} reply to: {}",
                    String::from_utf8_lossy(&incoming)
                );
                channel.send_application(reply.as_bytes()).await?;
            }
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) if is_graceful_quinn_close(err.as_ref()) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => return Err(Box::new(err)),
        }
    }
    // Keep the connection alive until the client has read its replies and closed.
    connection.closed().await;
    Ok(())
}

async fn run_client(
    endpoint: quinn_transport::Endpoint,
    remote: SocketAddr,
    server_name: &str,
    client_auth_configs: Vec<SessionAuthConfig>,
    messages: usize,
    thresholds: RekeyThresholds,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let connection = endpoint.connect(remote, server_name)?.await?;
    let config = TransportConfig::default().with_app_stream_id(1);
    let builder = TokioTransportBuilder::new().with_config(config);
    let mut channels = Vec::with_capacity(client_auth_configs.len());

    // Write a small cleartext tag on each raw stream so the server can bind the right Foctet
    // session even if transport accept order differs from open order.
    for (idx, auth) in client_auth_configs.into_iter().enumerate() {
        let (mut send, recv) = match connection.open_bi().await {
            Ok(parts) => parts,
            Err(err) if is_graceful_quinn_close(&err) => return Ok(()),
            Err(err) => return Err(Box::new(err)),
        };
        send.write_all(&(idx as u32).to_be_bytes()).await?;
        send.flush().await?;
        let channel = builder
            .establish_initiator_with_auth(
                SplitIo::from_split(recv, send),
                thresholds.clone(),
                auth,
            )
            .await?;
        channels.push((idx, channel));
    }

    let mut tasks = JoinSet::new();
    for (idx, mut channel) in channels {
        tasks.spawn(async move {
            assert!(channel.session().peer_authenticated());
            channel.session_mut().set_observer(Arc::new(RekeyLogger {
                side: "client",
                idx,
            }));
            for msg_idx in 0..messages {
                let payload = format!("hello from quinn stream {idx} message {msg_idx}");
                channel.send_application(payload.as_bytes()).await?;
                let response = channel.recv_application().await?;

                println!(
                    "client stream {idx} message {msg_idx} got: {}",
                    String::from_utf8_lossy(&response)
                );
            }
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) if is_graceful_quinn_close(err.as_ref()) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => return Err(Box::new(err)),
        }
    }
    Ok(())
}

fn server_auth_configs() -> Vec<SessionAuthConfig> {
    (0..STREAM_COUNT)
        .map(|idx| auth_config_pair(idx).1)
        .collect()
}

fn client_auth_configs(wrong_identity: bool) -> Vec<SessionAuthConfig> {
    (0..STREAM_COUNT)
        .map(|idx| {
            let client = auth_config_pair(idx).0;
            if wrong_identity {
                // Replace the local identity with one the server never pinned, so
                // the server's `require_peer_authentication` check must reject.
                client.with_local_identity(IdentityKeyPair::from_secret_key_bytes([0xFF; 32]))
            } else {
                client
            }
        })
        .collect()
}

/// Loopback: both peers in one process over an ephemeral port (quick smoke test).
async fn run_loopback(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (cert_chain, key) = resolve_cert_pair(args)?;
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let server_config = configure_server(cert_chain.clone(), key)?;
    let server_endpoint = quinn_transport::Endpoint::server(server_config, bind_addr)?;
    let server_addr = server_endpoint.local_addr()?;

    let client_config = configure_client(&cert_chain)?;
    let mut client_endpoint = quinn_transport::Endpoint::client(bind_addr)?;
    client_endpoint.set_default_client_config(client_config);

    let messages = args.messages;
    let server_thresholds = rekey_thresholds(args.rekey_frames);
    let client_thresholds = rekey_thresholds(args.rekey_frames);

    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.ok_or("endpoint closed")?;
        let connection = incoming.await?;
        serve_connection(
            connection,
            server_auth_configs(),
            messages,
            server_thresholds,
        )
        .await
    });
    if let Err(err) = run_client(
        client_endpoint,
        server_addr,
        "localhost",
        client_auth_configs(false),
        messages,
        client_thresholds,
    )
    .await
        && !is_graceful_quinn_close(err.as_ref())
    {
        return Err(err);
    }
    match server_task.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) if is_graceful_quinn_close(err.as_ref()) => {}
        Ok(Err(err)) => return Err(err),
        Err(err) => return Err(Box::new(err)),
    }
    println!("quinn multi-stream foctet E2EE example finished");
    Ok(())
}

/// Server role: bind `addr` and serve incoming connections until Ctrl+C.
async fn run_server_role(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    if args.tls_cert.is_none() || args.tls_key.is_none() {
        return Err(
            "the `server` role requires --tls-cert and --tls-key (e.g. devcert/localhost.crt \
             and devcert/localhost.key); the client must trust the same cert"
                .into(),
        );
    }
    let (cert_chain, key) = resolve_cert_pair(args)?;
    let server_config = configure_server(cert_chain, key)?;
    let endpoint = quinn_transport::Endpoint::server(server_config, args.addr)?;
    println!("quinn server listening on {} (Ctrl+C to stop)", args.addr);

    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(err) => {
                eprintln!("connection failed: {err}");
                continue;
            }
        };
        let peer = connection.remote_address();
        println!("accepted connection from {peer}");

        let messages = args.messages;
        let thresholds = rekey_thresholds(args.rekey_frames);

        match serve_connection(connection, server_auth_configs(), messages, thresholds).await {
            Ok(()) => println!("served {peer}"),
            Err(err) if is_graceful_quinn_close(err.as_ref()) => {}
            Err(err) => eprintln!("error serving {peer}: {err}"),
        }
    }
    Ok(())
}

/// Client role: connect to a server at `addr`.
async fn run_client_role(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    let Some(cert) = &args.tls_cert else {
        return Err(
            "the `client` role requires --tls-cert (the server's cert, to trust it; \
             e.g. devcert/localhost.crt)"
                .into(),
        );
    };
    let cert_chain = load_cert_chain(cert)?;
    let client_config = configure_client(&cert_chain)?;
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let mut endpoint = quinn_transport::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    println!("quinn client connecting to {}", args.addr);
    run_client(
        endpoint,
        args.addr,
        &args.server_name,
        client_auth_configs(args.wrong_identity),
        args.messages,
        rekey_thresholds(args.rekey_frames),
    )
    .await?;
    println!("quinn client finished");
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    match args.role {
        Role::Loopback => run_loopback(&args).await,
        Role::Server => run_server_role(&args).await,
        Role::Client => run_client_role(&args).await,
    }
}
