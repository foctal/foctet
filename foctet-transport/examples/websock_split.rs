use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use foctet_core::{IdentityKeyPair, PeerIdentity, RekeyThresholds, SessionAuthConfig};
use foctet_transport::adapter::SplitIo;
use foctet_transport::{TokioTransportBuilder, TransportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use websock_tungstenite_mux::{ClientBuilder, ServerBuilder};

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

fn find_free_tcp_addr() -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    let sock = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
    let addr = sock.local_addr()?;
    Ok(addr)
}

fn resolve_cert_pair(
    args: &Args,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    Box<dyn Error + Send + Sync>,
> {
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Ok(websock_tungstenite_mux::tls::load_cert(cert, key)?),
        (None, None) => Ok(websock_tungstenite_mux::tls::generate_self_signed_pair_der(
            vec![
                "localhost".to_owned(),
                "127.0.0.1".to_owned(),
                "::1".to_owned(),
            ],
        )?),
        _ => Err("both --tls-cert and --tls-key must be provided together".into()),
    }
}

fn load_cert_chain(
    path: &std::path::Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Box<dyn Error + Send + Sync>> {
    let data = std::fs::read(path)?;
    if path.extension().is_some_and(|ext| ext == "der") {
        return Ok(vec![rustls::pki_types::CertificateDer::from(data)]);
    }
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("no certificate found in tls-cert".into());
    }
    Ok(certs)
}

fn build_client_tls(
    cert_chain: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<rustls::ClientConfig, Box<dyn Error + Send + Sync>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in cert_chain {
        roots.add(cert.clone())?;
    }

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn build_server_tls(
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, Box<dyn Error + Send + Sync>> {
    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?)
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

/// Serve one accepted websock-mux session: bind a Foctet session per raw stream,
/// echo each application payload back uppercased-tagged.
async fn serve_session(
    session: websock_tungstenite_mux::Session,
    server_auth_configs: Vec<SessionAuthConfig>,
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
        let (send, mut recv) = session.accept_bi().await?;
        let mut tag = [0u8; STREAM_TAG_LEN];
        recv.read_exact(&mut tag).await?;
        let (idx, auth) = take_tagged_auth(&mut server_auth_configs, tag)?;
        let channel = builder
            .establish_responder_with_auth(
                SplitIo::from_split(recv, send),
                RekeyThresholds::default(),
                auth,
            )
            .await?;
        channels.push((idx, channel));
    }

    let mut tasks = JoinSet::new();
    for (idx, mut channel) in channels {
        tasks.spawn(async move {
            assert!(channel.session().peer_authenticated());
            let incoming = channel.recv_application().await?;
            let reply = format!(
                "websock-mux stream {idx} reply to: {}",
                String::from_utf8_lossy(&incoming)
            );
            channel.send_application(reply.as_bytes()).await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }

    while let Some(result) = tasks.join_next().await {
        result??;
    }
    Ok(())
}

async fn run_client(
    addr: SocketAddr,
    client_auth_configs: Vec<SessionAuthConfig>,
    client_tls: rustls::ClientConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let client = ClientBuilder::new()
        .with_default_alpn()
        .with_tls_config(client_tls)
        .build();
    let url = format!("wss://{}:{}", addr.ip(), addr.port());
    let session = client.connect(&url).await?;

    let config = TransportConfig::default().with_app_stream_id(1);
    let builder = TokioTransportBuilder::new().with_config(config);
    let mut channels = Vec::with_capacity(client_auth_configs.len());

    // Write a small cleartext tag on each raw stream so the server can bind the right Foctet
    // session even if transport accept order differs from open order.
    for (idx, auth) in client_auth_configs.into_iter().enumerate() {
        let (mut send, recv) = session.open_bi().await?;
        send.write_all(&(idx as u32).to_be_bytes()).await?;
        send.flush().await?;
        let channel = builder
            .establish_initiator_with_auth(
                SplitIo::from_split(recv, send),
                RekeyThresholds::default(),
                auth,
            )
            .await?;
        channels.push((idx, channel));
    }

    let mut tasks = JoinSet::new();
    for (idx, mut channel) in channels {
        tasks.spawn(async move {
            assert!(channel.session().peer_authenticated());
            let payload = format!("hello from websock stream {idx}");
            channel.send_application(payload.as_bytes()).await?;
            let response = channel.recv_application().await?;

            println!(
                "client stream {idx} got: {}",
                String::from_utf8_lossy(&response)
            );
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }

    while let Some(result) = tasks.join_next().await {
        result??;
    }

    Ok(())
}

/// Loopback: both peers in one process over an ephemeral port (quick smoke test).
async fn run_loopback(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (cert_chain, key) = resolve_cert_pair(args)?;
    let addr = find_free_tcp_addr()?;
    let client_tls = build_client_tls(&cert_chain)?;
    let server_tls = build_server_tls(cert_chain, key)?;

    let (ready_tx, ready_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let server = match ServerBuilder::new()
            .with_addr(addr)
            .with_default_alpn()
            .with_tls_config(server_tls)
            .build()
            .await
        {
            Ok(server) => {
                let _ = ready_tx.send(Ok::<(), String>(()));
                server
            }
            Err(err) => {
                let _ = ready_tx.send(Err(err.to_string()));
                return Err(Box::new(err) as Box<dyn Error + Send + Sync>);
            }
        };
        let session = server.accept().await?;
        serve_session(session, server_auth_configs()).await?;
        let _ = shutdown_rx.await;
        Ok(())
    });
    ready_rx
        .await
        .map_err(|_| "websock server readiness channel closed")??;

    run_client(addr, client_auth_configs(false), client_tls).await?;
    let _ = shutdown_tx.send(());
    server_task.await??;

    println!("websock multi-stream foctet E2EE example finished");
    Ok(())
}

/// Server role: bind `addr` and serve incoming sessions until Ctrl+C.
async fn run_server_role(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    if args.tls_cert.is_none() || args.tls_key.is_none() {
        return Err(
            "the `server` role requires --tls-cert and --tls-key (e.g. devcert/localhost.crt \
             and devcert/localhost.key); the client must trust the same cert"
                .into(),
        );
    }
    let (cert_chain, key) = resolve_cert_pair(args)?;
    let server_tls = build_server_tls(cert_chain, key)?;
    let server = ServerBuilder::new()
        .with_addr(args.addr)
        .with_default_alpn()
        .with_tls_config(server_tls)
        .build()
        .await?;
    println!(
        "websock server listening on wss://{} (Ctrl+C to stop)",
        args.addr
    );

    loop {
        let session = match server.accept().await {
            Ok(session) => session,
            Err(err) => {
                eprintln!("accept failed: {err}");
                continue;
            }
        };
        println!("accepted a websock session");
        match serve_session(session, server_auth_configs()).await {
            Ok(()) => println!("served session"),
            Err(err) => eprintln!("error serving session: {err}"),
        }
    }
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
    let client_tls = build_client_tls(&cert_chain)?;
    println!("websock client connecting to wss://{}", args.addr);
    run_client(
        args.addr,
        client_auth_configs(args.wrong_identity),
        client_tls,
    )
    .await?;
    println!("websock client finished");
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
