use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::PathBuf;

use clap::Parser;
use foctet_core::{RekeyThresholds, Session};
use foctet_transport::{TokioTransportBuilder, TransportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use websock_tungstenite_mux::{ClientBuilder, ServerBuilder};

const STREAM_COUNT: usize = 2;
const STREAM_TAG_LEN: usize = 4;

#[derive(Debug, Parser)]
struct Args {
    /// TLS certificate path (PEM/DER). Use together with --tls-key.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// TLS private key path (PEM/DER). Use together with --tls-cert.
    #[arg(long)]
    tls_key: Option<PathBuf>,
}

fn make_session_pair() -> Result<(Session, Session), foctet_core::CoreError> {
    let thresholds = RekeyThresholds::default();
    let (mut initiator, hello) = Session::new_initiator(thresholds.clone());
    let mut responder = Session::new_responder(thresholds);

    let server_hello = responder
        .handle_control(&hello)?
        .expect("responder must return server hello");
    initiator.handle_control(&server_hello)?;

    Ok((initiator, responder))
}

fn make_session_sets() -> Result<(Vec<Session>, Vec<Session>), foctet_core::CoreError> {
    let mut client = Vec::with_capacity(STREAM_COUNT);
    let mut server = Vec::with_capacity(STREAM_COUNT);

    for _ in 0..STREAM_COUNT {
        let (c, s) = make_session_pair()?;
        client.push(c);
        server.push(s);
    }

    Ok((client, server))
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

fn take_tagged_session(
    sessions: &mut [Option<Session>],
    tag: [u8; STREAM_TAG_LEN],
) -> Result<(usize, Session), Box<dyn Error + Send + Sync>> {
    let idx = u32::from_be_bytes(tag) as usize;
    let Some(slot) = sessions.get_mut(idx) else {
        return Err(format!("received out-of-range stream tag {idx}").into());
    };
    let Some(session) = slot.take() else {
        return Err(format!("received duplicate stream tag {idx}").into());
    };
    Ok((idx, session))
}

async fn run_server(
    addr: SocketAddr,
    server_sessions: Vec<Session>,
    server_tls: rustls::ServerConfig,
    ready: oneshot::Sender<Result<(), String>>,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = match ServerBuilder::new()
        .with_addr(addr)
        .with_default_alpn()
        .with_tls_config(server_tls)
        .build()
        .await
    {
        Ok(server) => {
            let _ = ready.send(Ok(()));
            server
        }
        Err(err) => {
            let _ = ready.send(Err(err.to_string()));
            return Err(Box::new(err));
        }
    };
    let session = server.accept().await?;

    let config = TransportConfig::default().with_app_stream_id(1);
    let builder = TokioTransportBuilder::new().with_config(config);
    let mut server_sessions = server_sessions.into_iter().map(Some).collect::<Vec<_>>();
    let mut channels = Vec::with_capacity(server_sessions.len());

    // Read an explicit stream tag before building Foctet so accept order can vary safely.
    for _ in 0..server_sessions.len() {
        let (send, mut recv) = session.accept_bi().await?;
        let mut tag = [0u8; STREAM_TAG_LEN];
        recv.read_exact(&mut tag).await?;
        let (idx, session_keys) = take_tagged_session(&mut server_sessions, tag)?;
        let channel = builder.build_from_split(recv, send, session_keys)?;
        channels.push((idx, channel));
    }

    let mut tasks = JoinSet::new();
    for (idx, mut channel) in channels {
        tasks.spawn(async move {
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

    let _ = shutdown.await;

    Ok(())
}

async fn run_client(
    addr: SocketAddr,
    client_sessions: Vec<Session>,
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
    let mut channels = Vec::with_capacity(client_sessions.len());

    // Write a small cleartext tag on each raw stream so the server can bind the right Foctet
    // session even if transport accept order differs from open order.
    for (idx, session_keys) in client_sessions.into_iter().enumerate() {
        let (mut send, recv) = session.open_bi().await?;
        send.write_all(&(idx as u32).to_be_bytes()).await?;
        send.flush().await?;
        let channel = builder.build_from_split(recv, send, session_keys)?;
        channels.push((idx, channel));
    }

    let mut tasks = JoinSet::new();
    for (idx, mut channel) in channels {
        tasks.spawn(async move {
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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    let (client_sessions, server_sessions) = make_session_sets()?;
    let (cert_chain, key) = resolve_cert_pair(&args)?;
    let addr = find_free_tcp_addr()?;

    let client_tls = build_client_tls(&cert_chain)?;
    let server_tls = build_server_tls(cert_chain, key)?;

    let (ready_tx, ready_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(run_server(
        addr,
        server_sessions,
        server_tls,
        ready_tx,
        shutdown_rx,
    ));
    ready_rx
        .await
        .map_err(|_| "websock server readiness channel closed")??;

    run_client(addr, client_sessions, client_tls).await?;
    let _ = shutdown_tx.send(());
    server_task.await??;

    println!("websock multi-stream foctet E2EE example finished");
    Ok(())
}
