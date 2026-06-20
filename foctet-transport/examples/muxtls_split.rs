use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};

use ::muxtls::{ClientConfig, Endpoint, ServerConfig};
use clap::Parser;
use foctet_core::{RekeyThresholds, Session, SessionAuthConfig};
use foctet_transport::{TokioTransportBuilder, TransportConfig};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

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
    // The mutually authenticated muxtls/TLS transport authenticates the peer,
    // so the inner Foctet handshake runs in explicit unauthenticated mode.
    let (mut initiator, hello) = Session::new_initiator_with_auth(
        thresholds.clone(),
        SessionAuthConfig::unauthenticated_for_testing(),
    );
    let mut responder = Session::new_responder_with_auth(
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
    );

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

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error + Send + Sync>> {
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

fn resolve_tls(args: &Args) -> Result<(ServerConfig, ClientConfig), Box<dyn Error + Send + Sync>> {
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            let server = ServerConfig::from_pem_files(cert, key)?;
            let client = ClientConfig::with_custom_roots(load_certs(cert)?)?;
            Ok((server, client))
        }
        (None, None) => {
            let (server, cert) = ServerConfig::self_signed_for_localhost()?;
            let client = ClientConfig::with_custom_roots(vec![cert])?;
            Ok((server, client))
        }
        _ => Err("both --tls-cert and --tls-key must be provided together".into()),
    }
}

fn is_graceful_muxtls_close(err: &(dyn Error + 'static)) -> bool {
    let msg = err.to_string();
    msg.contains("stream reset with code 0")
        || msg.contains("connection closed")
        || msg.contains("Broken pipe")
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
    endpoint: Endpoint,
    server_sessions: Vec<Session>,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let conn = endpoint.accept().await?;
    let config = TransportConfig::default().with_app_stream_id(1);
    let builder = TokioTransportBuilder::new().with_config(config);
    let mut server_sessions = server_sessions.into_iter().map(Some).collect::<Vec<_>>();
    let mut channels = Vec::with_capacity(server_sessions.len());

    // Read an explicit stream tag before building Foctet so accept order can vary safely.
    for _ in 0..server_sessions.len() {
        let (send, mut recv) = match conn.accept_bi().await {
            Ok(parts) => parts,
            Err(err) if is_graceful_muxtls_close(&err) => return Ok(()),
            Err(err) => return Err(Box::new(err)),
        };

        let mut tag = [0u8; STREAM_TAG_LEN];
        recv.read_exact(&mut tag).await?;
        let (idx, session) = take_tagged_session(&mut server_sessions, tag)?;
        let channel = builder.build_from_split(recv, send, session)?;
        channels.push((idx, channel));
    }

    let mut tasks = JoinSet::new();
    for (idx, mut channel) in channels {
        tasks.spawn(async move {
            let incoming = channel.recv_application().await?;
            let reply = format!(
                "muxtls stream {idx} reply to: {}",
                String::from_utf8_lossy(&incoming)
            );
            channel.send_application(reply.as_bytes()).await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) if is_graceful_muxtls_close(err.as_ref()) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => return Err(Box::new(err)),
        }
    }

    let _ = shutdown.await;

    Ok(())
}

async fn run_client(
    endpoint: Endpoint,
    addr: SocketAddr,
    client_sessions: Vec<Session>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let conn = endpoint.connect(addr, "localhost")?.await?;
    let config = TransportConfig::default().with_app_stream_id(1);
    let builder = TokioTransportBuilder::new().with_config(config);
    let mut channels = Vec::with_capacity(client_sessions.len());

    // Write a small cleartext tag on each raw stream so the server can bind the right Foctet
    // session even if transport accept order differs from open order.
    for (idx, session) in client_sessions.into_iter().enumerate() {
        let (mut send, recv) = match conn.open_bi().await {
            Ok(parts) => parts,
            Err(err) if is_graceful_muxtls_close(&err) => return Ok(()),
            Err(err) => return Err(Box::new(err)),
        };
        send.write_all(&(idx as u32).to_be_bytes()).await?;
        send.flush().await?;
        let channel = builder.build_from_split(recv, send, session)?;
        channels.push((idx, channel));
    }

    let mut tasks = JoinSet::new();
    for (idx, mut channel) in channels {
        tasks.spawn(async move {
            let payload = format!("hello from muxtls stream {idx}");
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
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) if is_graceful_muxtls_close(err.as_ref()) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => return Err(Box::new(err)),
        }
    }

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    let (client_sessions, server_sessions) = make_session_sets()?;
    let (server_config, client_config) = resolve_tls(&args)?;

    let server_endpoint = Endpoint::server(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        server_config,
    )
    .await?;
    let addr = server_endpoint.local_addr()?;
    let client_endpoint = Endpoint::client(client_config);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(run_server(server_endpoint, server_sessions, shutdown_rx));
    run_client(client_endpoint, addr, client_sessions).await?;
    let _ = shutdown_tx.send(());
    server_task.await??;

    println!("muxtls multi-stream foctet E2EE example finished");
    Ok(())
}
