use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};

use ::muxtls::{ClientConfig, Endpoint, ServerConfig};
use clap::Parser;
use foctet_core::{RekeyThresholds, Session};
use foctet_transport::{TransportConfig, muxtls as foctet_muxtls};
use rustls::pki_types::CertificateDer;
use tokio::task::JoinSet;

const STREAM_COUNT: usize = 2;

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

async fn run_server(
    endpoint: Endpoint,
    server_sessions: Vec<Session>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let conn = endpoint.accept().await?;
    let mut tasks = JoinSet::new();
    let config = TransportConfig::default().with_app_stream_id(1);

    for (idx, session) in server_sessions.into_iter().enumerate() {
        let conn = conn.clone();
        tasks.spawn(async move {
            let mut channel =
                match foctet_muxtls::accept_secure_channel_with(&conn, session, config).await {
                    Ok(channel) => channel,
                    Err(err) if is_graceful_muxtls_close(&err) => return Ok(()),
                    Err(err) => return Err(Box::new(err) as Box<dyn Error + Send + Sync>),
                };

            let incoming = channel.recv_application().await?;
            let reply = format!(
                "muxtls stream {idx} reply to: {}",
                String::from_utf8_lossy(&incoming)
            );
            channel.send_application(reply.as_bytes()).await?;
            channel.close().await?;
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

async fn run_client(
    endpoint: Endpoint,
    addr: SocketAddr,
    client_sessions: Vec<Session>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let conn = endpoint.connect(addr, "localhost")?.await?;
    let mut tasks = JoinSet::new();
    let config = TransportConfig::default().with_app_stream_id(1);

    for (idx, session) in client_sessions.into_iter().enumerate() {
        let conn = conn.clone();
        tasks.spawn(async move {
            let mut channel =
                match foctet_muxtls::open_secure_channel_with(&conn, session, config).await {
                    Ok(channel) => channel,
                    Err(err) if is_graceful_muxtls_close(&err) => return Ok(()),
                    Err(err) => return Err(Box::new(err) as Box<dyn Error + Send + Sync>),
                };

            let payload = format!("hello from muxtls stream {idx}");
            channel.send_application(payload.as_bytes()).await?;
            let response = channel.recv_application().await?;

            println!(
                "client stream {idx} got: {}",
                String::from_utf8_lossy(&response)
            );
            channel.close().await?;
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

    let server_task = tokio::spawn(run_server(server_endpoint, server_sessions));
    run_client(client_endpoint, addr, client_sessions).await?;
    server_task.await??;

    println!("muxtls multi-stream foctet E2EE example finished");
    Ok(())
}
