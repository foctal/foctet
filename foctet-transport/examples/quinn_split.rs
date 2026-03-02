use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use foctet_core::{AsyncSecureChannel, RekeyThresholds, Session};
use foctet_transport::quinn as quinn_adapter;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
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
    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, key)?;
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
    Ok(quinn::ClientConfig::with_root_certificates(Arc::new(
        roots,
    ))?)
}

fn is_graceful_quinn_close(err: &(dyn Error + 'static)) -> bool {
    let msg = err.to_string();
    msg.contains("ApplicationClosed") || msg.contains("ConnectionLost(ApplicationClosed")
}

async fn run_server(
    endpoint: quinn::Endpoint,
    server_sessions: Vec<Session>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let connection = incoming.await?;

    let mut tasks = JoinSet::new();
    for (idx, session_keys) in server_sessions.into_iter().enumerate() {
        let (send, recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(err) if is_graceful_quinn_close(&err) => break,
            Err(err) => return Err(Box::new(err)),
        };
        tasks.spawn(async move {
            let io = quinn_adapter::from_split(recv, send);
            let mut channel =
                AsyncSecureChannel::from_tokio(io, session_keys)?.with_app_stream_id(1);

            let incoming = channel.recv_application().await?;
            let reply = format!(
                "quinn stream {idx} reply to: {}",
                String::from_utf8_lossy(&incoming)
            );
            channel.send_data(reply.as_bytes()).await?;
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

async fn run_client(
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
    client_sessions: Vec<Session>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let connection = endpoint.connect(remote, "localhost")?.await?;

    let mut tasks = JoinSet::new();
    for (idx, session_keys) in client_sessions.into_iter().enumerate() {
        let (send, recv) = match connection.open_bi().await {
            Ok(pair) => pair,
            Err(err) if is_graceful_quinn_close(&err) => break,
            Err(err) => return Err(Box::new(err)),
        };
        tasks.spawn(async move {
            let io = quinn_adapter::from_split(recv, send);
            let mut channel =
                AsyncSecureChannel::from_tokio(io, session_keys)?.with_app_stream_id(1);

            let payload = format!("hello from quinn stream {idx}");
            channel.send_data(payload.as_bytes()).await?;
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
            Ok(Err(err)) if is_graceful_quinn_close(err.as_ref()) => {}
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
    let (cert_chain, key) = resolve_cert_pair(&args)?;

    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let server_config = configure_server(cert_chain.clone(), key)?;
    let server_endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    let server_addr = server_endpoint.local_addr()?;

    let client_config = configure_client(&cert_chain)?;
    let mut client_endpoint = quinn::Endpoint::client(bind_addr)?;
    client_endpoint.set_default_client_config(client_config);

    let server_task = tokio::spawn(run_server(server_endpoint, server_sessions));
    if let Err(err) = run_client(client_endpoint, server_addr, client_sessions).await
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
