use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ::quinn as quinn_transport;
use clap::Parser;
use foctet_core::{IdentityKeyPair, PeerIdentity, RekeyThresholds, SessionAuthConfig};
use foctet_transport::adapter::SplitIo;
use foctet_transport::{TokioTransportBuilder, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncWriteExt;
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

async fn run_server(
    endpoint: quinn_transport::Endpoint,
    server_auth_configs: Vec<SessionAuthConfig>,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let connection = incoming.await?;
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
                "quinn stream {idx} reply to: {}",
                String::from_utf8_lossy(&incoming)
            );
            channel.send_application(reply.as_bytes()).await?;
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
    let _ = shutdown.await;
    Ok(())
}

async fn run_client(
    endpoint: quinn_transport::Endpoint,
    remote: SocketAddr,
    client_auth_configs: Vec<SessionAuthConfig>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let connection = endpoint.connect(remote, "localhost")?.await?;
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
            let payload = format!("hello from quinn stream {idx}");
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
    let (client_auth_configs, server_auth_configs): (Vec<_>, Vec<_>) =
        (0..STREAM_COUNT).map(auth_config_pair).unzip();
    let (cert_chain, key) = resolve_cert_pair(&args)?;

    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let server_config = configure_server(cert_chain.clone(), key)?;
    let server_endpoint = quinn_transport::Endpoint::server(server_config, bind_addr)?;
    let server_addr = server_endpoint.local_addr()?;

    let client_config = configure_client(&cert_chain)?;
    let mut client_endpoint = quinn_transport::Endpoint::client(bind_addr)?;
    client_endpoint.set_default_client_config(client_config);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(run_server(
        server_endpoint,
        server_auth_configs,
        shutdown_rx,
    ));
    if let Err(err) = run_client(client_endpoint, server_addr, client_auth_configs).await
        && !is_graceful_quinn_close(err.as_ref())
    {
        return Err(err);
    }
    let _ = shutdown_tx.send(());

    match server_task.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) if is_graceful_quinn_close(err.as_ref()) => {}
        Ok(Err(err)) => return Err(err),
        Err(err) => return Err(Box::new(err)),
    }

    println!("quinn multi-stream foctet E2EE example finished");
    Ok(())
}
