use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::PathBuf;

use ::webtrans::{ClientBuilder, ServerBuilder, tls};
use clap::Parser;
use foctet_core::{IdentityKeyPair, PeerIdentity, RekeyThresholds, SessionAuthConfig};
use foctet_transport::adapter::SplitIo;
use foctet_transport::{TokioTransportBuilder, TransportConfig};
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use url::Url;

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

fn find_free_udp_addr() -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    let sock = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
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
        (Some(cert), Some(key)) => Ok(tls::load_cert(cert, key)?),
        (None, None) => Ok(tls::generate_self_signed_pair_der(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ])?),
        _ => Err("both --tls-cert and --tls-key must be provided together".into()),
    }
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
    addr: SocketAddr,
    server_auth_configs: Vec<SessionAuthConfig>,
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    ready: oneshot::Sender<Result<(), String>>,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut server = match ServerBuilder::new()
        .with_addr(addr)
        .with_certificate(cert_chain, key)
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

    let request = server.accept().await.ok_or("server closed")??;
    let session = request.ok().await?;
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

    for (idx, mut channel) in channels {
        assert!(channel.session().peer_authenticated());
        let incoming = channel.recv_application().await?;
        let reply = format!(
            "webtrans stream {idx} reply to: {}",
            String::from_utf8_lossy(&incoming)
        );
        channel.send_application(reply.as_bytes()).await?;
    }

    let _ = shutdown.await;

    Ok(())
}

async fn run_client(
    addr: SocketAddr,
    client_auth_configs: Vec<SessionAuthConfig>,
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let client = ClientBuilder::new().with_server_certificates(cert_chain)?;

    let url = Url::parse(&format!("https://127.0.0.1:{}", addr.port()))?;
    let session = client.connect(url).await?;
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

    for (idx, mut channel) in channels {
        assert!(channel.session().peer_authenticated());
        let payload = format!("hello from webtrans stream {idx}");
        channel.send_application(payload.as_bytes()).await?;
        let response = channel.recv_application().await?;

        println!(
            "client stream {idx} got: {}",
            String::from_utf8_lossy(&response)
        );
    }

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    let (client_auth_configs, server_auth_configs): (Vec<_>, Vec<_>) =
        (0..STREAM_COUNT).map(auth_config_pair).unzip();
    let (cert_chain, key) = resolve_cert_pair(&args)?;
    let addr = find_free_udp_addr()?;

    let (ready_tx, ready_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(run_server(
        addr,
        server_auth_configs,
        cert_chain.clone(),
        key,
        ready_tx,
        shutdown_rx,
    ));
    ready_rx
        .await
        .map_err(|_| "webtrans server readiness channel closed")??;

    run_client(addr, client_auth_configs, cert_chain).await?;
    let _ = shutdown_tx.send(());
    server_task.await??;

    println!("webtrans multi-stream foctet E2EE example finished");
    Ok(())
}
