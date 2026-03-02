use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::PathBuf;

use clap::Parser;
use foctet_core::{AsyncSecureChannel, RekeyThresholds, Session};
use foctet_transport::webtrans as webtrans_adapter;
use tokio::io::AsyncWriteExt;
use url::Url;
use webtrans::{ClientBuilder, ServerBuilder};

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
        (Some(cert), Some(key)) => Ok(webtrans::tls::load_cert(cert, key)?),
        (None, None) => Ok(webtrans::tls::generate_self_signed_pair_der(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ])?),
        _ => Err("both --tls-cert and --tls-key must be provided together".into()),
    }
}

async fn shutdown_channel<T>(
    channel: AsyncSecureChannel<foctet_core::io::TokioIo<T>>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (framed, _session) = channel.into_parts();
    let io = framed.into_inner();
    let mut io = io.into_inner();
    io.shutdown().await?;
    Ok(())
}

async fn run_server(
    addr: SocketAddr,
    server_sessions: Vec<Session>,
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut server = ServerBuilder::new()
        .with_addr(addr)
        .with_certificate(cert_chain, key)?;

    let request = server.accept().await.ok_or("server closed")?;
    let session = request.ok().await?;

    for (idx, session_keys) in server_sessions.into_iter().enumerate() {
        let (send, recv) = session.accept_bi().await?;
        let io = webtrans_adapter::from_split(recv, send);
        let mut channel = AsyncSecureChannel::from_tokio(io, session_keys)?.with_app_stream_id(1);

        let incoming = channel.recv_application().await?;
        let reply = format!(
            "webtrans stream {idx} reply to: {}",
            String::from_utf8_lossy(&incoming)
        );
        channel.send_data(reply.as_bytes()).await?;
        shutdown_channel(channel).await?;
    }

    Ok(())
}

async fn run_client(
    addr: SocketAddr,
    client_sessions: Vec<Session>,
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let client = ClientBuilder::new().with_server_certificates(cert_chain)?;

    let url = Url::parse(&format!("https://127.0.0.1:{}", addr.port()))?;
    let session = client.connect(url).await?;

    for (idx, session_keys) in client_sessions.into_iter().enumerate() {
        let (send, recv) = session.open_bi().await?;
        let io = webtrans_adapter::from_split(recv, send);
        let mut channel = AsyncSecureChannel::from_tokio(io, session_keys)?.with_app_stream_id(1);

        let payload = format!("hello from webtrans stream {idx}");
        channel.send_data(payload.as_bytes()).await?;
        let response = channel.recv_application().await?;

        println!(
            "client stream {idx} got: {}",
            String::from_utf8_lossy(&response)
        );
        shutdown_channel(channel).await?;
    }

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    let (client_sessions, server_sessions) = make_session_sets()?;
    let (cert_chain, key) = resolve_cert_pair(&args)?;
    let addr = find_free_udp_addr()?;

    let server_task = tokio::spawn(run_server(addr, server_sessions, cert_chain.clone(), key));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    run_client(addr, client_sessions, cert_chain).await?;
    server_task.await??;

    println!("webtrans multi-stream foctet E2EE example finished");
    Ok(())
}
