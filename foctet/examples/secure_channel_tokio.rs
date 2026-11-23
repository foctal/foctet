mod common;

use std::error::Error;

use foctet::core::{AsyncSecureChannel, Session};
use tokio::net::{TcpListener, TcpStream};

async fn run_server(
    listener: TcpListener,
    session: Session,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (stream, peer) = listener.accept().await?;
    stream.set_nodelay(true)?;

    let mut channel = AsyncSecureChannel::from_tokio(stream, session)?.with_app_stream_id(1);
    assert!(channel.session().peer_authenticated());

    let incoming = channel.recv_application().await?;
    println!(
        "server received from {peer}: {}",
        String::from_utf8_lossy(&incoming)
    );

    channel.send_data(b"pong from async secure channel").await?;
    Ok(())
}

async fn run_client(addr: std::net::SocketAddr, session: Session) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;

    let mut channel = AsyncSecureChannel::from_tokio(stream, session)?.with_app_stream_id(1);
    assert!(channel.session().peer_authenticated());
    channel.send_data(b"ping over async secure channel").await?;

    let reply = channel.recv_application().await?;
    println!("client received: {}", String::from_utf8_lossy(&reply));
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let (client_session, server_session) = common::session_pair()?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server_task = tokio::spawn(async move { run_server(listener, server_session).await });

    run_client(addr, client_session).await?;

    match server_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e.to_string().into()),
        Err(e) => return Err(format!("server task join error: {e}").into()),
    }

    println!("foctet async secure-channel demo finished successfully");

    Ok(())
}
