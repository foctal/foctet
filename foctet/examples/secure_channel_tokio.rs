use std::error::Error;

use foctet::core::{
    AsyncSecureChannel, IdentityKeyPair, PeerIdentity, RekeyThresholds, Session, SessionAuthConfig,
};
use tokio::net::{TcpListener, TcpStream};

fn make_session_pair() -> (Session, Session) {
    let thresholds = RekeyThresholds::default();
    let client_identity = IdentityKeyPair::from_secret_key_bytes([0x41; 32]);
    let server_identity = IdentityKeyPair::from_secret_key_bytes([0x61; 32]);
    let client_auth = SessionAuthConfig::new()
        .with_local_identity(client_identity.clone())
        .with_peer_identity(PeerIdentity::new(server_identity.public_key()))
        .require_peer_authentication(true);
    let server_auth = SessionAuthConfig::new()
        .with_local_identity(server_identity)
        .with_peer_identity(PeerIdentity::new(client_identity.public_key()))
        .require_peer_authentication(true);

    let (mut initiator, hello) = Session::new_initiator_with_auth(thresholds.clone(), client_auth);
    let mut responder = Session::new_responder_with_auth(thresholds, server_auth);

    let server_hello = responder
        .handle_control(&hello)
        .expect("responder handle client hello")
        .expect("server hello");
    initiator
        .handle_control(&server_hello)
        .expect("initiator handle server hello");

    (initiator, responder)
}

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
    let (client_session, server_session) = make_session_pair();

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
