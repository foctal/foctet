use std::{env, error::Error};

use foctet::core::{Direction, FoctetStream, TrafficKeys, derive_traffic_keys};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use x25519_dalek::{PublicKey, StaticSecret};

fn build_shared_keys() -> Result<TrafficKeys, foctet::core::CoreError> {
    let client_private = StaticSecret::from([0x31; 32]);
    let server_private = StaticSecret::from([0x52; 32]);
    let server_public = PublicKey::from(&server_private).to_bytes();
    let shared_secret = client_private
        .diffie_hellman(&PublicKey::from(server_public))
        .to_bytes();
    let session_salt = [0xA5; 32];
    derive_traffic_keys(&shared_secret, &session_salt, 1)
}

async fn run_server(
    listener: TcpListener,
    keys: TrafficKeys,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (stream, peer) = listener.accept().await?;
    stream.set_nodelay(true)?;

    let mut secured = FoctetStream::from_tokio(stream, keys, Direction::C2S, Direction::S2C);

    let inbound_len = secured.read_u32().await? as usize;
    let mut inbound = vec![0u8; inbound_len];
    secured.read_exact(&mut inbound).await?;

    println!(
        "server received from {peer}: {}",
        String::from_utf8_lossy(&inbound)
    );

    let outbound = b"pong from async foctet server";
    secured.write_u32(outbound.len() as u32).await?;
    secured.write_all(outbound).await?;
    secured.flush().await?;

    Ok(())
}

async fn run_client(addr: std::net::SocketAddr, keys: TrafficKeys) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;

    let mut secured = FoctetStream::from_tokio(stream, keys, Direction::S2C, Direction::C2S);

    let outbound = b"ping from async foctet client";
    secured.write_u32(outbound.len() as u32).await?;
    secured.write_all(outbound).await?;
    secured.flush().await?;

    let inbound_len = secured.read_u32().await? as usize;
    let mut inbound = vec![0u8; inbound_len];
    secured.read_exact(&mut inbound).await?;
    println!("client received: {}", String::from_utf8_lossy(&inbound));

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let keys = build_shared_keys()?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server_keys = keys.clone();
    let server_task = tokio::spawn(async move { run_server(listener, server_keys).await });

    run_client(addr, keys).await?;

    match server_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e.to_string().into()),
        Err(e) => return Err(format!("server task join error: {e}").into()),
    }

    if env::var_os("FOCTET_EXAMPLE_SILENT").is_none() {
        println!("foctet async E2EE TCP demo finished successfully");
    }

    Ok(())
}
