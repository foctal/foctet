use std::{env, error::Error};

use foctet::core::{Direction, FoctetStream, derive_traffic_keys};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

fn derive_demo_keys() -> Result<foctet::core::TrafficKeys, foctet::core::CoreError> {
    let shared_secret = [0x11u8; 32];
    let session_salt = [0x22u8; 32];
    derive_traffic_keys(&shared_secret, &session_salt, 1)
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    bytes
        .iter()
        .take(n)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

async fn pump(
    src: &mut OwnedReadHalf,
    dst: &mut OwnedWriteHalf,
    tap_prefix: Option<&str>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut first_chunk = true;
    let mut buf = [0u8; 4096];

    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            dst.shutdown().await?;
            return Ok(());
        }

        if first_chunk {
            if let Some(prefix) = tap_prefix {
                println!(
                    "relay observed {prefix} first bytes (ciphertext/header): {}",
                    hex_prefix(&buf[..n], 24)
                );
            }
            first_chunk = false;
        }

        dst.write_all(&buf[..n]).await?;
        dst.flush().await?;
    }
}

async fn run_relay(
    relay_listener: TcpListener,
    server_addr: std::net::SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (client_stream, client_peer) = relay_listener.accept().await?;
    client_stream.set_nodelay(true)?;

    let server_stream = TcpStream::connect(server_addr).await?;
    server_stream.set_nodelay(true)?;

    println!("relay connected: client={client_peer} -> server={server_addr}");

    let (mut c_read, mut c_write) = client_stream.into_split();
    let (mut s_read, mut s_write) = server_stream.into_split();

    let c_to_s =
        tokio::spawn(async move { pump(&mut c_read, &mut s_write, Some("client->server")).await });
    let s_to_c =
        tokio::spawn(async move { pump(&mut s_read, &mut c_write, Some("server->client")).await });

    c_to_s
        .await
        .map_err(|e| format!("relay c->s task join error: {e}"))??;
    s_to_c
        .await
        .map_err(|e| format!("relay s->c task join error: {e}"))??;

    Ok(())
}

async fn run_server(
    server_listener: TcpListener,
    keys: foctet::core::TrafficKeys,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (stream, peer) = server_listener.accept().await?;
    stream.set_nodelay(true)?;

    let mut secured = FoctetStream::from_tokio(stream, keys, Direction::C2S, Direction::S2C)
        .with_max_write_frame(64 * 1024);

    let inbound_len = secured.read_u32().await? as usize;
    let mut inbound = vec![0u8; inbound_len];
    secured.read_exact(&mut inbound).await?;
    println!(
        "server received from relay-side peer {peer}: {}",
        String::from_utf8_lossy(&inbound)
    );

    let outbound = b"pong via async relay";
    secured.write_u32(outbound.len() as u32).await?;
    secured.write_all(outbound).await?;
    secured.flush().await?;

    Ok(())
}

async fn run_client(
    relay_addr: std::net::SocketAddr,
    keys: foctet::core::TrafficKeys,
) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(relay_addr).await?;
    stream.set_nodelay(true)?;

    let mut secured = FoctetStream::from_tokio(stream, keys, Direction::S2C, Direction::C2S)
        .with_max_write_frame(64 * 1024);

    let outbound = b"ping through untrusted async relay";
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
    let keys = derive_demo_keys()?;

    let server_listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = server_listener.local_addr()?;

    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = relay_listener.local_addr()?;
    let server_keys = keys.clone();
    let server_task = tokio::spawn(async move { run_server(server_listener, server_keys).await });
    let relay_task = tokio::spawn(async move { run_relay(relay_listener, server_addr).await });
    run_client(relay_addr, keys).await?;

    match relay_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e.to_string().into()),
        Err(e) => return Err(format!("relay task join error: {e}").into()),
    }

    match server_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e.to_string().into()),
        Err(e) => return Err(format!("server task join error: {e}").into()),
    }

    if env::var_os("FOCTET_EXAMPLE_SILENT").is_none() {
        println!("foctet async relay E2EE demo finished successfully");
    }

    Ok(())
}
