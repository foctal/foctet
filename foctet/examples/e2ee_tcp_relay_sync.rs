use std::{
    error::Error,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::mpsc,
    thread,
};

use foctet::core::{Direction, derive_traffic_keys, io::SyncIo};

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

fn pump(
    src: &mut TcpStream,
    dst: &mut TcpStream,
    tap_prefix: Option<&str>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut first_chunk = true;
    let mut buf = [0u8; 4096];

    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            dst.shutdown(std::net::Shutdown::Write)?;
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

        dst.write_all(&buf[..n])?;
        dst.flush()?;
    }
}

fn run_relay(
    relay_listener: TcpListener,
    server_addr: SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (client_stream, client_peer) = relay_listener.accept()?;
    client_stream.set_nodelay(true)?;

    let server_stream = TcpStream::connect(server_addr)?;
    server_stream.set_nodelay(true)?;

    println!("relay connected: client={client_peer} -> server={server_addr}");

    let mut c_to_s_src = client_stream.try_clone()?;
    let mut c_to_s_dst = server_stream.try_clone()?;
    let t1 = thread::spawn(move || pump(&mut c_to_s_src, &mut c_to_s_dst, Some("client->server")));

    let mut s_to_c_src = server_stream;
    let mut s_to_c_dst = client_stream;
    let t2 = thread::spawn(move || pump(&mut s_to_c_src, &mut s_to_c_dst, Some("server->client")));

    t1.join().map_err(|_| "relay thread panicked")??;
    t2.join().map_err(|_| "relay thread panicked")??;
    Ok(())
}

fn run_server(
    server_listener: TcpListener,
    keys: foctet::core::TrafficKeys,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (stream, peer) = server_listener.accept()?;
    stream.set_nodelay(true)?;

    let mut secured = SyncIo::new(stream, keys, Direction::C2S, Direction::S2C).with_stream_id(1);
    let request = secured.recv()?;
    println!(
        "server received from relay-side peer {peer}: {}",
        String::from_utf8_lossy(&request)
    );

    secured.send(b"pong via relay")?;
    Ok(())
}

fn run_client(
    relay_addr: SocketAddr,
    keys: foctet::core::TrafficKeys,
) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(relay_addr)?;
    stream.set_nodelay(true)?;

    let mut secured = SyncIo::new(stream, keys, Direction::S2C, Direction::C2S).with_stream_id(1);
    secured.send(b"ping through untrusted relay")?;
    let reply = secured.recv()?;

    println!("client received: {}", String::from_utf8_lossy(&reply));
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let keys = derive_demo_keys()?;

    let server_listener = TcpListener::bind("127.0.0.1:0")?;
    let server_addr = server_listener.local_addr()?;

    let relay_listener = TcpListener::bind("127.0.0.1:0")?;
    let relay_addr = relay_listener.local_addr()?;

    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server_keys = keys.clone();
    let server_thread = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        run_server(server_listener, server_keys)
    });

    let relay_thread = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        ready_tx
            .send(())
            .map_err(|e| format!("relay ready signal failed: {e}"))?;
        run_relay(relay_listener, server_addr)
    });

    ready_rx
        .recv()
        .map_err(|e| format!("relay did not start: {e}"))?;

    run_client(relay_addr, keys)?;

    let relay_result = relay_thread.join().map_err(|_| "relay thread panicked")?;
    relay_result.map_err(|e| -> Box<dyn Error> { e })?;

    let server_result = server_thread.join().map_err(|_| "server thread panicked")?;
    server_result.map_err(|e| -> Box<dyn Error> { e })?;

    println!("relay demo finished successfully");
    Ok(())
}
