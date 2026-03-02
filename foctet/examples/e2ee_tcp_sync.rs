use std::{
    error::Error,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
};

use foctet::core::{Direction, derive_traffic_keys, io::SyncIo};
use x25519_dalek::{PublicKey, StaticSecret};

fn build_shared_keys() -> Result<foctet::core::TrafficKeys, foctet::core::CoreError> {
    let client_private = StaticSecret::from([0x31; 32]);
    let server_private = StaticSecret::from([0x52; 32]);
    let server_public = PublicKey::from(&server_private).to_bytes();
    let shared_secret = client_private
        .diffie_hellman(&PublicKey::from(server_public))
        .to_bytes();
    let session_salt = [0xA5; 32];
    derive_traffic_keys(&shared_secret, &session_salt, 1)
}

fn run_server(
    listener: TcpListener,
    keys: foctet::core::TrafficKeys,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (stream, peer) = listener.accept()?;
    stream.set_nodelay(true)?;

    let mut secured = SyncIo::new(stream, keys, Direction::C2S, Direction::S2C).with_stream_id(1);
    let request = secured.recv()?;
    println!(
        "server received from {peer}: {}",
        String::from_utf8_lossy(&request)
    );

    secured.send(b"pong from foctet server")?;
    Ok(())
}

fn run_client(
    addr: std::net::SocketAddr,
    keys: foctet::core::TrafficKeys,
) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;

    let mut secured = SyncIo::new(stream, keys, Direction::S2C, Direction::C2S).with_stream_id(1);
    secured.send(b"ping from foctet client")?;

    let response = secured.recv()?;
    println!("client received: {}", String::from_utf8_lossy(&response));
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let keys = build_shared_keys()?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_keys = keys.clone();
    let server_thread = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        ready_tx
            .send(())
            .map_err(|e| format!("server ready signal failed: {e}"))?;
        run_server(listener, server_keys)
    });

    ready_rx
        .recv()
        .map_err(|e| format!("server did not start: {e}"))?;
    run_client(addr, keys)?;

    let server_result = server_thread.join().map_err(|_| "server thread panicked")?;
    server_result.map_err(|e| -> Box<dyn Error> { e })?;

    println!("foctet E2EE TCP demo finished successfully");
    Ok(())
}
