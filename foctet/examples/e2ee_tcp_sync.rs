mod common;

use std::{
    error::Error,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
};

use foctet::core::{Direction, KeyHandle, io::SyncIo};

fn run_server(listener: TcpListener, keys: KeyHandle) -> Result<(), Box<dyn Error + Send + Sync>> {
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

fn run_client(addr: std::net::SocketAddr, keys: KeyHandle) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;

    let mut secured = SyncIo::new(stream, keys, Direction::S2C, Direction::C2S).with_stream_id(1);
    secured.send(b"ping from foctet client")?;

    let response = secured.recv()?;
    println!("client received: {}", String::from_utf8_lossy(&response));
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let (client, server) = common::session_pair()?;
    let keys = client
        .active_keys()
        .ok_or(foctet::core::CoreError::InvalidSessionState)?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_keys = server
        .active_keys()
        .ok_or(foctet::core::CoreError::InvalidSessionState)?;
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
