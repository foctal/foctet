mod common;

use std::{
    error::Error,
    net::{TcpListener, TcpStream},
    thread,
};

use foctet::core::SecureChannel;

fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let (client_session, server_session) = common::session_pair()?;

    let server_thread = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
        let (stream, peer) = listener.accept()?;
        stream.set_nodelay(true)?;

        let mut channel =
            SecureChannel::from_active_session(stream, server_session)?.with_app_stream_id(1);
        assert!(channel.session().peer_authenticated());

        let incoming = channel.recv_application()?;
        println!(
            "server received from {peer}: {}",
            String::from_utf8_lossy(&incoming)
        );

        channel.send_data(b"pong from secure channel")?;
        Ok(())
    });

    let stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;

    let mut channel =
        SecureChannel::from_active_session(stream, client_session)?.with_app_stream_id(1);
    assert!(channel.session().peer_authenticated());
    channel.send_data(b"ping over secure channel")?;
    let reply = channel.recv_application()?;
    println!("client received: {}", String::from_utf8_lossy(&reply));

    let server_result = server_thread.join().map_err(|_| "server thread panicked")?;
    server_result.map_err(|e| -> Box<dyn Error> { e })?;

    Ok(())
}
