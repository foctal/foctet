// Two-process raw-UDP datagram example (TODO §3.5, tests.md §3.6).
//
// Raw UDP has no handshake of its own, so this example follows the recommended
// pattern: run the authenticated Foctet handshake over a *reliable* control
// channel (here a plain TCP stream), then build a `SecureDatagramChannel` from
// the resulting session over a *connected* `UdpDatagramTransport` on each side
// and exchange sealed datagrams.
//
// It also demonstrates anti-amplification: the server enables
// `with_anti_amplification(3)`, so before the client has proven it can receive
// at its claimed address the server refuses to send (a spoofed source cannot
// turn the server into a reflector). Once the first client datagram arrives the
// server calls `mark_peer_validated()` and the cap is lifted.
//
// The two peers derive their pinned identities from fixed seeds, so the
// processes authenticate each other without any out-of-band key exchange.

use std::error::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;

use clap::{Parser, ValueEnum};
use foctet_core::{IdentityKeyPair, PeerIdentity, RekeyThresholds, SessionAuthConfig};
use foctet_transport::udp::UdpDatagramTransport;
use foctet_transport::{DatagramChannelError, SecureDatagramChannel, TokioTransportBuilder};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// How to run the example.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Role {
    /// Run both peers in one process over the loopback (quick smoke test).
    #[default]
    Loopback,
    /// Run only the server: bind the control/UDP addresses and serve one client.
    Server,
    /// Run only the client: connect to a server's control address.
    Client,
}

#[derive(Debug, Parser)]
struct Args {
    /// Which side to run. `loopback` (default) runs both in one process; use
    /// `server` and `client` in separate terminals / on two hosts.
    #[arg(long, value_enum, default_value_t = Role::Loopback)]
    role: Role,
    /// Reliable control channel (TCP). Server binds it; client connects to it.
    /// Ignored for `loopback`. Default `127.0.0.1:4455`.
    #[arg(long, default_value = "127.0.0.1:4455")]
    control_addr: SocketAddr,
    /// UDP socket to bind on this side. The server advertises its bound address
    /// over the control channel, so the client leaves this ephemeral. Server
    /// default `127.0.0.1:4456`; client default `127.0.0.1:0`.
    #[arg(long)]
    udp_addr: Option<SocketAddr>,
    /// Number of datagrams the client sends (each echoed back). Default `4`.
    #[arg(long, default_value_t = 4)]
    datagrams: usize,
    /// Anti-amplification factor the server enforces until the client is
    /// address-validated (QUIC's default is 3). Default `3`.
    #[arg(long, default_value_t = 3)]
    anti_amplification: u64,
}

fn auth_config_pair() -> (SessionAuthConfig, SessionAuthConfig) {
    let client_identity = IdentityKeyPair::from_secret_key_bytes([0x41; 32]);
    let server_identity = IdentityKeyPair::from_secret_key_bytes([0x61; 32]);
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

/// Server side: authenticate over `control`, agree on UDP addresses, then run
/// the anti-amplification-gated datagram echo over `udp`. The client dictates
/// how many datagrams it will send (over the control channel), so the two
/// processes agree without a shared count argument.
async fn serve(
    control: TcpStream,
    udp: UdpSocket,
    factor: u64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (_client_auth, server_auth) = auth_config_pair();
    let mut channel = TokioTransportBuilder::new()
        .establish_responder_with_auth(control, RekeyThresholds::default(), server_auth)
        .await?;
    assert!(channel.session().peer_authenticated());

    // Advertise our bound UDP address, then learn the client's address and how
    // many datagrams it will send. Ordering (server sends first, client
    // receives first) avoids a control-channel deadlock.
    let local_udp = udp.local_addr()?;
    channel
        .send_application(local_udp.to_string().as_bytes())
        .await?;
    let peer_udp: SocketAddr = String::from_utf8(channel.recv_application().await?)?.parse()?;
    let datagrams: usize = String::from_utf8(channel.recv_application().await?)?.parse()?;
    udp.connect(peer_udp).await?;

    let transport = UdpDatagramTransport::new(udp)?.with_anti_amplification(factor);
    let mut datagram = SecureDatagramChannel::from_active_session(transport, channel.session())?;

    // Anti-amplification: with zero bytes received the budget is zero, so an
    // unsolicited send is refused. Proves a spoofed peer cannot be amplified.
    match datagram.send_datagram(0, 0, b"unsolicited probe").await {
        Err(DatagramChannelError::Transport(err)) if err.kind() == ErrorKind::WouldBlock => {
            println!("anti-amplification: refused to send before validation (WouldBlock) — ok");
        }
        Ok(()) => return Err("anti-amplification failed: unsolicited send was allowed".into()),
        Err(err) => return Err(Box::new(err)),
    }

    for idx in 0..datagrams {
        let incoming = datagram.recv_datagram().await?;
        if idx == 0 {
            // The client reached us at its claimed address; lift the cap.
            datagram.transport().mark_peer_validated();
            println!("received first client datagram — marked peer validated, cap lifted");
        }
        let reply = format!(
            "udp echo {idx} reply to: {}",
            String::from_utf8_lossy(&incoming.plaintext)
        );
        datagram.send_datagram(0, 0, reply.as_bytes()).await?;
    }
    println!("server echoed {datagrams} datagram(s)");
    Ok(())
}

/// Client side: authenticate over `control`, agree on UDP addresses, then send
/// `datagrams` sealed datagrams and read each echo.
async fn run_client(
    control: TcpStream,
    udp: UdpSocket,
    datagrams: usize,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (client_auth, _server_auth) = auth_config_pair();
    let mut channel = TokioTransportBuilder::new()
        .establish_initiator_with_auth(control, RekeyThresholds::default(), client_auth)
        .await?;
    assert!(channel.session().peer_authenticated());

    // Learn the server's UDP address, connect, then advertise ours and the
    // number of datagrams we will send so the server echoes exactly that many.
    let peer_udp: SocketAddr = String::from_utf8(channel.recv_application().await?)?.parse()?;
    udp.connect(peer_udp).await?;
    let local_udp = udp.local_addr()?;
    channel
        .send_application(local_udp.to_string().as_bytes())
        .await?;
    channel
        .send_application(datagrams.to_string().as_bytes())
        .await?;

    let transport = UdpDatagramTransport::new(udp)?;
    let mut datagram = SecureDatagramChannel::from_active_session(transport, channel.session())?;

    for idx in 0..datagrams {
        let payload = format!("hello udp datagram {idx}");
        datagram.send_datagram(0, 0, payload.as_bytes()).await?;
        let echo = datagram.recv_datagram().await?;
        println!(
            "client datagram {idx} got: {}",
            String::from_utf8_lossy(&echo.plaintext)
        );
    }
    Ok(())
}

async fn run_loopback(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Bind everything on ephemeral ports so repeated runs never collide.
    let control_listener = TcpListener::bind("127.0.0.1:0").await?;
    let control_addr = control_listener.local_addr()?;
    let server_udp = UdpSocket::bind("127.0.0.1:0").await?;
    let factor = args.anti_amplification;
    let datagrams = args.datagrams;

    let server_task = tokio::spawn(async move {
        let (control, _peer) = control_listener.accept().await?;
        serve(control, server_udp, factor).await
    });

    let control = TcpStream::connect(control_addr).await?;
    let client_udp = UdpSocket::bind("127.0.0.1:0").await?;
    run_client(control, client_udp, datagrams).await?;
    server_task.await??;
    Ok(())
}

async fn run_server_role(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    let udp_addr = args.udp_addr.unwrap_or("127.0.0.1:4456".parse()?);
    let control_listener = TcpListener::bind(args.control_addr).await?;
    println!(
        "udp datagram server: control on tcp://{}, datagrams on udp://{} (Ctrl+C to stop)",
        args.control_addr, udp_addr
    );
    loop {
        let (control, peer) = control_listener.accept().await?;
        println!("accepted control connection from {peer}");
        // Fresh UDP socket per connection so the previous one's port is free.
        let udp = UdpSocket::bind(udp_addr).await?;
        match serve(control, udp, args.anti_amplification).await {
            Ok(()) => println!("served {peer}"),
            Err(err) => eprintln!("error serving {peer}: {err}"),
        }
    }
}

async fn run_client_role(args: &Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    let udp_addr = args.udp_addr.unwrap_or("127.0.0.1:0".parse()?);
    println!(
        "udp datagram client connecting to tcp://{}",
        args.control_addr
    );
    let control = TcpStream::connect(args.control_addr).await?;
    let udp = UdpSocket::bind(udp_addr).await?;
    run_client(control, udp, args.datagrams).await?;
    println!("udp datagram client finished");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    match args.role {
        Role::Loopback => {
            run_loopback(&args).await?;
            println!("udp datagram loopback example finished");
        }
        Role::Server => run_server_role(&args).await?,
        Role::Client => run_client_role(&args).await?,
    }
    Ok(())
}
