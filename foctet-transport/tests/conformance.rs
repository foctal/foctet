//! Shared conformance suite: the same application-level checks run against all
//! three Foctet transport shapes (message, datagram, byte stream) through the
//! unified [`SecureChannel`] trait, so the shapes stay behaviourally consistent.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use foctet_core::{RekeyThresholds, Session, SessionAuthConfig};
use foctet_transport::{
    DatagramTransport, MessageTransport, SecureChannel, SecureDatagramChannel, SecureMessageChannel,
};

/// Drives the shared checks over any pair of connected secure channels.
async fn run_conformance<A, B>(a: &mut A, b: &mut B)
where
    A: SecureChannel,
    B: SecureChannel,
{
    // Round trip in both directions.
    a.send_payload(b"ping").await.expect("a -> b send");
    assert_eq!(b.recv_payload().await.expect("b recv"), b"ping");
    b.send_payload(b"pong").await.expect("b -> a send");
    assert_eq!(a.recv_payload().await.expect("a recv"), b"pong");

    // Ordering: several payloads arrive in the order sent.
    let payloads: [&[u8]; 3] = [b"one", b"two", b"three"];
    for p in payloads {
        a.send_payload(p).await.expect("a send seq");
    }
    for p in payloads {
        assert_eq!(b.recv_payload().await.expect("b recv seq"), p);
    }

    // A larger payload survives a single round trip (well under the datagram MTU
    // so every shape can carry it).
    let big = vec![0x5Au8; 1000];
    a.send_payload(&big).await.expect("a send big");
    assert_eq!(b.recv_payload().await.expect("b recv big"), big);
}

/// Drives a real native handshake so both sides share traffic keys.
fn session_pair() -> (Session, Session) {
    let (mut initiator, hello) = Session::new_initiator_with_auth(
        RekeyThresholds::default(),
        SessionAuthConfig::unauthenticated_for_testing(),
    );
    let mut responder = Session::new_responder_with_auth(
        RekeyThresholds::default(),
        SessionAuthConfig::unauthenticated_for_testing(),
    );
    let server_hello = responder
        .handle_control(&hello)
        .expect("responder handles hello")
        .expect("server hello");
    initiator
        .handle_control(&server_hello)
        .expect("initiator finalizes");
    (initiator, responder)
}

// ---- In-memory transports for the message and datagram shapes ----

#[derive(Debug)]
struct MemoryError;

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("in-memory transport closed")
    }
}

impl std::error::Error for MemoryError {}

#[derive(Default)]
struct MemoryQueueTransport {
    inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
    outbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

fn linked_pair() -> (MemoryQueueTransport, MemoryQueueTransport) {
    let a_to_b: Rc<RefCell<VecDeque<Vec<u8>>>> = Rc::default();
    let b_to_a: Rc<RefCell<VecDeque<Vec<u8>>>> = Rc::default();
    let a = MemoryQueueTransport {
        inbox: b_to_a.clone(),
        outbox: a_to_b.clone(),
    };
    let b = MemoryQueueTransport {
        inbox: a_to_b,
        outbox: b_to_a,
    };
    (a, b)
}

impl MessageTransport for MemoryQueueTransport {
    type Error = MemoryError;

    async fn send_message(&self, message: Vec<u8>) -> Result<(), Self::Error> {
        self.outbox.borrow_mut().push_back(message);
        Ok(())
    }

    async fn recv_message(&self) -> Result<Vec<u8>, Self::Error> {
        self.inbox.borrow_mut().pop_front().ok_or(MemoryError)
    }

    fn max_message_size(&self) -> Option<usize> {
        None
    }
}

impl DatagramTransport for MemoryQueueTransport {
    type Error = MemoryError;

    async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Self::Error> {
        self.outbox.borrow_mut().push_back(datagram);
        Ok(())
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>, Self::Error> {
        self.inbox.borrow_mut().pop_front().ok_or(MemoryError)
    }

    fn max_datagram_size(&self) -> Option<usize> {
        None
    }
}

#[tokio::test]
async fn message_shape_conformance() {
    let (init, resp) = session_pair();
    let (ta, tb) = linked_pair();
    let mut a = SecureMessageChannel::from_active_session(ta, &init).expect("a");
    let mut b = SecureMessageChannel::from_active_session(tb, &resp).expect("b");
    run_conformance(&mut a, &mut b).await;
}

#[tokio::test]
async fn datagram_shape_conformance() {
    let (init, resp) = session_pair();
    let (ta, tb) = linked_pair();
    let mut a = SecureDatagramChannel::from_active_session(ta, &init).expect("a");
    let mut b = SecureDatagramChannel::from_active_session(tb, &resp).expect("b");
    run_conformance(&mut a, &mut b).await;
}

#[cfg(feature = "runtime-tokio")]
#[tokio::test]
async fn byte_stream_shape_conformance() {
    use foctet_transport::TokioTransportBuilder;

    let (init, resp) = session_pair();
    let (a_io, b_io) = tokio::io::duplex(64 * 1024);
    let mut a = TokioTransportBuilder::new()
        .build(a_io, init)
        .expect("a channel");
    let mut b = TokioTransportBuilder::new()
        .build(b_io, resp)
        .expect("b channel");
    run_conformance(&mut a, &mut b).await;
}

// ---- Real-backend byte-stream conformance ----
//
// The same suite runs over a real loopback connection for every advertised
// byte-stream backend: each test brings up the outer transport with a
// self-signed localhost certificate, runs the native Foctet handshake over one
// bidirectional stream, and then drives `run_conformance` end to end.

#[cfg(all(feature = "runtime-tokio", feature = "transport-quinn"))]
mod quinn_byte_stream {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use foctet_core::RekeyThresholds;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::run_conformance;

    #[tokio::test]
    async fn quinn_byte_stream_conformance() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("self-signed cert");
        let cert_der = CertificateDer::from(cert.cert);
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let server_config = quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server config");
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let server_ep = quinn::Endpoint::server(server_config, bind).expect("server endpoint");
        let server_addr = server_ep.local_addr().expect("server addr");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("add root");
        let client_config =
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config");
        let mut client_ep = quinn::Endpoint::client(bind).expect("client endpoint");
        client_ep.set_default_client_config(client_config);

        let server_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("incoming");
            let conn = incoming.await.expect("server connection");
            (server_ep, conn)
        });
        let client_conn = client_ep
            .connect(server_addr, "localhost")
            .expect("connect")
            .await
            .expect("client connection");
        let (_server_ep, server_conn) = server_task.await.expect("server join");

        let (client, server) = tokio::join!(
            foctet_transport::quinn::open_secure_channel_with_handshake(
                &client_conn,
                RekeyThresholds::default(),
            ),
            foctet_transport::quinn::accept_secure_channel_with_handshake(
                &server_conn,
                RekeyThresholds::default(),
            ),
        );
        let mut a = client.expect("client channel");
        let mut b = server.expect("server channel");
        run_conformance(&mut a, &mut b).await;
    }
}

#[cfg(all(feature = "runtime-tokio", feature = "transport-muxtls"))]
mod muxtls_byte_stream {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use foctet_core::RekeyThresholds;

    use super::run_conformance;

    #[tokio::test]
    async fn muxtls_byte_stream_conformance() {
        let (server_config, cert) =
            muxtls::ServerConfig::self_signed_for_localhost().expect("self-signed cert");
        let client_config =
            muxtls::ClientConfig::with_custom_roots(vec![cert]).expect("client config");

        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let server_ep = muxtls::Endpoint::server(bind, server_config)
            .await
            .expect("server endpoint");
        let server_addr = server_ep.local_addr().expect("server addr");
        let client_ep = muxtls::Endpoint::client(client_config);

        let server_task = tokio::spawn(async move {
            let conn = server_ep.accept().await.expect("server connection");
            (server_ep, conn)
        });
        let client_conn = client_ep
            .connect(server_addr, "localhost")
            .expect("connect")
            .await
            .expect("client connection");
        let (_server_ep, server_conn) = server_task.await.expect("server join");

        let (client, server) = tokio::join!(
            foctet_transport::muxtls::open_secure_channel_with_handshake(
                &client_conn,
                RekeyThresholds::default(),
            ),
            foctet_transport::muxtls::accept_secure_channel_with_handshake(
                &server_conn,
                RekeyThresholds::default(),
            ),
        );
        let mut a = client.expect("client channel");
        let mut b = server.expect("server channel");
        run_conformance(&mut a, &mut b).await;
    }
}

#[cfg(all(feature = "runtime-tokio", feature = "transport-webtrans"))]
mod webtrans_byte_stream {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use foctet_core::RekeyThresholds;

    use super::run_conformance;

    #[tokio::test]
    async fn webtransport_byte_stream_conformance() {
        let (cert_chain, key) = webtrans::tls::generate_self_signed_pair_der(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .expect("self-signed cert");

        // Reserve a free UDP port for the server (bind-and-release; the tiny
        // race is acceptable for a loopback test).
        let addr = {
            let sock = std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                0,
            )))
            .expect("probe socket");
            sock.local_addr().expect("probe addr")
        };

        let mut server = webtrans::ServerBuilder::new()
            .with_addr(addr)
            .with_certificate(cert_chain.clone(), key)
            .expect("server");
        let server_task = tokio::spawn(async move {
            let request = server.accept().await.expect("server closed");
            let session = request.ok().await.expect("server session");
            (server, session)
        });

        let client = webtrans::ClientBuilder::new()
            .with_server_certificates(cert_chain)
            .expect("client");
        let url =
            url::Url::parse(&format!("https://127.0.0.1:{}", addr.port())).expect("server url");
        let client_session = client.connect(url).await.expect("client session");
        let (_server, server_session) = server_task.await.expect("server join");

        let (client, server) = tokio::join!(
            foctet_transport::webtrans::open_secure_channel_with_handshake(
                &client_session,
                RekeyThresholds::default(),
            ),
            foctet_transport::webtrans::accept_secure_channel_with_handshake(
                &server_session,
                RekeyThresholds::default(),
            ),
        );
        let mut a = client.expect("client channel");
        let mut b = server.expect("server channel");
        run_conformance(&mut a, &mut b).await;
    }
}

#[cfg(feature = "transport-websock-mux")]
mod websock_mux_byte_stream {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use foctet_core::RekeyThresholds;

    use super::run_conformance;

    #[tokio::test]
    async fn websocket_mux_byte_stream_conformance() {
        let (cert_chain, key) = websock_tungstenite_mux::tls::generate_self_signed_pair_der(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .expect("self-signed cert");

        let mut roots = rustls::RootCertStore::empty();
        for cert in &cert_chain {
            roots.add(cert.clone()).expect("add root");
        }
        let client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("server tls");

        // Reserve a free TCP port (bind-and-release, same as the UDP probe).
        let addr = {
            let sock = std::net::TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                0,
            )))
            .expect("probe socket");
            sock.local_addr().expect("probe addr")
        };

        let server = websock_tungstenite_mux::ServerBuilder::new()
            .with_addr(addr)
            .with_default_alpn()
            .with_tls_config(server_tls)
            .build()
            .await
            .expect("server");
        let server_task = tokio::spawn(async move {
            let session = server.accept().await.expect("server session");
            (server, session)
        });

        let client = websock_tungstenite_mux::ClientBuilder::new()
            .with_default_alpn()
            .with_tls_config(client_tls)
            .build();
        let url = format!("wss://127.0.0.1:{}", addr.port());
        let client_session = client.connect(&url).await.expect("client session");
        let (_server, server_session) = server_task.await.expect("server join");

        let (client, server) = tokio::join!(
            foctet_transport::websock::open_secure_channel_with_handshake(
                &client_session,
                RekeyThresholds::default(),
            ),
            foctet_transport::websock::accept_secure_channel_with_handshake(
                &server_session,
                RekeyThresholds::default(),
            ),
        );
        let mut a = client.expect("client channel");
        let mut b = server.expect("server channel");
        run_conformance(&mut a, &mut b).await;
    }
}
