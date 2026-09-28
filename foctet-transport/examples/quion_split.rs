//! Authenticated Foctet streams and datagrams over a loopback Quion connection.

use std::{error::Error, time::Duration};

use foctet_core::{IdentityKeyPair, PeerIdentity, ProductionSessionAuth, RekeyThresholds};
use foctet_transport::{SecureChannel, quion as adapter};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(30), run()).await?
}

async fn run() -> Result<(), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone())?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut transport = quion::TransportConfig::default();
    transport.set_max_datagram_frame_size(Some(quion::VarInt::from_u32(65_535)));
    let server = quion::Endpoint::server(
        quion::ServerConfig::builder()
            .with_single_cert(vec![cert.cert.der().clone()], key)?
            .with_transport_config(transport.clone())
            .build()?,
        "127.0.0.1:0".parse()?,
    )?;
    // Quion servers require a live UDP driver in addition to the endpoint.
    let driver = server.spawn_default_server_udp_driver(65_535)?;
    let client = quion::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(
        quion::ClientConfig::builder()
            .with_root_certificates(roots)?
            .with_transport_config(transport)
            .build(),
    );
    let (client_conn, server_conn) =
        tokio::try_join!(client.connect(server.local_addr(), "localhost")?, async {
            server.accept().await.expect("server open").await
        },)?;

    // In production, exchange and pin peer public keys through a trusted path.
    let client_identity = IdentityKeyPair::generate();
    let server_identity = IdentityKeyPair::generate();
    let client_auth = ProductionSessionAuth::pinned_identity(
        client_identity.clone(),
        PeerIdentity::new(server_identity.public_key()),
    );
    let server_auth = ProductionSessionAuth::pinned_identity(
        server_identity,
        PeerIdentity::new(client_identity.public_key()),
    );
    let (mut a, mut b) = tokio::try_join!(
        adapter::open_secure_channel_with_handshake_and_auth_config(
            &client_conn,
            RekeyThresholds::default(),
            client_auth.into_session_auth(),
            Default::default(),
        ),
        adapter::accept_secure_channel_with_handshake_and_auth_config(
            &server_conn,
            RekeyThresholds::default(),
            server_auth.into_session_auth(),
            Default::default(),
        ),
    )?;
    assert!(a.session().peer_authenticated() && b.session().peer_authenticated());
    a.send_payload(b"hello over Quion").await?;
    assert_eq!(b.recv_payload().await?, b"hello over Quion");
    b.send_payload(b"authenticated reply").await?;
    assert_eq!(a.recv_payload().await?, b"authenticated reply");

    let mut a_datagrams =
        adapter::QuionDatagramChannel::from_active_session(client_conn.clone(), a.session())?;
    let mut b_datagrams =
        adapter::QuionDatagramChannel::from_active_session(server_conn.clone(), b.session())?;
    a_datagrams.send_datagram(0, 0, b"Quion datagram").await?;
    assert_eq!(
        b_datagrams.recv_datagram().await?.plaintext,
        b"Quion datagram"
    );

    tokio::try_join!(a.close(), b.close())?;
    client_conn.close(quion::VarInt::from_u32(0), b"example complete");
    driver.stop().await?;
    println!("Quion authenticated stream and datagram round trips completed");
    Ok(())
}
