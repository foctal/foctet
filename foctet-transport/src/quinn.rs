//! High-level Foctet integration helpers for `quinn`.

use bytes::Bytes;
use foctet_core::{
    CoreError, DatagramConfig, DatagramEndpoint, DecodedDatagram, RekeyThresholds, Session,
    SessionAuthConfig,
};
use thiserror::Error;

use crate::{
    TokioTransportBuilder, TokioTransportChannel, TransportChannelError, TransportConfig,
    adapter::SplitIo,
};

/// Error returned by the [`crate::DatagramTransport`] implementation for
/// [`quinn::Connection`].
#[derive(Debug, Error)]
pub enum QuinnDatagramTransportError {
    /// Quinn refused to send the datagram (too large, disabled, or closed).
    #[error("quinn send datagram error: {0}")]
    Send(#[from] quinn::SendDatagramError),
    /// The Quinn connection failed while receiving a datagram.
    #[error("quinn connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
}

/// Generic datagram-transport view of a [`quinn::Connection`], usable with
/// [`crate::SecureDatagramChannel`].
impl crate::DatagramTransport for quinn::Connection {
    type Error = QuinnDatagramTransportError;

    async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Self::Error> {
        quinn::Connection::send_datagram(self, Bytes::from(datagram))?;
        Ok(())
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>, Self::Error> {
        let bytes = quinn::Connection::read_datagram(self).await?;
        Ok(bytes.to_vec())
    }

    fn max_datagram_size(&self) -> Option<usize> {
        quinn::Connection::max_datagram_size(self)
    }
}

/// Error returned by [`QuinnDatagramChannel`] operations.
#[derive(Debug, Error)]
pub enum QuinnDatagramError {
    /// Foctet datagram seal/open failed.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// Quinn refused to send the datagram (too large, disabled, or closed).
    #[error("quinn send datagram error: {0}")]
    Send(#[from] quinn::SendDatagramError),
    /// The Quinn connection failed while receiving a datagram.
    #[error("quinn connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
}

/// A Foctet datagram channel over a QUIC connection.
///
/// Each call seals one Foctet frame into exactly one QUIC datagram (and opens
/// one per received datagram). QUIC datagrams are unreliable and unordered;
/// Foctet's replay window tolerates loss and reordering and rejects duplicates.
///
/// Negotiate keys with a normal Foctet handshake over a QUIC stream first (for
/// example via [`open_secure_channel_with_handshake_and_auth_config`]), then
/// build this channel from the resulting [`Session`].
///
/// # MTU and anti-amplification
///
/// Set [`DatagramConfig::max_datagram_size`] at or below the connection's
/// [`quinn::Connection::max_datagram_size`]. As with any datagram protocol, do
/// not send a large volume of datagrams to a peer whose address has not been
/// validated.
#[derive(Debug)]
pub struct QuinnDatagramChannel {
    connection: quinn::Connection,
    endpoint: DatagramEndpoint,
}

impl QuinnDatagramChannel {
    /// Builds a datagram channel from a connection and an active [`Session`],
    /// clamping the datagram size to the connection's current maximum.
    pub fn from_active_session(
        connection: quinn::Connection,
        session: &Session,
    ) -> Result<Self, CoreError> {
        let mut config = DatagramConfig::default();
        if let Some(max) = connection.max_datagram_size() {
            config.max_datagram_size = config.max_datagram_size.min(max);
        }
        Self::from_active_session_with_config(connection, session, config)
    }

    /// Builds a datagram channel from a connection, an active [`Session`], and
    /// an explicit datagram configuration.
    pub fn from_active_session_with_config(
        connection: quinn::Connection,
        session: &Session,
        config: DatagramConfig,
    ) -> Result<Self, CoreError> {
        let keys = session.active_keys().ok_or(CoreError::InvalidSessionState)?;
        let endpoint = DatagramEndpoint::with_config(
            keys,
            session.inbound_direction(),
            session.outbound_direction(),
            config,
        );
        Ok(Self {
            connection,
            endpoint,
        })
    }

    /// Returns the maximum plaintext bytes that fit in one datagram.
    pub fn max_plaintext_len(&self) -> usize {
        self.endpoint.max_plaintext_len()
    }

    /// Installs a freshly rotated set of traffic keys (after a rekey).
    pub fn install_active_keys(&mut self, keys: foctet_core::TrafficKeys) {
        self.endpoint.install_active_keys(keys);
    }

    /// Returns a reference to the underlying QUIC connection.
    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    /// Seals `plaintext` into one Foctet frame and sends it as a QUIC datagram.
    pub fn send_datagram(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<(), QuinnDatagramError> {
        let bytes = self.endpoint.seal(stream_id, flags, plaintext)?;
        self.connection.send_datagram(Bytes::from(bytes))?;
        Ok(())
    }

    /// Receives one QUIC datagram and opens it into a decrypted payload.
    pub async fn recv_datagram(&mut self) -> Result<DecodedDatagram, QuinnDatagramError> {
        let bytes = self.connection.read_datagram().await?;
        let decoded = self.endpoint.open(&bytes)?;
        Ok(decoded)
    }
}

/// Opens a bidirectional Quinn stream and wraps it as a Foctet secure channel.
pub async fn open_secure_channel(
    connection: &quinn::Connection,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    open_secure_channel_with(connection, session, TransportConfig::default()).await
}

/// Opens a bidirectional Quinn stream and applies a custom transport config.
pub async fn open_secure_channel_with(
    connection: &quinn::Connection,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .build_from_split(recv, send, session)
        .map_err(TransportChannelError::core)
}

/// Opens a bidirectional Quinn stream, runs the native Foctet handshake, and wraps it as a secure channel.
pub async fn open_secure_channel_with_handshake(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Opens a bidirectional Quinn stream, runs the native Foctet handshake, and applies a custom transport config.
pub async fn open_secure_channel_with_handshake_and_config(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    open_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Opens a bidirectional Quinn stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
pub async fn open_secure_channel_with_handshake_and_auth_config(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .establish_initiator_with_auth(SplitIo::from_split(recv, send), thresholds, auth)
        .await
        .map_err(TransportChannelError::core)
}

/// Accepts a bidirectional Quinn stream and wraps it as a Foctet secure channel.
pub async fn accept_secure_channel(
    connection: &quinn::Connection,
    session: Session,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    accept_secure_channel_with(connection, session, TransportConfig::default()).await
}

/// Accepts a bidirectional Quinn stream and applies a custom transport config.
pub async fn accept_secure_channel_with(
    connection: &quinn::Connection,
    session: Session,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .build_from_split(recv, send, session)
        .map_err(TransportChannelError::core)
}

/// Accepts a bidirectional Quinn stream, runs the native Foctet handshake, and wraps it as a secure channel.
pub async fn accept_secure_channel_with_handshake(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        TransportConfig::default(),
    )
    .await
}

/// Accepts a bidirectional Quinn stream, runs the native Foctet handshake, and applies a custom transport config.
pub async fn accept_secure_channel_with_handshake_and_config(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    accept_secure_channel_with_handshake_and_auth_config(
        connection,
        thresholds,
        SessionAuthConfig::unauthenticated_for_testing(),
        config,
    )
    .await
}

/// Accepts a bidirectional Quinn stream, runs the native Foctet handshake with explicit auth config, and applies a custom transport config.
pub async fn accept_secure_channel_with_handshake_and_auth_config(
    connection: &quinn::Connection,
    thresholds: RekeyThresholds,
    auth: SessionAuthConfig,
    config: TransportConfig,
) -> Result<
    TokioTransportChannel<SplitIo<quinn::RecvStream, quinn::SendStream>>,
    TransportChannelError<quinn::ConnectionError>,
> {
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(TransportChannelError::transport)?;
    TokioTransportBuilder::new()
        .with_config(config)
        .establish_responder_with_auth(SplitIo::from_split(recv, send), thresholds, auth)
        .await
        .map_err(TransportChannelError::core)
}

#[cfg(all(test, feature = "runtime-tokio"))]
mod datagram_tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use foctet_core::{RekeyThresholds, Session};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::QuinnDatagramChannel;
    use crate::{SecureDatagramChannel, TokioTransportBuilder};

    fn server_endpoint() -> (quinn::Endpoint, Vec<CertificateDer<'static>>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("self-signed cert");
        let cert_der = CertificateDer::from(cert.cert);
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key_der).expect("config");
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let endpoint = quinn::Endpoint::server(server_config, addr).expect("server endpoint");
        (endpoint, vec![cert_der])
    }

    fn client_endpoint(cert_chain: &[CertificateDer<'static>]) -> quinn::Endpoint {
        let mut roots = rustls::RootCertStore::empty();
        for cert in cert_chain {
            roots.add(cert.clone()).expect("add root");
        }
        let client_config =
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config");
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let mut endpoint = quinn::Endpoint::client(addr).expect("client endpoint");
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    /// Establishes a QUIC connection pair and runs the Foctet handshake over a
    /// bi-directional stream, returning both connections and their sessions.
    async fn establish() -> (quinn::Connection, Session, quinn::Connection, Session) {
        let (server_ep, cert_chain) = server_endpoint();
        let server_addr = server_ep.local_addr().expect("server addr");
        let client_ep = client_endpoint(&cert_chain);

        let server_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("incoming");
            incoming.await.expect("server connection")
        });
        let client_conn = client_ep
            .connect(server_addr, "localhost")
            .expect("connect")
            .await
            .expect("client connection");
        let server_conn = server_task.await.expect("server join");

        let client_conn_hs = client_conn.clone();
        let client_hs = tokio::spawn(async move {
            let (send, recv) = client_conn_hs.open_bi().await.expect("open_bi");
            TokioTransportBuilder::new()
                .establish_initiator_from_split(recv, send, RekeyThresholds::default())
                .await
                .expect("client handshake")
                .into_transport_and_session()
        });

        let (server_send, server_recv) = server_conn.accept_bi().await.expect("accept_bi");
        let server_channel = TokioTransportBuilder::new()
            .establish_responder_from_split(server_recv, server_send, RekeyThresholds::default())
            .await
            .expect("server handshake");
        let (_server_io, server_session) = server_channel.into_transport_and_session();
        let (_client_io, client_session) = client_hs.await.expect("client hs join");

        (client_conn, client_session, server_conn, server_session)
    }

    #[tokio::test]
    async fn quinn_datagram_roundtrip_over_real_connection() {
        let (client_conn, client_session, server_conn, server_session) = establish().await;

        let mut client_dgram =
            QuinnDatagramChannel::from_active_session(client_conn, &client_session)
                .expect("client datagram channel");
        let mut server_dgram =
            QuinnDatagramChannel::from_active_session(server_conn, &server_session)
                .expect("server datagram channel");

        client_dgram
            .send_datagram(0, 0, b"datagram payload")
            .expect("send datagram");
        let received = server_dgram.recv_datagram().await.expect("recv datagram");
        assert_eq!(received.plaintext, b"datagram payload");

        server_dgram
            .send_datagram(0, 0, b"reply payload")
            .expect("send reply");
        let reply = client_dgram.recv_datagram().await.expect("recv reply");
        assert_eq!(reply.plaintext, b"reply payload");
    }

    #[tokio::test]
    async fn generic_secure_datagram_channel_over_quinn() {
        // The same QUIC connection works through the backend-agnostic
        // `DatagramTransport` / `SecureDatagramChannel` interface (§3.2).
        let (client_conn, client_session, server_conn, server_session) = establish().await;

        let mut client = SecureDatagramChannel::from_active_session(client_conn, &client_session)
            .expect("client secure datagram channel");
        let mut server = SecureDatagramChannel::from_active_session(server_conn, &server_session)
            .expect("server secure datagram channel");

        client
            .send_datagram(0, 0, b"generic datagram")
            .await
            .expect("send");
        let received = server.recv_datagram().await.expect("recv");
        assert_eq!(received.plaintext, b"generic datagram");
    }
}
