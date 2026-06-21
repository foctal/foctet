//! Raw UDP [`DatagramTransport`] adapter.
//!
//! This wraps a connected `tokio::net::UdpSocket` so it implements
//! [`DatagramTransport`] and can be used with [`SecureDatagramChannel`].
//!
//! Unlike QUIC/WebTransport datagrams, raw UDP has no built-in connection or
//! peer authentication. This adapter only moves bytes; *you* are responsible
//! for:
//!
//! - **Session setup.** Negotiate Foctet traffic keys out of band (e.g. a
//!   Foctet handshake over a TCP/TLS control connection, or any other secure
//!   channel) before constructing the [`SecureDatagramChannel`], exactly as
//!   for the QUIC datagram adapter.
//! - **Peer discovery / pinning.** Call [`tokio::net::UdpSocket::connect`] on
//!   the socket before wrapping it here: this trait carries no destination
//!   address, so an unconnected socket would accept datagrams from (and only
//!   report errors for, not actually block) any source. A connected socket
//!   only sends to and receives from the one peer address passed to
//!   `connect`, which is the raw-UDP equivalent of the implicit peer binding
//!   QUIC/WebTransport give you for free.
//! - **Path/MTU changes and fragmentation.** Not handled here; oversized
//!   plaintext fails closed with `CoreError::FrameTooLarge` (see
//!   `foctet_core::datagram`).
//! - **Anti-amplification.** If you accept first datagrams from
//!   not-yet-validated peers (e.g. a rendezvous/listener socket spawning a
//!   connected socket per peer), bound how much you send before the peer has
//!   proven they can receive at that address, the same concern QUIC's
//!   handshake amplification limits address.

use std::sync::Arc;

use foctet_core::DEFAULT_MAX_DATAGRAM_SIZE;
use tokio::net::UdpSocket;

use crate::datagram::DatagramTransport;

/// [`DatagramTransport`] over a connected `tokio::net::UdpSocket`.
#[derive(Clone, Debug)]
pub struct UdpDatagramTransport {
    socket: Arc<UdpSocket>,
    max_datagram_size: usize,
}

impl UdpDatagramTransport {
    /// Wraps a socket, defaulting the reported max datagram size to
    /// [`DEFAULT_MAX_DATAGRAM_SIZE`] (a conservative bound safe for typical
    /// Internet paths without path-MTU discovery).
    ///
    /// The socket must already be connected to the single intended peer (see
    /// the module docs); this constructor does not call `connect` for you.
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
        }
    }

    /// Overrides the reported max datagram size, e.g. after path-MTU
    /// discovery or for a known-constrained network.
    pub fn with_max_datagram_size(mut self, max_datagram_size: usize) -> Self {
        self.max_datagram_size = max_datagram_size;
        self
    }

    /// Returns the underlying socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

impl DatagramTransport for UdpDatagramTransport {
    type Error = std::io::Error;

    async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Self::Error> {
        self.socket.send(&datagram).await.map(|_| ())
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>, Self::Error> {
        let mut buf = vec![0u8; self.max_datagram_size];
        let n = self.socket.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    fn max_datagram_size(&self) -> Option<usize> {
        Some(self.max_datagram_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecureDatagramChannel;
    use foctet_core::{RekeyThresholds, Session, SessionAuthConfig};

    async fn connected_pair() -> (UdpSocket, UdpSocket) {
        let a = UdpSocket::bind("127.0.0.1:0").await.expect("bind a");
        let b = UdpSocket::bind("127.0.0.1:0").await.expect("bind b");
        a.connect(b.local_addr().expect("b addr"))
            .await
            .expect("connect a->b");
        b.connect(a.local_addr().expect("a addr"))
            .await
            .expect("connect b->a");
        (a, b)
    }

    fn session_pair() -> (Session, Session) {
        let thresholds = RekeyThresholds::default();
        let (mut initiator, hello) = Session::new_initiator_with_auth(
            thresholds.clone(),
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let mut responder = Session::new_responder_with_auth(
            thresholds,
            SessionAuthConfig::unauthenticated_for_testing(),
        );
        let server_hello = responder
            .handle_control(&hello)
            .expect("responder handles hello")
            .expect("server hello");
        initiator
            .handle_control(&server_hello)
            .expect("initiator handles server hello");
        (initiator, responder)
    }

    #[tokio::test]
    async fn roundtrip_over_real_udp_sockets() {
        let (sock_a, sock_b) = connected_pair().await;
        let (session_a, session_b) = session_pair();

        // Directions mirror the QUIC datagram adapter test: each side seals
        // with its own outbound direction and opens with the peer's.
        let mut channel_a = SecureDatagramChannel::from_active_session(
            UdpDatagramTransport::new(sock_a),
            &session_a,
        )
        .expect("channel a");
        let mut channel_b = SecureDatagramChannel::from_active_session(
            UdpDatagramTransport::new(sock_b),
            &session_b,
        )
        .expect("channel b");

        channel_a
            .send_datagram(0, 0, b"hello over udp")
            .await
            .expect("send");
        let decoded = channel_b.recv_datagram().await.expect("recv");
        assert_eq!(decoded.plaintext, b"hello over udp");
        assert_eq!(decoded.header.stream_id, 0);
    }

    #[tokio::test]
    async fn max_datagram_size_override_is_reported() {
        let (sock_a, _sock_b) = connected_pair().await;
        let transport = UdpDatagramTransport::new(sock_a).with_max_datagram_size(500);
        assert_eq!(transport.max_datagram_size(), Some(500));
    }
}
