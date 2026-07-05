//! Raw UDP [`DatagramTransport`] adapter.
//!
//! This wraps a connected `tokio::net::UdpSocket` so it implements
//! [`DatagramTransport`] and can be used with [`crate::SecureDatagramChannel`].
//!
//! Unlike QUIC/WebTransport datagrams, raw UDP has no built-in connection or
//! peer authentication. This adapter only moves bytes; *you* are responsible
//! for:
//!
//! - **Session setup.** Negotiate Foctet traffic keys out of band (e.g. a
//!   Foctet handshake over a TCP/TLS control connection, or any other secure
//!   channel) before constructing the [`crate::SecureDatagramChannel`], exactly as
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
//!   handshake amplification limits address. This adapter can enforce that for
//!   you — see [`UdpDatagramTransport::with_anti_amplification`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use foctet_core::DEFAULT_MAX_DATAGRAM_SIZE;
use tokio::net::UdpSocket;

use crate::datagram::DatagramTransport;

/// The standard QUIC anti-amplification factor: a server may send at most this
/// many times the bytes it has received from an unvalidated peer.
pub const DEFAULT_AMPLIFICATION_FACTOR: u64 = 3;

/// Tracks the anti-amplification budget for one peer.
#[derive(Debug)]
struct AmplificationLimiter {
    factor: u64,
    received: AtomicU64,
    sent: AtomicU64,
    validated: AtomicBool,
}

/// [`DatagramTransport`] over a connected `tokio::net::UdpSocket`.
#[derive(Clone, Debug)]
pub struct UdpDatagramTransport {
    socket: Arc<UdpSocket>,
    max_datagram_size: usize,
    limiter: Option<Arc<AmplificationLimiter>>,
}

impl UdpDatagramTransport {
    /// Wraps a socket, defaulting the reported max datagram size to
    /// [`DEFAULT_MAX_DATAGRAM_SIZE`] (a conservative bound safe for typical
    /// Internet paths without path-MTU discovery).
    ///
    /// The socket must already be connected to the single intended peer (see
    /// the module docs); this constructor does not call `connect` for you.
    /// Anti-amplification is **off** by default; opt in with
    /// [`UdpDatagramTransport::with_anti_amplification`].
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
            limiter: None,
        }
    }

    /// Overrides the reported max datagram size, e.g. after path-MTU
    /// discovery or for a known-constrained network.
    pub fn with_max_datagram_size(mut self, max_datagram_size: usize) -> Self {
        self.max_datagram_size = max_datagram_size;
        self
    }

    /// Enforces an anti-amplification limit until the peer is validated.
    ///
    /// While the peer is **not** validated, [`Self::send_datagram`] refuses to
    /// send once the cumulative bytes sent would exceed `factor` times the
    /// cumulative bytes received (returning a [`std::io::ErrorKind::WouldBlock`]
    /// error), so a spoofed source address cannot turn this endpoint into a
    /// reflector/amplifier. Call [`Self::mark_peer_validated`] once the peer has
    /// proven it can receive at its claimed address (typically when the Foctet
    /// handshake over this path completes) to lift the limit.
    ///
    /// `factor` is clamped to at least 1; [`DEFAULT_AMPLIFICATION_FACTOR`] (3)
    /// matches QUIC. Counters are shared across clones of this transport.
    pub fn with_anti_amplification(mut self, factor: u64) -> Self {
        self.limiter = Some(Arc::new(AmplificationLimiter {
            factor: factor.max(1),
            received: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            validated: AtomicBool::new(false),
        }));
        self
    }

    /// Marks the peer as address-validated, lifting any anti-amplification
    /// limit. No-op if anti-amplification was not enabled.
    pub fn mark_peer_validated(&self) {
        if let Some(limiter) = &self.limiter {
            limiter.validated.store(true, Ordering::Release);
        }
    }

    /// Returns whether the peer has been marked validated (always `true` when
    /// anti-amplification is not enabled).
    pub fn is_peer_validated(&self) -> bool {
        match &self.limiter {
            Some(limiter) => limiter.validated.load(Ordering::Acquire),
            None => true,
        }
    }

    /// Returns the underlying socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

impl DatagramTransport for UdpDatagramTransport {
    type Error = std::io::Error;

    async fn send_datagram(&self, datagram: Vec<u8>) -> Result<(), Self::Error> {
        if let Some(limiter) = &self.limiter
            && !limiter.validated.load(Ordering::Acquire)
        {
            let budget = limiter
                .received
                .load(Ordering::Acquire)
                .saturating_mul(limiter.factor);
            let projected = limiter
                .sent
                .load(Ordering::Acquire)
                .saturating_add(datagram.len() as u64);
            if projected > budget {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "anti-amplification limit reached: cannot send more until the peer is \
                     validated or has sent more",
                ));
            }
        }

        self.socket.send(&datagram).await?;

        if let Some(limiter) = &self.limiter {
            limiter
                .sent
                .fetch_add(datagram.len() as u64, Ordering::AcqRel);
        }
        Ok(())
    }

    async fn recv_datagram(&self) -> Result<Vec<u8>, Self::Error> {
        let mut buf = vec![0u8; self.max_datagram_size];
        let n = self.socket.recv(&mut buf).await?;
        buf.truncate(n);
        if let Some(limiter) = &self.limiter {
            limiter.received.fetch_add(n as u64, Ordering::AcqRel);
        }
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

    #[tokio::test]
    async fn anti_amplification_caps_sends_until_validated() {
        use std::io::ErrorKind;

        let (sock_a, sock_b) = connected_pair().await;
        // `a` is the responder enforcing a 3x anti-amplification budget.
        let a = UdpDatagramTransport::new(sock_a).with_anti_amplification(3);
        let b = UdpDatagramTransport::new(sock_b);
        assert!(!a.is_peer_validated());

        // With nothing received yet, the budget is zero: any send is refused.
        let err = a
            .send_datagram(vec![0u8; 32])
            .await
            .expect_err("send before any receipt must be blocked");
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        // The peer sends 100 bytes; the budget becomes 300.
        b.send_datagram(vec![0u8; 100]).await.expect("peer sends");
        let got = a.recv_datagram().await.expect("recv");
        assert_eq!(got.len(), 100);

        // 300 bytes are now allowed; the next 100-byte send (total 400) is not.
        a.send_datagram(vec![0u8; 200])
            .await
            .expect("within budget");
        a.send_datagram(vec![0u8; 100]).await.expect("at budget");
        let err = a
            .send_datagram(vec![0u8; 100])
            .await
            .expect_err("over budget must be blocked");
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        // Once the peer is validated the limit no longer applies.
        a.mark_peer_validated();
        assert!(a.is_peer_validated());
        a.send_datagram(vec![0u8; 4096])
            .await
            .expect("validated peer is unlimited");
    }
}
