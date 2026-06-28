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
