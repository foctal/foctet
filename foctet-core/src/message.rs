//! Message-oriented Foctet endpoint (one frame per discrete message).
//!
//! This is the codec for **reliable, ordered, message-bounded** transports —
//! most importantly raw WebSocket messages, where each WebSocket frame is a
//! discrete unit and the application wants to preserve those boundaries instead
//! of treating the connection as an opaque byte stream
//! ([`crate::frame::FoctetFramed`]).
//!
//! It sits between the two existing shapes:
//!
//! - Unlike [`crate::frame::FoctetFramed`] (byte stream), there is **exactly one
//!   complete frame per message** with no cross-message reassembly and no
//!   length prefix — the transport already preserves message boundaries.
//! - Unlike [`crate::datagram::DatagramEndpoint`] (datagram), the transport is
//!   reliable and ordered, so the default maximum message size is large
//!   ([`DEFAULT_MAX_MESSAGE_SIZE`]) rather than MTU-bounded. The replay window is
//!   still used, so duplicate or reordered messages (e.g. from a buggy or hostile
//!   peer) are rejected, and **replay state is committed only after AEAD
//!   authentication**.
//! - **Fail-closed endpoint lifetime.** Authentication, parsing, replay, key,
//!   or sequence failures make an endpoint terminal; applications must create
//!   a fresh authenticated session rather than continue on a diverged channel.
//!
//! Outbound sequence numbers are tracked per `(key_id, stream_id)` and fail
//! closed on exhaustion, so a `(key_id, stream_id, seq)` nonce is never reused.

use std::collections::HashMap;

use crate::{
    CoreError,
    crypto::{Direction, KeyHandle, decrypt_frame_with_key, encrypt_frame},
    frame::{FRAME_HEADER_LEN, Frame, FrameHeader},
    limits::{
        DEFAULT_MAX_OUTBOUND_STREAMS, DEFAULT_MAX_RETAINED_KEYS, MAX_OUTBOUND_STREAMS,
        MAX_RETAINED_KEYS,
    },
    replay::{DEFAULT_MAX_REPLAY_WINDOWS, DEFAULT_REPLAY_WINDOW, ReplayProtector},
    sequence::OutboundSequence,
};

/// AEAD tag length added to every frame ciphertext.
const TAG_LEN: usize = 16;

/// Per-frame wire overhead (fixed header + AEAD tag).
pub const MESSAGE_FRAME_OVERHEAD: usize = FRAME_HEADER_LEN + TAG_LEN;

/// Default maximum on-wire message (single frame) size in bytes (16 MiB).
///
/// Matches [`crate::limits::DEFAULT_MAX_CIPHERTEXT_LEN`] so the message shape and
/// the byte-stream shape accept the same maximum frame by default. Tune to the
/// transport's own message-size limit (for example a WebSocket server's
/// `max_message_size`).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = crate::limits::DEFAULT_MAX_CIPHERTEXT_LEN;

/// Configuration for a [`MessageEndpoint`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageConfig {
    /// Maximum on-wire message (single frame) size in bytes.
    pub max_message_size: usize,
    /// Per-`(key_id, stream_id)` replay window span.
    pub replay_window: u64,
    /// Maximum number of distinct replay windows tracked simultaneously.
    pub max_replay_windows: usize,
    /// Maximum number of distinct stream IDs tracked for outbound sequencing.
    pub max_outbound_streams: usize,
    /// Number of previous keys retained for inbound decryption after rekey.
    pub max_retained_keys: usize,
}

impl Default for MessageConfig {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            replay_window: DEFAULT_REPLAY_WINDOW,
            max_replay_windows: DEFAULT_MAX_REPLAY_WINDOWS,
            max_outbound_streams: DEFAULT_MAX_OUTBOUND_STREAMS,
            max_retained_keys: DEFAULT_MAX_RETAINED_KEYS,
        }
    }
}

/// One decrypted inbound message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedMessage {
    /// Authenticated frame header.
    pub header: FrameHeader,
    /// Decrypted payload bytes.
    pub plaintext: Vec<u8>,
}

/// Seals and opens individual Foctet messages (one frame each).
///
/// This type performs no I/O; pair it with a message transport adapter (for
/// example a raw WebSocket connection) that moves the returned bytes preserving
/// message boundaries.
#[derive(Clone, Debug)]
pub struct MessageEndpoint {
    keys: Vec<KeyHandle>,
    active_key_id: u8,
    max_retained_keys: usize,
    inbound_direction: Direction,
    outbound_direction: Direction,
    next_seq: HashMap<(u8, u32), OutboundSequence>,
    replay: ReplayProtector,
    max_message_size: usize,
    max_outbound_streams: usize,
    terminal: bool,
}

impl MessageEndpoint {
    /// Constructs an endpoint from shared traffic keys without a session lease.
    ///
    /// # Danger: nonce-domain ownership
    ///
    /// The caller must prove that no other outbound endpoint can use the same
    /// `(direction, key_id, stream_id)` nonce domain. Prefer
    /// [`Session::claim_message_endpoint`](crate::Session::claim_message_endpoint).
    pub fn dangerously_from_shared_keys_without_nonce_ownership(
        keys: KeyHandle,
        inbound_direction: Direction,
        outbound_direction: Direction,
    ) -> Self {
        Self::new(keys, inbound_direction, outbound_direction)
    }

    /// Creates a nonce-owning endpoint from a single-use session lease.
    pub fn from_session_lease(lease: crate::MessageEndpointKeyLease) -> Self {
        Self::with_config(
            lease.keys,
            lease.inbound_direction,
            lease.outbound_direction,
            MessageConfig::default(),
        )
    }

    /// Creates a nonce-owning endpoint from a lease with explicit limits.
    pub fn from_session_lease_with_config(
        lease: crate::MessageEndpointKeyLease,
        config: MessageConfig,
    ) -> Self {
        Self::with_config(
            lease.keys,
            lease.inbound_direction,
            lease.outbound_direction,
            config,
        )
    }

    /// Creates a message endpoint with default configuration.
    fn new(keys: KeyHandle, inbound_direction: Direction, outbound_direction: Direction) -> Self {
        Self::with_config(
            keys,
            inbound_direction,
            outbound_direction,
            MessageConfig::default(),
        )
    }

    /// Creates a message endpoint with explicit configuration.
    pub(crate) fn with_config(
        keys: KeyHandle,
        inbound_direction: Direction,
        outbound_direction: Direction,
        config: MessageConfig,
    ) -> Self {
        Self {
            active_key_id: keys.key_id,
            keys: vec![keys],
            max_retained_keys: config.max_retained_keys.clamp(1, MAX_RETAINED_KEYS),
            inbound_direction,
            outbound_direction,
            next_seq: HashMap::new(),
            replay: ReplayProtector::new(config.replay_window)
                .with_max_windows(config.max_replay_windows),
            max_message_size: config.max_message_size.max(MESSAGE_FRAME_OVERHEAD + 1),
            max_outbound_streams: config.max_outbound_streams.clamp(1, MAX_OUTBOUND_STREAMS),
            terminal: false,
        }
    }

    /// Returns the configured maximum message size in bytes.
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Returns the maximum plaintext bytes that fit in one message.
    pub fn max_plaintext_len(&self) -> usize {
        self.max_message_size - MESSAGE_FRAME_OVERHEAD
    }

    /// Returns the active key identifier.
    pub fn active_key_id(&self) -> u8 {
        self.active_key_id
    }

    /// Returns how many inbound frames this endpoint's replay protection has
    /// rejected since creation (see
    /// [`crate::ReplayProtector::rejections`]); an observability counter that
    /// carries no key material.
    pub fn replay_rejections(&self) -> u64 {
        self.replay.rejections()
    }

    /// Returns whether a protocol failure made this endpoint terminal.
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Returns known key IDs, active first.
    pub fn known_key_ids(&self) -> Vec<u8> {
        self.keys.iter().map(|k| k.key_id).collect()
    }

    /// Installs new active keys and retains a bounded set of previous keys.
    pub fn install_active_keys(&mut self, keys: KeyHandle) {
        if self.active_key_id != keys.key_id {
            self.next_seq.clear();
        }
        self.keys.retain(|k| k.key_id != keys.key_id);
        self.keys.insert(0, keys.clone());
        self.active_key_id = keys.key_id;
        let keep = self.max_retained_keys + 1;
        if self.keys.len() > keep {
            self.keys.truncate(keep);
        }
    }

    fn active_keys(&self) -> Result<&KeyHandle, CoreError> {
        self.keys
            .iter()
            .find(|k| k.key_id == self.active_key_id)
            .ok_or(CoreError::MissingSessionSecret)
    }

    fn key_for_id(&self, key_id: u8) -> Option<&KeyHandle> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }

    /// Seals plaintext into a single message using the active key.
    ///
    /// Fails closed with [`CoreError::FrameTooLarge`] when the resulting frame
    /// would exceed [`MessageConfig::max_message_size`], and with
    /// [`CoreError::SequenceExhausted`] when the per-stream sequence space is
    /// exhausted. In both cases no sequence number is consumed.
    pub fn seal(
        &mut self,
        stream_id: u32,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        if self.terminal {
            return Err(CoreError::TransportTerminal);
        }
        let keys = self.active_keys()?.clone();
        let key_id = keys.key_id;
        if !self.next_seq.contains_key(&(key_id, stream_id))
            && self.next_seq.len() >= self.max_outbound_streams
        {
            return Err(CoreError::OutboundStreamCapacityExceeded);
        }
        let sequence = self
            .next_seq
            .get(&(key_id, stream_id))
            .copied()
            .unwrap_or_default();
        let seq = sequence.current();

        let frame = encrypt_frame(
            &keys,
            self.outbound_direction,
            flags,
            stream_id,
            seq,
            plaintext,
        )?;
        let bytes = frame.to_bytes();
        if bytes.len() > self.max_message_size {
            return Err(CoreError::FrameTooLarge);
        }

        // Reserve the next sequence only after the message is known to be
        // emittable, so a rejected message never consumes a nonce.
        let next = match sequence.prepared_next() {
            Ok(next) => next,
            Err(error) => {
                self.terminal = true;
                return Err(error);
            }
        };
        self.next_seq.insert((key_id, stream_id), next);
        Ok(bytes)
    }

    /// Opens one message into its decrypted payload.
    ///
    /// The message MUST contain exactly one complete frame and no trailing
    /// bytes. The ciphertext is authenticated before replay state is committed.
    pub fn open(&mut self, message: &[u8]) -> Result<DecodedMessage, CoreError> {
        if self.terminal {
            return Err(CoreError::TransportTerminal);
        }
        let result = self.open_inner(message);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    fn open_inner(&mut self, message: &[u8]) -> Result<DecodedMessage, CoreError> {
        if message.len() > self.max_message_size {
            return Err(CoreError::FrameTooLarge);
        }
        if message.len() < FRAME_HEADER_LEN {
            return Err(CoreError::InvalidHeaderLength(message.len()));
        }

        // `Frame::from_bytes` requires the ciphertext length to match the header
        // exactly, enforcing one complete frame per message with no trailing
        // bytes and no truncation.
        let frame = Frame::from_bytes(message)?;
        frame.header.validate_v0()?;

        let keys = self
            .key_for_id(frame.header.key_id)
            .ok_or(CoreError::UnexpectedKeyId {
                expected: self.active_key_id,
                actual: frame.header.key_id,
            })?;

        let plaintext = decrypt_frame_with_key(keys, self.inbound_direction, &frame)?;
        self.replay.check_and_record(
            frame.header.key_id,
            frame.header.stream_id,
            frame.header.seq,
        )?;

        Ok(DecodedMessage {
            header: frame.header,
            plaintext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{EphemeralKeyPair, derive_traffic_keys, random_session_salt};

    fn endpoints() -> (MessageEndpoint, MessageEndpoint) {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let ss = a.shared_secret(b.public).expect("shared secret");
        let salt = random_session_salt();
        let keys = KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("traffic keys"));
        // Client seals C2S / opens S2C; server is the mirror.
        let client = MessageEndpoint::new(keys.clone(), Direction::S2C, Direction::C2S);
        let server = MessageEndpoint::new(keys, Direction::C2S, Direction::S2C);
        (client, server)
    }

    #[test]
    fn message_roundtrip() {
        let (mut client, mut server) = endpoints();
        let msg = client.seal(0, 0, b"hello message").expect("seal");
        let opened = server.open(&msg).expect("open");
        assert_eq!(opened.plaintext, b"hello message");
        assert_eq!(opened.header.seq, 0);
    }

    #[test]
    fn large_message_above_datagram_mtu_roundtrips() {
        // A message much larger than a datagram MTU is accepted by default,
        // which is the whole point of the message shape versus the datagram one.
        let (mut client, mut server) = endpoints();
        let payload = vec![0x5Au8; 64 * 1024];
        let msg = client.seal(0, 0, &payload).expect("seal large");
        let opened = server.open(&msg).expect("open large");
        assert_eq!(opened.plaintext, payload);
    }

    #[test]
    fn outbound_stream_count_is_bounded_before_encryption() {
        let (client, _server) = endpoints();
        let config = MessageConfig {
            max_outbound_streams: 2,
            ..MessageConfig::default()
        };
        let mut endpoint = MessageEndpoint::with_config(
            client.active_keys().expect("active keys").clone(),
            Direction::S2C,
            Direction::C2S,
            config,
        );
        endpoint.seal(1, 0, b"one").expect("first stream");
        endpoint.seal(2, 0, b"two").expect("second stream");
        let err = endpoint
            .seal(3, 0, b"three")
            .expect_err("third stream must exceed the cap");
        assert!(matches!(err, CoreError::OutboundStreamCapacityExceeded));
        assert!(!endpoint.is_terminal());
        endpoint
            .seal(1, 0, b"existing")
            .expect("an existing stream remains usable");
    }

    #[test]
    fn duplicate_message_is_rejected_as_replay() {
        let (mut client, mut server) = endpoints();
        let m0 = client.seal(0, 0, b"zero").expect("m0");
        let m1 = client.seal(0, 0, b"one").expect("m1");

        assert_eq!(server.open(&m0).expect("m0").plaintext, b"zero");
        assert_eq!(server.open(&m1).expect("m1").plaintext, b"one");

        let err = server.open(&m1).expect_err("duplicate rejected");
        assert!(matches!(err, CoreError::Replay));
        assert!(server.is_terminal());
        assert!(matches!(
            server.open(&m0),
            Err(CoreError::TransportTerminal)
        ));
    }

    #[test]
    fn rejects_oversized_outbound_and_keeps_sequence() {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let ss = a.shared_secret(b.public).expect("shared secret");
        let salt = random_session_salt();
        let keys = KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("traffic keys"));
        let config = MessageConfig {
            max_message_size: MESSAGE_FRAME_OVERHEAD + 4,
            ..MessageConfig::default()
        };
        let mut small = MessageEndpoint::with_config(keys, Direction::S2C, Direction::C2S, config);

        let ok = small.seal(0, 0, b"abcd").expect("fits");
        assert!(ok.len() <= small.max_message_size());
        let err = small.seal(0, 0, b"abcde").expect_err("too large");
        assert!(matches!(err, CoreError::FrameTooLarge));
        // The next valid message still uses seq 1 (only the first succeeded).
        let next = small.seal(0, 0, b"efgh").expect("next");
        let frame = Frame::from_bytes(&next).expect("parse");
        assert_eq!(frame.header.seq, 1);
    }

    #[test]
    fn authentication_failure_makes_message_endpoint_terminal() {
        let (mut client, mut server) = endpoints();
        let mut forged = client.seal(0, 0, b"forged").expect("seal");
        let last = forged.len() - 1;
        forged[last] ^= 0xff;

        let err = server.open(&forged).expect_err("forged must fail auth");
        assert!(matches!(err, CoreError::Aead));
        assert!(server.is_terminal());

        let m = client.seal(1, 0, b"genuine").expect("seal new stream");
        assert!(matches!(server.open(&m), Err(CoreError::TransportTerminal)));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let (mut client, mut server) = endpoints();
        let mut msg = client.seal(0, 0, b"payload").expect("seal");
        msg.push(0x00);
        let err = server.open(&msg).expect_err("trailing bytes rejected");
        assert!(matches!(err, CoreError::CiphertextLengthMismatch { .. }));
    }
}
