//! Datagram-oriented Foctet endpoint (one frame per datagram).
//!
//! Stream framing ([`crate::frame::FoctetFramed`]) length-prefixes frames inside
//! a reliable, ordered byte stream. Datagram transports (UDP, QUIC datagrams,
//! WebTransport datagrams) are unreliable, unordered, and message-bounded, so
//! they need a different contract:
//!
//! - **Exactly one complete, bounded frame per datagram.** A datagram with
//!   trailing bytes or a truncated frame is rejected; there is no cross-datagram
//!   reassembly.
//! - **A configured maximum datagram size** ([`DatagramConfig::max_datagram_size`])
//!   that the caller MUST keep below the transport path MTU. Outbound frames that
//!   would exceed it fail closed rather than being emitted.
//! - **Loss and reordering are expected.** The replay window accepts
//!   out-of-order sequence numbers within its span and rejects duplicates, so
//!   dropped or reordered datagrams do not break the channel.
//! - **Replay state is committed only after AEAD authentication**, so a forged
//!   datagram cannot advance the window (matching the stream paths).
//! - **Fail-closed endpoint lifetime.** Authentication, parsing, replay, key,
//!   or sequence failures make an endpoint terminal; applications must create
//!   a fresh authenticated session rather than continue on a diverged channel.
//! - **Anti-amplification** (not sending many bytes to an unverified peer) is a
//!   transport-layer responsibility and is documented for adapters; this codec
//!   does not itself send data.
//!
//! Outbound sequence numbers are tracked per `(key_id, stream_id)` and fail
//! closed on exhaustion, so a `(key_id, stream_id, seq)` nonce is never reused.

use std::collections::HashMap;

use crate::{
    CoreError,
    crypto::{Direction, KeyHandle, decrypt_frame_with_key, encrypt_frame},
    frame::{FRAME_HEADER_LEN, Frame, FrameHeader},
    limits::{DEFAULT_MAX_OUTBOUND_STREAMS, MAX_OUTBOUND_STREAMS, MAX_RETAINED_KEYS},
    replay::{DEFAULT_MAX_REPLAY_WINDOWS, DEFAULT_REPLAY_WINDOW, ReplayProtector},
    sequence::OutboundSequence,
};

/// AEAD tag length added to every frame ciphertext.
const TAG_LEN: usize = 16;

/// Per-frame wire overhead (fixed header + AEAD tag).
pub const DATAGRAM_FRAME_OVERHEAD: usize = FRAME_HEADER_LEN + TAG_LEN;

/// Conservative default maximum datagram size in bytes.
///
/// Chosen to fit comfortably within the QUIC minimum datagram allowance
/// (`1232` bytes) with headroom; tune to the actual transport path MTU.
pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1200;

/// Configuration for a [`DatagramEndpoint`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatagramConfig {
    /// Maximum on-wire datagram (single frame) size in bytes.
    pub max_datagram_size: usize,
    /// Per-`(key_id, stream_id)` replay window span.
    pub replay_window: u64,
    /// Maximum number of distinct replay windows tracked simultaneously.
    pub max_replay_windows: usize,
    /// Maximum number of distinct stream IDs tracked for outbound sequencing.
    pub max_outbound_streams: usize,
    /// Number of previous keys retained for inbound decryption after rekey.
    pub max_retained_keys: usize,
}

impl Default for DatagramConfig {
    fn default() -> Self {
        Self {
            max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
            replay_window: DEFAULT_REPLAY_WINDOW,
            max_replay_windows: DEFAULT_MAX_REPLAY_WINDOWS,
            max_outbound_streams: DEFAULT_MAX_OUTBOUND_STREAMS,
            max_retained_keys: 2,
        }
    }
}

/// One decrypted inbound datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedDatagram {
    /// Authenticated frame header.
    pub header: FrameHeader,
    /// Decrypted payload bytes.
    pub plaintext: Vec<u8>,
}

/// Seals and opens individual Foctet datagrams (one frame each).
///
/// This type performs no I/O; pair it with a datagram transport adapter (for
/// example a QUIC or WebTransport datagram socket) that moves the returned bytes.
#[derive(Clone, Debug)]
pub struct DatagramEndpoint {
    keys: Vec<KeyHandle>,
    active_key_id: u8,
    max_retained_keys: usize,
    inbound_direction: Direction,
    outbound_direction: Direction,
    next_seq: HashMap<(u8, u32), OutboundSequence>,
    replay: ReplayProtector,
    max_datagram_size: usize,
    max_outbound_streams: usize,
    terminal: bool,
}

impl DatagramEndpoint {
    /// Constructs an endpoint from shared traffic keys without a session lease.
    ///
    /// # Danger: nonce-domain ownership
    ///
    /// The caller must prove that no other outbound endpoint can use the same
    /// `(direction, key_id, stream_id)` nonce domain. Prefer
    /// [`Session::claim_datagram_endpoint`](crate::Session::claim_datagram_endpoint).
    pub fn dangerously_from_shared_keys_without_nonce_ownership(
        keys: KeyHandle,
        inbound_direction: Direction,
        outbound_direction: Direction,
    ) -> Self {
        Self::new(keys, inbound_direction, outbound_direction)
    }

    /// Creates a nonce-owning endpoint from a single-use session lease.
    pub fn from_session_lease(lease: crate::DatagramEndpointKeyLease) -> Self {
        Self::with_config(
            lease.keys,
            lease.inbound_direction,
            lease.outbound_direction,
            DatagramConfig::default(),
        )
    }

    /// Creates a nonce-owning endpoint from a lease with explicit limits.
    pub fn from_session_lease_with_config(
        lease: crate::DatagramEndpointKeyLease,
        config: DatagramConfig,
    ) -> Self {
        Self::with_config(
            lease.keys,
            lease.inbound_direction,
            lease.outbound_direction,
            config,
        )
    }

    /// Creates a datagram endpoint with default configuration.
    fn new(keys: KeyHandle, inbound_direction: Direction, outbound_direction: Direction) -> Self {
        Self::with_config(
            keys,
            inbound_direction,
            outbound_direction,
            DatagramConfig::default(),
        )
    }

    /// Creates a datagram endpoint with explicit configuration.
    pub(crate) fn with_config(
        keys: KeyHandle,
        inbound_direction: Direction,
        outbound_direction: Direction,
        config: DatagramConfig,
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
            max_datagram_size: config.max_datagram_size.max(DATAGRAM_FRAME_OVERHEAD + 1),
            max_outbound_streams: config.max_outbound_streams.clamp(1, MAX_OUTBOUND_STREAMS),
            terminal: false,
        }
    }

    /// Returns the configured maximum datagram size in bytes.
    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    /// Returns the maximum plaintext bytes that fit in one datagram.
    pub fn max_plaintext_len(&self) -> usize {
        self.max_datagram_size - DATAGRAM_FRAME_OVERHEAD
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

    /// Seals plaintext into a single datagram using the active key.
    ///
    /// Fails closed with [`CoreError::FrameTooLarge`] when the resulting frame
    /// would exceed [`DatagramConfig::max_datagram_size`], and with
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
        if bytes.len() > self.max_datagram_size {
            return Err(CoreError::FrameTooLarge);
        }

        // Reserve the next sequence only after the datagram is known to be
        // emittable, so a rejected datagram never consumes a nonce.
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

    /// Opens one datagram into its decrypted payload.
    ///
    /// The datagram MUST contain exactly one complete frame and no trailing
    /// bytes. The ciphertext is authenticated before replay state is committed.
    pub fn open(&mut self, datagram: &[u8]) -> Result<DecodedDatagram, CoreError> {
        if self.terminal {
            return Err(CoreError::TransportTerminal);
        }
        let result = self.open_inner(datagram);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }

    fn open_inner(&mut self, datagram: &[u8]) -> Result<DecodedDatagram, CoreError> {
        if datagram.len() > self.max_datagram_size {
            return Err(CoreError::FrameTooLarge);
        }
        if datagram.len() < FRAME_HEADER_LEN {
            return Err(CoreError::InvalidHeaderLength(datagram.len()));
        }

        // `Frame::from_bytes` requires the ciphertext length to match the header
        // exactly, enforcing one complete frame per datagram with no trailing
        // bytes and no truncation.
        let frame = Frame::from_bytes(datagram)?;
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

        Ok(DecodedDatagram {
            header: frame.header,
            plaintext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{EphemeralKeyPair, KeyHandle, derive_traffic_keys, random_session_salt};

    fn endpoints() -> (DatagramEndpoint, DatagramEndpoint) {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let ss = a.shared_secret(b.public).expect("shared secret");
        let salt = random_session_salt();
        let keys = KeyHandle::new(derive_traffic_keys(&ss, &salt, 1).expect("traffic keys"));
        // Client seals C2S / opens S2C; server is the mirror.
        let client = DatagramEndpoint::new(keys.clone(), Direction::S2C, Direction::C2S);
        let server = DatagramEndpoint::new(keys, Direction::C2S, Direction::S2C);
        (client, server)
    }

    #[test]
    fn datagram_roundtrip() {
        let (mut client, mut server) = endpoints();
        let dg = client.seal(0, 0, b"hello datagram").expect("seal");
        let opened = server.open(&dg).expect("open");
        assert_eq!(opened.plaintext, b"hello datagram");
        assert_eq!(opened.header.seq, 0);
    }

    #[test]
    fn tolerates_loss_and_reordering() {
        let (mut client, mut server) = endpoints();
        let d0 = client.seal(0, 0, b"zero").expect("d0");
        let d1 = client.seal(0, 0, b"one").expect("d1");
        let d2 = client.seal(0, 0, b"two").expect("d2");

        // Deliver out of order, drop nothing: 2, 0, 1.
        assert_eq!(server.open(&d2).expect("d2").plaintext, b"two");
        assert_eq!(server.open(&d0).expect("d0").plaintext, b"zero");
        assert_eq!(server.open(&d1).expect("d1").plaintext, b"one");

        // A duplicate is rejected as a replay.
        let err = server.open(&d1).expect_err("duplicate rejected");
        assert!(matches!(err, CoreError::Replay));
        assert!(server.is_terminal());
        assert!(matches!(
            server.open(&d0),
            Err(CoreError::TransportTerminal)
        ));
    }

    #[test]
    fn outbound_stream_count_is_bounded_before_encryption() {
        let (client, _server) = endpoints();
        let config = DatagramConfig {
            max_outbound_streams: 2,
            ..DatagramConfig::default()
        };
        let mut endpoint = DatagramEndpoint::with_config(
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
    fn rejects_oversized_outbound_and_keeps_sequence() {
        let (mut client, _server) = endpoints();
        let config = DatagramConfig {
            max_datagram_size: DATAGRAM_FRAME_OVERHEAD + 4,
            ..DatagramConfig::default()
        };
        let mut small = DatagramEndpoint::with_config(
            client.active_keys().unwrap().clone(),
            Direction::S2C,
            Direction::C2S,
            config,
        );
        // 4-byte plaintext fits exactly.
        let ok = small.seal(0, 0, b"abcd").expect("fits");
        assert!(ok.len() <= small.max_datagram_size());
        // 5 bytes overflow and must fail closed without consuming a sequence.
        let err = small.seal(0, 0, b"abcde").expect_err("too large");
        assert!(matches!(err, CoreError::FrameTooLarge));
        // The next valid datagram still uses seq 1 (only the first succeeded).
        let next = small.seal(0, 0, b"efgh").expect("next");
        let frame = Frame::from_bytes(&next).expect("parse");
        assert_eq!(frame.header.seq, 1);
        let _ = client.seal(0, 0, b"x");
    }

    #[test]
    fn authentication_failure_makes_datagram_endpoint_terminal() {
        let (mut client, mut server) = endpoints();
        // Forge a high-sequence datagram by corrupting an authentic one.
        let _warm = client.seal(0, 0, b"warm");
        let mut forged = client.seal(0, 0, b"forged").expect("seal");
        let last = forged.len() - 1;
        forged[last] ^= 0xff;

        let err = server.open(&forged).expect_err("forged must fail auth");
        assert!(matches!(err, CoreError::Aead));
        assert!(server.is_terminal());

        let d0 = client.seal(1, 0, b"genuine").expect("seal new stream");
        assert!(matches!(
            server.open(&d0),
            Err(CoreError::TransportTerminal)
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let (mut client, mut server) = endpoints();
        let mut dg = client.seal(0, 0, b"payload").expect("seal");
        dg.push(0x00); // extra trailing byte -> not exactly one frame
        let err = server.open(&dg).expect_err("trailing bytes rejected");
        assert!(matches!(err, CoreError::CiphertextLengthMismatch { .. }));
    }
}
