Foctet Protocol Specification (Draft v0)
========================================

0\. Status
----------

*   **Status**: Draft v0 (work-in-progress)
*   **Scope**: Defines Foctet **Core** (framing, E2EE payload protection, key schedule), **Secure Archive** (encrypted storage format), and references the `application/foctet` one-shot body envelope specification (`docs/http-body-format.md`).
*   **Non-goals**: Transport reliability, congestion control, NAT traversal, application semantics. Those are delegated to underlying transports and higher layers.
*   **Compatibility Policy (Draft v0)**:
    *   The current release line is `0.x` and may include breaking changes while v0 is still draft.
    *   Any wire-level change MUST update `SPEC.md` and corresponding files under `test-vectors/` in the same change.
    *   A stable compatibility commitment is deferred to v1.

* * *

1\. Goals
---------

### 1.1 Primary Goals

*   **E2EE / Zero-Knowledge**: Intermediaries (relays, storage providers) MUST NOT be able to decrypt payloads.
*   **Transport-agnostic**: Works over QUIC, WebTransport, TLS-TCP, WSS, plain TCP/UDP, or any byte stream / datagram.
*   **Thin core, strong invariants**: Minimal primitives with strict security guarantees.
*   **Archiveable**: Encrypted data MUST be representable as a file (or multiple files) for offline distribution and later reassembly.

### 1.2 Quality Attributes

*   **Security**: conservative cryptographic defaults, explicit threat model, replay protection, key rotation.
*   **Correctness**: deterministic parsing, explicit validation rules, reproducible test vectors.
*   **Performance**: bounded allocations and streaming-friendly processing.
*   **Extensibility**: versioned wire format, reserved fields, pluggable crypto profiles.

* * *

2\. Terminology
---------------

*   **Endpoint**: A device/user agent that participates in the E2EE session.
*   **Relay**: A forwarding node that routes frames between endpoints. Relays are untrusted.
*   **Frame**: The smallest authenticated and encrypted unit in Foctet Core.
*   **Stream**: An underlying transport stream (e.g., QUIC stream, TCP connection, WebSocket).
*   **Chunk**: A piece of a larger payload (e.g., file) segmented for streaming or storage.
*   **Secure Archive**: File container format for encrypted chunks + metadata needed for reassembly (metadata itself is encrypted except minimal header).

Normative keywords: **MUST**, **SHOULD**, **MAY**.

* * *

3\. Threat Model
----------------

### 3.1 Adversary Capabilities

*   Can observe, drop, delay, reorder, replay, and inject packets/frames.
*   Can operate relays and storage; relays/storage are considered **honest-but-curious** at minimum, potentially malicious.
*   Cannot break modern cryptography assumptions.

### 3.2 Security Properties Required

*   **Confidentiality**: Payload plaintext not revealed to relays/storage.
*   **Integrity & Authenticity**: Endpoints detect tampering/injection.
*   **Replay protection**: Endpoints detect replayed frames within a session.
*   **Forward secrecy**: Session compromise does not reveal past sessions (and ideally limits within-session exposure via rekey).
*   **Key separation**: Distinct keys for directions and purposes (data vs control).

### 3.3 Misuse Cases (Implementation Risks)

Implementations MUST document and defend against at least:

*   sequence rollback after crash/restart causing nonce reuse
*   reusing `(key material, key_id, stream_id)` with reset `seq`
*   accepting control messages in invalid session states
*   disabling replay checks in production paths
*   using unbounded allocations from attacker-controlled lengths

* * *

4\. Architecture Overview
-------------------------

Foctet consists of two related specs:

1.  **Foctet Core** (wire protocol)
    *   Framing
    *   Handshake / session key establishment (or binding to an existing secure channel)
    *   Payload AEAD encryption
    *   Replay/ordering primitives
    *   Rekey mechanism
2.  **Foctet Secure Archive** (storage format)
    *   Container header (minimal plaintext)
    *   Encrypted metadata
    *   Encrypted chunks
    *   Recipient authorization (who can decrypt)
    *   Optional multi-file split and manifest

Relays forward frames without decryption and SHOULD NOT require any Foctet awareness beyond routing.

* * *

5\. Foctet Core
---------------

### 5.1 Transport Requirements

Foctet Core can run over:

*   **Byte stream** transports (TCP, TLS-TCP, WSS): requires Foctet framing delimiter/length prefix.
*   **Datagram** transports (UDP, QUIC datagram): each datagram MUST contain one or more complete frames.

Transport MUST provide a method to send/receive bytes. Reliability is not required but affects upper-layer behavior.

### 5.2 Core Concepts

*   Every application message is encoded into one or more **Frames**.
*   Each Frame is encrypted with AEAD and authenticated.
*   Frame headers required for routing/replay are included as **AAD**.

* * *

6\. Frame Format (Wire)
-----------------------

### 6.1 Encoding

*   All integer fields are **unsigned**.
*   Multi-byte integers use **network byte order (big-endian)** unless noted.
*   Variable-length integers MAY be used (e.g., QUIC varint). Draft v0 uses fixed-width for simplicity.

### 6.2 Frame Header (plaintext, authenticated via AAD)

| Field | Size | Description |
| --- | --- | --- |
| magic | 2 | `0xF0 0xC7` |
| version | 1 | Protocol version |
| flags | 1 | Bit flags |
| profile\_id | 1 | Crypto profile identifier |
| key\_id | 1 | Active traffic key identifier |
| stream\_id | 4 | Multiplexing ID (0 if unused) |
| seq | 8 | Monotonic sequence number per (direction, stream\_id) |
| ct\_len | 4 | Ciphertext length (bytes) |

Immediately followed by:

*   `ciphertext[ct_len]` (includes AEAD tag depending on profile)
*   No trailing fields in draft v0

**AAD** MUST include the entire header from `magic` through `ct_len`.
`magic` MUST be present in Draft v0.

### 6.3 Flags (draft)

*   bit0: `HAS_ROUTING` (routing info present at higher layer / relay envelope)
*   bit1: `IS_CONTROL` (control frame vs application data)
*   bit2: `ACK_REQUIRED` (hint for upper layers; no semantics in core v0)
*   bit3: `PADDING` (ciphertext includes padding semantics)
*   others: reserved (MUST be 0; receivers in Draft v0 MUST reject frames with unknown bits)

### 6.4 Sequence Numbers & Replay

*   Sender `seq` MUST be strictly increasing for each `(direction, stream_id, key_id)` tuple.
*   Receiver MUST maintain a replay window per tuple and reject duplicates.
*   Receiver MAY accept out-of-order frames only when they are within the replay window.
*   Frames outside the window MUST be rejected unless an application profile explicitly defines a different mode.

Default replay window recommendation: 4096 frames.

* * *

7\. Crypto Profiles
-------------------

### 7.1 Mandatory-to-Implement Profile (v0)

**Profile 0x01: X25519 + HKDF + XChaCha20-Poly1305**

*   Handshake: X25519 ephemeral key agreement
*   KDF: HKDF-SHA256
*   AEAD: XChaCha20-Poly1305
*   Identity: optional in v0 core; can be layered via signed handshake transcript (recommended)

#### 7.1.1 Nonce Construction

*   XChaCha requires 24-byte nonce.
*   Nonce MUST be unique per key.
*   Draft v0 nonce:
    *   `nonce = key_id(1) || stream_id(4) || seq(8) || zeros(11)` (total 24)
*   Endpoints MUST ensure `(key, nonce)` uniqueness; rekey MUST occur before collisions are plausible.

Operational constraints for uniqueness:

*   For a fixed traffic key, `seq` MUST NOT repeat for the same `(direction, stream_id, key_id)` tuple.
*   Reusing a `stream_id` is safe only if `key_id` or traffic key material changes and `seq` restarts from a fresh domain.
*   Reusing the same key material with wrapped `key_id` values is NOT allowed.
*   Implementations SHOULD treat `(direction, stream_id, key_id, seq)` as a write-once space and fail closed on state rollback.

#### 7.1.2 Rekey

Endpoints SHOULD rekey on:

*   elapsed time threshold, OR
*   frame-count threshold, OR
*   data-volume threshold

Rekey produces a new `key_id` and new traffic keys via HKDF with context binding.

#### 7.1.3 Profile 0x01 Algorithm Invariants

For Draft v0 profile `0x01`, implementations MUST satisfy all of the following:

*   **X25519 key material**
    *   Ephemeral public/private keys are 32 bytes.
    *   Shared secret output is 32 bytes.
*   **HKDF-SHA256 derivation**
    *   Initial traffic keys use labels `foctet c2s` and `foctet s2c`.
    *   Rekey traffic keys use labels `foctet rekey c2s || key_id` and `foctet rekey s2c || key_id`.
    *   `key_c2s` and `key_s2c` MUST be derived independently and MUST NOT share output buffers.
*   **AEAD usage**
    *   Cipher is XChaCha20-Poly1305 with 24-byte nonce and 16-byte authentication tag.
    *   AAD MUST be the full plaintext frame header bytes (`magic..ct_len`) exactly as transmitted.
    *   Decryption MUST fail closed on any AEAD authentication error.
*   **Nonce/key domain separation**
    *   Nonce construction MUST follow section 7.1.1 exactly.
    *   For any fixed traffic key, nonce reuse is forbidden.
    *   Implementations MUST rotate key material before any tuple reuse could occur.
*   **Replay-domain consistency**
    *   Replay tracking domain is `(direction, key_id, stream_id, seq)`.
    *   Receivers MUST reject duplicates and frames outside the configured replay window.

* * *

8\. Handshake (Session Establishment)
-------------------------------------

### 8.1 Session Modes

Foctet supports two modes:

1.  **Native Foctet Handshake** (over any transport)
2.  **Bound Mode** (derive traffic keys from an existing secure channel, e.g., TLS exporter)

Draft v0 defines **Native**.

### 8.2 Native Handshake Outline (draft)

*   Each side generates ephemeral X25519 key pair.
*   Exchange ephemeral public keys in control frames.
*   Derive shared secret `ss = X25519(eph_priv, peer_eph_pub)`.
*   Derive traffic keys:
    *   `prk = HKDF-Extract(salt=session_salt, IKM=ss)`
    *   `key_c2s = HKDF-Expand(prk, info="foctet c2s", L=keylen)`
    *   `key_s2c = HKDF-Expand(prk, info="foctet s2c", L=keylen)`
*   Optional: bind to static identity keys (Ed25519) by signing transcript.

### 8.3 Authentication (Recommended)

To prevent MITM:

*   Each endpoint SHOULD have a long-term identity key and present a signature over the transcript.
*   If identity is out-of-band (pre-shared public keys), verification is mandatory.
*   If using a directory / PKI, trust model is defined at higher layer.

* * *

9\. Relay Model
---------------

### 9.1 Relay Properties

*   Relay MUST be able to forward frames without decryption.
*   Relay MUST NOT require access to session keys.
*   Relay MAY add an **outer envelope** for routing (not part of Foctet Core).

### 9.2 Outer Envelope (Non-normative, recommended)

To support routing while minimizing metadata:

*   Outer header contains:
    *   destination relay hop id / next hop token
    *   optional connection id
*   Inner Foctet frame remains unchanged and opaque.

Relays MUST NOT alter Foctet frame bytes.

* * *

10\. File Transfer Over Foctet (Streaming)
------------------------------------------

### 10.1 Chunking

*   Large payloads (files) MUST be chunked into fixed-size chunks (e.g., 256 KiB - 4 MiB).
*   Each chunk is carried in one or more frames.
*   Chunk metadata (file id, chunk index, total chunks) MUST be encrypted (inside ciphertext), not in plaintext header.

### 10.2 Reassembly

*   Receiver reassembles chunks based on encrypted metadata.
*   Receiver MUST validate per-chunk integrity via AEAD (already ensured) and optionally an overall file hash (encrypted metadata).

### 10.3 Backpressure & Flow Control

Core has no flow control. Implementations SHOULD:

*   bound in-memory reassembly buffers
*   stream chunks to disk (optional) or to a sink
*   use transport-specific flow control where available (QUIC streams)

* * *

11\. Foctet Secure Archive (Storage Format)
-------------------------------------------

### 11.1 Design Goals

*   Store encrypted content for offline transfer.
*   Support splitting into multiple files.
*   Only authorized recipients can decrypt and reassemble.
*   Storage provider learns minimal metadata.

### 11.2 Container Structure (Single-file)

Plaintext header (minimal):

| Field | Size | Description |
| --- | --- | --- |
| magic | 8 | `"FOCTETAR"` |
| version | 1 | archive version |
| profile\_id | 1 | crypto profile |
| header\_len | 4 | length of encrypted header blob |
| header\_ct | var | encrypted header blob |

Then sequence of encrypted chunks:

| Field | Size | Description |
| --- | --- | --- |
| chunk\_len | 4 | ciphertext length |
| chunk\_ct | var | encrypted chunk record |

Everything beyond the minimal header is encrypted.

### 11.3 Encrypted Header Blob (inside `header_ct`)

Contains:

*   archive\_id (random 128-bit)
*   created\_at (optional)
*   content\_type (optional)
*   file manifest:
    *   file\_id
    *   file\_name (optional)
    *   file\_size
    *   chunk\_size
    *   total\_chunks
    *   overall\_hash (e.g., BLAKE3)
*   recipients list (encrypted **and** individually wrapped keys, see 11.4)
*   optional padding policy

### 11.4 Recipient Authorization (Key Wrapping)

Archive uses a **Data Encryption Key (DEK)**:

*   DEK encrypts header blob and all chunks.
*   For each recipient, DEK is wrapped using recipient's public key:
    *   e.g., X25519-based sealed box / HPKE-like encapsulation (profile-defined)

Only recipients with matching private keys can unwrap DEK and decrypt.

### 11.5 Multi-file Split

Archive MAY be split into:

*   `manifest.far` (contains header\_ct and recipient-wrapped keys)
*   `data.partNNN.far` files containing chunk records

Reassembly rules:

*   manifest provides `archive_id`, `total_parts`, chunk index mapping.
*   parts are order-independent.

### 11.6 Integrity & Tamper Detection

*   Each chunk record MUST include an internal encrypted structure:
    *   chunk\_index
    *   chunk\_plain\_len
    *   chunk\_hash (optional)
    *   payload bytes
*   AEAD authenticates the structure; tampering is detected at decrypt time.
*   Overall file hash in encrypted header allows end-to-end verification after reassembly.

* * *

12\. Security Considerations
----------------------------

### 12.1 Metadata Leakage

Plaintext leakage in v0:

*   Foctet Core: `stream_id`, `seq`, `ct_len`, `key_id`, `profile_id` (and possibly magic/version)
*   Archive: magic/version/profile\_id and encrypted header length

Mitigations:

*   padding (`PADDING` flag) to normalize sizes
*   fixed-size chunks
*   optional cover traffic at higher layer

### 12.2 Replay & Reordering

*   Receivers MUST enforce replay windows.
*   Reordering is permitted within window; higher layers can impose strict ordering.

### 12.3 Key Management

*   Long-term identity keys MUST be protected by OS keystore when possible.
*   Session keys MUST be kept in memory only and zeroized on teardown.
*   Rekey MUST occur per thresholds to reduce blast radius.

Operational guidance:

*   Rekey trigger SHOULD use earliest-of:
    *   `2^20` outbound frames, OR
    *   `1 GiB` outbound plaintext, OR
    *   `10 minutes` elapsed
*   Replay window SHOULD default to `4096` and MAY be increased for high-reordering networks.
*   Implementations SHOULD persist or monotonic-track sender sequence state when process restarts are possible.

### 12.4 Side-channel & Implementation Safety

*   Constant-time crypto primitives.
*   Bounds checks for all lengths.
*   Reject unknown versions/profiles unless explicitly negotiated.
*   Avoid unbounded allocations based on attacker-controlled lengths.

* * *

13\. Performance Considerations
-------------------------------

*   Prefer streaming encrypt/decrypt with bounded buffers.
*   Chunk sizes SHOULD be tuned:
    *   small chunks: better latency, more overhead
    *   large chunks: better throughput, larger memory spikes
*   Implementations SHOULD support:
    *   parallel chunk encryption for archive creation
    *   pipelined frame sending
    *   zero-copy parsing where feasible

* * *

14\. Extensibility
------------------

### 14.1 Versioning

*   `version` changes indicate wire-incompatible changes.
*   `profile_id` changes indicate cryptographic suite changes.
*   Draft v0 reserves plaintext header bits for future extension and requires unknown bits to be zero.
*   Minor additions SHOULD be introduced via:
    *   new profile IDs
    *   encrypted payload TLVs inside ciphertext
    *   optional outer-envelope metadata (out-of-core)

Compatibility policy targets:

*   Draft v0 (`0.x` line): breaking changes are allowed, but MUST update spec and vectors together.
*   v1+: wire compatibility MUST be preserved within major version, and incompatibilities MUST use a new wire `version`.

### 14.2 Encrypted Payload TLV (Recommended)

Inside ciphertext, define a simple TLV:

*   type (varint)
*   length (varint)
*   value

This allows future features (ack hints, compression hints, file metadata) without changing plaintext header.

### 14.3 Unknown-Type Handling Policy

Draft v0 behavior:

*   Unknown plaintext header flag bits: MUST reject.
*   Unknown control message kinds: MUST reject.
*   Unknown TLV types inside ciphertext: MAY be ignored only when the application profile explicitly allows it.

v1 target behavior:

*   Unknown critical extensions MUST fail closed.
*   Unknown non-critical extensions SHOULD be safely ignored.
*   Criticality signaling SHOULD be explicit (for example, a flag bit or type range convention).

### 14.4 Extension Guidelines

Future extension designs SHOULD:

*   avoid adding unauthenticated plaintext fields
*   preserve replay-domain semantics
*   define deterministic parse-failure behavior
*   include test vectors before enabling by default

* * *

15\. Test Vectors, Validation, and Error Conditions
---------------------------------------------------

### 15.1 Draft v0 vectors

The repository includes deterministic vectors under `test-vectors/`:

*   `frame-v0.json`
*   `handshake-v0.json`
*   `archive-v0.json`

Implementations SHOULD validate these vectors as part of CI.

### 15.2 Vector validation expectations

Implementations SHOULD validate both:

*   value-level behavior (decrypt/derive outputs match expected values), and
*   schema-level behavior (required fields exist and have valid hex encoding/lengths).

### 15.3 Mandatory parse/decrypt rejection cases

Core implementations MUST reject at least the following:

*   invalid frame header length
*   invalid magic/version/profile
*   unknown or reserved plaintext header flag bits in Draft v0
*   ciphertext length mismatch (`ct_len` mismatch)
*   AEAD authentication failure
*   replayed frames and frames outside replay window
*   malformed TLV/control payloads

Archive implementations MUST reject at least the following:

*   invalid magic/version/profile
*   malformed/truncated container bytes
*   missing recipient wrapper
*   hash mismatch on plaintext/chunks/parts
*   missing or duplicated split-part indices
*   AEAD authentication failure

* * *

16\. Open Questions (Draft v0)
------------------------------

1.  **Handshake authentication**: should static identity authentication become mandatory in v1?
2.  **Nonce format**: should v1 introduce stricter domain separation and explicit endianness requirements?
3.  **Varint adoption**: should v1 replace fixed-width integer fields where appropriate?
4.  **Relay envelope**: should relay envelope metadata remain out-of-scope or be standardized?
5.  **Padding defaults**: should v1 define a mandatory default padding strategy?

* * *

Appendix A: Recommended Defaults (Draft)
========================================

*   chunk\_size: 1 MiB
*   replay\_window: 4096
*   rekey\_threshold:
    *   2^20 frames OR 1 GiB OR 10 minutes (whichever comes first)
*   profile: 0x01
*   replay acceptance mode: strict (duplicates and out-of-window frames rejected)
*   control message handling: fail closed on unknown kind

* * *

Appendix B: Minimal State Machines (Sketch)
===========================================

Sender (per stream\_id)
-----------------------

*   INIT -> (handshake complete) -> ACTIVE
*   ACTIVE: seq++, encrypt, send
*   ACTIVE -> REKEY -> ACTIVE
*   ACTIVE -> CLOSED

Receiver (per stream\_id)
-------------------------

*   INIT -> ACTIVE
*   ACTIVE: verify AAD/tag, replay check, deliver
*   ACTIVE -> REKEY -> ACTIVE
*   ACTIVE -> CLOSED
