//! Top-level public API for the Foctet workspace.
//!
//! This crate re-exports:
//!
//! - `core` for framing, key schedule, handshake/rekey, and replay protection.
//! - `archive` for encrypted single-file and split archive containers.
//! - `transport` for optional split-stream adapters when the `transport`
//!   feature is enabled.
//!
//! # Quick Start
//!
//! ```rust
//! use foctet::{archive, core};
//!
//! let _wire = core::WIRE_VERSION_V0;
//! let _chunk_size = archive::DEFAULT_CHUNK_SIZE;
//! ```
//!
//! # Which Crate To Reach For
//!
//! - Use `foctet::transport` when you want the easiest authenticated E2EE path
//!   over split stream transports such as QUIC, WebTransport, or multiplexed
//!   WebSocket streams.
//! - Use `foctet::core` when you need direct control over handshake messages,
//!   framing, rekey policy, or the `application/foctet` body envelope.
//! - Use `foctet::archive` for encrypted files, manifests, and deterministic
//!   interoperability fixtures.
//!
//! # Production Guidance
//!
//! - Prefer authenticated native handshakes with pinned peer identities.
//! - Pair `foctet::core::body` or `foctet-http` usage with an authenticated
//!   outer HTTP transport because body envelopes protect body bytes only.
//! - Reserve deterministic archive build secrets for test fixtures and vectors,
//!   not for live user data.
//!
//! For wire-format details, see `SPEC.md` in the workspace root.

pub use foctet_archive as archive;
pub use foctet_core as core;
#[cfg(feature = "transport")]
pub use foctet_transport as transport;
