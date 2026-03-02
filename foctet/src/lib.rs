//! Top-level public API for the Foctet workspace.
//!
//! This crate re-exports:
//!
//! - `core` for framing, key schedule, handshake/rekey, and replay protection.
//! - `archive` for encrypted single-file and split archive containers.
//! - `transport` for optional split-stream adapters when the `transport` feature is enabled.
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
//! For wire-format details, see `SPEC.md` in the workspace root.

pub use foctet_archive as archive;
pub use foctet_core as core;
#[cfg(feature = "transport")]
pub use foctet_transport as transport;
