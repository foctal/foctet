//! Top-level public API for the Foctet workspace.
//!
//! This crate re-exports:
//!
//! - `core` for framing, handshake/rekey, and replay protection
//! - `archive` for encrypted single-file and split archives
//! - `transport` for optional authenticated channel builders over stream
//!   transports
//!
//! Use `foctet::transport` for the easiest transport E2EE path, `foctet::core`
//! for low-level protocol control, and `foctet::archive` for encrypted file
//! packaging.

pub use foctet_archive as archive;
pub use foctet_core as core;
#[cfg(feature = "transport")]
pub use foctet_transport as transport;
