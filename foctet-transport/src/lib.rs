#![cfg_attr(docsrs, feature(doc_cfg))]
//! High-level Foctet integration helpers for stream-oriented transports.
//!
//! `foctet-transport` is the recommended entry point when you want Foctet to
//! run over an existing stream abstraction. The builders in this crate perform
//! the native handshake, wire up framing, and expose authenticated secure
//! channels with minimal boilerplate.
//!
//! Start with `TokioTransportBuilder` or `FuturesTransportBuilder` when you
//! already have split I/O halves. Use transport-specific modules such as
//! `quinn`, `webtrans`, `websock`, or `muxtls` when you want convenience
//! wrappers around those transports.
//!
//! For production use, prefer `establish_production_*` methods together with
//! `foctet_core::ProductionSessionAuth`.
//!
//! # Quick Start
//!
//! ```rust
//! #[cfg(feature = "runtime-tokio")]
//! async fn quick_start() -> Result<(), foctet_core::CoreError> {
//!     use foctet_core::{ChannelBinding, ProductionSessionAuth, RekeyThresholds};
//!     use foctet_transport::TokioTransportBuilder;
//!
//!     let (client_io, server_io) = tokio::io::duplex(64 * 1024);
//!     let binding = ChannelBinding::new(b"authenticated outer channel exporter")?;
//!     let client_auth = ProductionSessionAuth::authenticated_channel(binding.clone());
//!     let server_auth = ProductionSessionAuth::authenticated_channel(binding);
//!
//!     let (client, server) = tokio::join!(
//!         TokioTransportBuilder::new().establish_production_initiator(
//!             client_io, RekeyThresholds::default(), client_auth),
//!         TokioTransportBuilder::new().establish_production_responder(
//!             server_io, RekeyThresholds::default(), server_auth),
//!     );
//!     assert!(client.is_ok() && server.is_ok());
//!     Ok(())
//! }
//! ```
//!
//! Transport-specific helpers follow the same authentication model; the main
//! difference is whether this crate opens the underlying stream for you.

#![forbid(unsafe_code)]

pub mod adapter;
mod config;
pub mod datagram;
mod error;
#[cfg(feature = "runtime-futures")]
mod futures;
pub mod message;
#[cfg(not(target_arch = "wasm32"))]
pub mod rate_limit;
pub mod shape;
#[cfg(feature = "runtime-tokio")]
mod tokio;

#[cfg(feature = "transport-muxtls")]
pub mod muxtls;
#[cfg(feature = "transport-quinn")]
pub mod quinn;
#[cfg(feature = "runtime-tokio")]
pub mod udp;
#[cfg(feature = "transport-websock")]
pub mod websock;
#[cfg(feature = "transport-webtrans")]
pub mod webtrans;
#[cfg(all(target_arch = "wasm32", feature = "transport-webtrans-browser"))]
pub mod webtrans_browser;

pub use adapter::SplitIo;
pub use config::TransportConfig;
pub use datagram::{DatagramChannelError, DatagramTransport, SecureDatagramChannel};
pub use error::{TransportChannelError, TransportErrorDisposition};
#[cfg(feature = "runtime-futures")]
pub use futures::{FuturesTransportBuilder, FuturesTransportChannel};
pub use message::{MessageChannelError, MessageTransport, SecureMessageChannel};
#[cfg(not(target_arch = "wasm32"))]
pub use rate_limit::{
    HandshakeConcurrencyLimiter, HandshakePermit, HandshakeRateLimiter, MAX_CONCURRENT_HANDSHAKES,
};
#[cfg(feature = "runtime-futures")]
pub use shape::ByteStreamTransport;
pub use shape::SecureChannel;
#[cfg(feature = "runtime-tokio")]
pub use tokio::{DEFAULT_HANDSHAKE_TIMEOUT, TokioTransportBuilder, TokioTransportChannel};
#[cfg(all(target_arch = "wasm32", feature = "transport-webtrans-browser"))]
pub use webtrans_browser::{BrowserWebTransportDatagrams, BrowserWebTransportError};
