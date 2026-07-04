//! High-level Foctet integration helpers for stream-oriented transports.
//!
//! `foctet-transport` is the recommended entry point when you want Foctet to
//! run over an existing stream abstraction. The builders in this crate perform
//! the native Foctet handshake, wire up framing, and expose a secure channel
//! with minimal boilerplate.
//!
//! # Layers
//!
//! - Recommended high-level API:
//!   [`TransportConfig`], `TokioTransportBuilder`, `FuturesTransportBuilder`,
//!   `TokioTransportChannel`, and `FuturesTransportChannel`
//! - Transport-specific helpers:
//!   feature-gated modules such as `muxtls` and `quinn`
//! - Low-level escape hatch:
//!   [`adapter`] and [`SplitIo`]
//!
//! # Recommended Production Path
//!
//! - Use `*_with_auth` builder methods together with
//!   `foctet_core::SessionAuthConfig`.
//! - Pin the expected remote identity with `foctet_core::PeerIdentity`.
//! - Require authenticated peers unless the outer transport already provides
//!   strong peer authentication that your application trusts.
//!
//! # Choosing an Integration Style
//!
//! - Use `TokioTransportBuilder` or `FuturesTransportBuilder` when you
//!   already have split I/O halves and want runtime-generic Foctet channels.
//! - Use transport-specific modules such as `quinn`, `webtrans`,
//!   `websock`, or `muxtls` when you want convenience wrappers that open or
//!   accept streams and immediately wrap them as Foctet channels.
//! - Use [`adapter`] and [`SplitIo`] only when you need a custom integration
//!   path that the high-level builders do not cover.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use foctet_core::{IdentityKeyPair, PeerIdentity, RekeyThresholds, SessionAuthConfig};
//! use foctet_transport::TokioTransportBuilder;
//!
//! let auth = SessionAuthConfig::new()
//!     .with_local_identity(IdentityKeyPair::generate())
//!     .with_peer_identity(PeerIdentity::new(peer_identity_public_key))
//!     .require_peer_authentication(true);
//!
//! let builder = TokioTransportBuilder::new();
//! let channel = builder
//!     .establish_initiator_with_auth(stream, RekeyThresholds::default(), auth)
//!     .await?;
//! # let _ = channel;
//! # Ok::<(), Box<dyn std::error::Error>>(())
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
pub use error::TransportChannelError;
#[cfg(feature = "runtime-futures")]
pub use futures::{FuturesTransportBuilder, FuturesTransportChannel};
pub use message::{MessageChannelError, MessageTransport, SecureMessageChannel};
#[cfg(not(target_arch = "wasm32"))]
pub use rate_limit::HandshakeRateLimiter;
#[cfg(feature = "runtime-futures")]
pub use shape::ByteStreamTransport;
pub use shape::SecureChannel;
#[cfg(feature = "runtime-tokio")]
pub use tokio::{DEFAULT_HANDSHAKE_TIMEOUT, TokioTransportBuilder, TokioTransportChannel};
#[cfg(all(target_arch = "wasm32", feature = "transport-webtrans-browser"))]
pub use webtrans_browser::{BrowserWebTransportDatagrams, BrowserWebTransportError};
