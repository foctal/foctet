//! High-level Foctet integration helpers for stream-oriented transports.
//!
//! # Layers
//!
//! - Recommended high-level API:
//!   [`TransportConfig`], [`TokioTransportBuilder`], [`FuturesTransportBuilder`],
//!   [`TokioTransportChannel`], and [`FuturesTransportChannel`]
//! - Transport-specific helpers:
//!   feature-gated modules such as [`muxtls`] and [`quinn`]
//! - Low-level escape hatch:
//!   [`adapter`] and [`SplitIo`]
//!

#![forbid(unsafe_code)]

pub mod adapter;
mod config;
mod error;
#[cfg(feature = "runtime-futures")]
mod futures;
#[cfg(feature = "runtime-tokio")]
mod tokio;

#[cfg(feature = "transport-muxtls")]
pub mod muxtls;
#[cfg(feature = "transport-quinn")]
pub mod quinn;
#[cfg(feature = "transport-websock")]
pub mod websock;
#[cfg(feature = "transport-webtrans")]
pub mod webtrans;

pub use adapter::SplitIo;
pub use config::TransportConfig;
pub use error::TransportChannelError;
#[cfg(feature = "runtime-futures")]
pub use futures::{FuturesTransportBuilder, FuturesTransportChannel};
#[cfg(feature = "runtime-tokio")]
pub use tokio::{TokioTransportBuilder, TokioTransportChannel};
