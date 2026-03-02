//! Thin adapters for combining transport streams into a single I/O object.
//!
//! Many transport crates expose receive/send stream halves.
//! `foctet-transport` merges these halves into a single `SplitIo<R, W>` so Foctet
//! can use one object implementing both read and write traits.
//!
//! This crate contains no transport-specific protocol logic.
//!
//! # Feature Flags
//!
//! - `runtime-tokio`: implements Tokio `AsyncRead`/`AsyncWrite` for [`SplitIo`].
//! - `runtime-futures`: implements `futures-io` `AsyncRead`/`AsyncWrite` for [`SplitIo`].
//! - `transport-muxtls`, `transport-webtrans`, `transport-websock`, `transport-quinn`:
//!   expose `from_split(recv, send)` helpers.
//!
//! # Non-goals
//!
//! - TLS or certificate policy
//! - transport negotiation/state machines
//! - buffering or framing
//!
//! # Minimal Example
//!
//! ```rust
//! use foctet_transport::SplitIo;
//!
//! let io = SplitIo::from_split("recv-half", "send-half");
//! let (_recv, _send) = io.into_inner();
//! ```

#![forbid(unsafe_code)]

#[cfg(any(feature = "runtime-tokio", feature = "runtime-futures"))]
use core::pin::Pin;
#[cfg(any(feature = "runtime-tokio", feature = "runtime-futures"))]
use core::task::{Context, Poll};
use pin_project_lite::pin_project;

pin_project! {
    /// Combines independent receive and send halves into one I/O object.
    #[derive(Debug)]
    pub struct SplitIo<R, W> {
        #[pin]
        recv: R,
        #[pin]
        send: W,
    }
}

impl<R, W> SplitIo<R, W> {
    /// Creates a `SplitIo` from split receive and send halves.
    pub fn from_split(recv: R, send: W) -> Self {
        Self { recv, send }
    }

    /// Returns a shared reference to the receive half.
    pub fn recv(&self) -> &R {
        &self.recv
    }

    /// Returns a shared reference to the send half.
    pub fn send(&self) -> &W {
        &self.send
    }

    /// Decomposes this value into its receive and send halves.
    pub fn into_inner(self) -> (R, W) {
        (self.recv, self.send)
    }
}

#[cfg(feature = "runtime-tokio")]
impl<R, W> tokio::io::AsyncRead for SplitIo<R, W>
where
    R: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<core::result::Result<(), std::io::Error>> {
        self.project().recv.poll_read(cx, buf)
    }
}

#[cfg(feature = "runtime-tokio")]
impl<R, W> tokio::io::AsyncWrite for SplitIo<R, W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, std::io::Error>> {
        self.project().send.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<core::result::Result<(), std::io::Error>> {
        self.project().send.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<core::result::Result<(), std::io::Error>> {
        self.project().send.poll_shutdown(cx)
    }
}

#[cfg(feature = "runtime-futures")]
impl<R, W> futures_io::AsyncRead for SplitIo<R, W>
where
    R: futures_io::AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<core::result::Result<usize, std::io::Error>> {
        self.project().recv.poll_read(cx, buf)
    }
}

#[cfg(feature = "runtime-futures")]
impl<R, W> futures_io::AsyncWrite for SplitIo<R, W>
where
    W: futures_io::AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<core::result::Result<usize, std::io::Error>> {
        self.project().send.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<core::result::Result<(), std::io::Error>> {
        self.project().send.poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<core::result::Result<(), std::io::Error>> {
        self.project().send.poll_close(cx)
    }
}

#[cfg(feature = "transport-muxtls")]
pub mod muxtls {
    use crate::SplitIo;

    /// Wraps split muxtls receive/send halves as a single I/O object.
    pub fn from_split<R, W>(recv: R, send: W) -> SplitIo<R, W> {
        SplitIo::from_split(recv, send)
    }
}

#[cfg(feature = "transport-webtrans")]
pub mod webtrans {
    use crate::SplitIo;

    /// Wraps split webtrans receive/send halves as a single I/O object.
    pub fn from_split<R, W>(recv: R, send: W) -> SplitIo<R, W> {
        SplitIo::from_split(recv, send)
    }
}

#[cfg(feature = "transport-websock")]
pub mod websock {
    use crate::SplitIo;

    /// Wraps split websock receive/send halves as a single I/O object.
    pub fn from_split<R, W>(recv: R, send: W) -> SplitIo<R, W> {
        SplitIo::from_split(recv, send)
    }
}

#[cfg(feature = "transport-quinn")]
pub mod quinn {
    use crate::SplitIo;

    /// Wraps split quinn receive/send halves as a single I/O object.
    pub fn from_split<R, W>(recv: R, send: W) -> SplitIo<R, W> {
        SplitIo::from_split(recv, send)
    }
}

#[cfg(all(test, feature = "runtime-tokio"))]
mod tests {
    use super::SplitIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn split_io_reads_and_writes() {
        let (recv_side, mut recv_peer) = tokio::io::duplex(64);
        let (mut send_peer, send_side) = tokio::io::duplex(64);

        let mut io = SplitIo::from_split(recv_side, send_side);

        recv_peer.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 5];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        io.write_all(b"world").await.unwrap();
        io.flush().await.unwrap();

        let mut out = [0u8; 5];
        send_peer.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"world");
    }
}
