//! Low-level transport adapters.

#[cfg(any(feature = "runtime-futures", feature = "runtime-tokio"))]
use core::pin::Pin;
#[cfg(any(feature = "runtime-futures", feature = "runtime-tokio"))]
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
    ) -> Poll<std::io::Result<()>> {
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
    ) -> Poll<std::io::Result<usize>> {
        self.project().send.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().send.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
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
    ) -> Poll<std::io::Result<usize>> {
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
    ) -> Poll<std::io::Result<usize>> {
        self.project().send.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().send.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().send.poll_close(cx)
    }
}

#[cfg(feature = "transport-muxtls")]
pub mod muxtls {
    use super::SplitIo;

    /// Wraps split muxtls receive/send halves as a single I/O object.
    pub fn from_split<R, W>(recv: R, send: W) -> SplitIo<R, W> {
        SplitIo::from_split(recv, send)
    }
}

#[cfg(feature = "transport-webtrans")]
pub mod webtrans {
    use super::SplitIo;

    /// Wraps split WebTransport receive/send halves as a single I/O object.
    pub fn from_split<R, W>(recv: R, send: W) -> SplitIo<R, W> {
        SplitIo::from_split(recv, send)
    }
}

#[cfg(feature = "transport-websock")]
pub mod websock {
    use super::SplitIo;

    /// Wraps split WebSocket transport halves as a single I/O object.
    pub fn from_split<R, W>(recv: R, send: W) -> SplitIo<R, W> {
        SplitIo::from_split(recv, send)
    }
}

#[cfg(feature = "transport-quinn")]
pub mod quinn {
    use super::SplitIo;

    /// Wraps split Quinn receive/send halves as a single I/O object.
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

        recv_peer.write_all(b"hello").await.expect("write recv");

        let mut buf = [0u8; 5];
        io.read_exact(&mut buf).await.expect("read exact");
        assert_eq!(&buf, b"hello");

        io.write_all(b"world").await.expect("write all");
        io.flush().await.expect("flush");

        let mut out = [0u8; 5];
        send_peer.read_exact(&mut out).await.expect("read peer");
        assert_eq!(&out, b"world");
    }
}
