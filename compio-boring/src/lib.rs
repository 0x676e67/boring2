//! Async TLS streams backed by BoringSSL
//!
//! This library is an implementation of TLS streams using BoringSSL for
//! negotiating the connection. Each TLS stream implements the `Read` and
//! `Write` traits to interact and interoperate with the rest of the futures I/O
//! ecosystem. Client connections initiated from this crate verify hostnames
//! automatically and by default.
//!
//! `tokio-boring` exports this ability through [`accept`] and [`connect`]. `accept` should
//! be used by servers, and `connect` by clients. These augment the functionality provided by the
//! [`boring`] crate, on which this crate is built. Configuration of TLS parameters is still
//! primarily done through the [`boring`] crate.
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod async_callbacks;

use boring::ssl::{self, ConnectConfiguration, ErrorCode, SslAcceptor, SslRef};
use boring_sys as ffi;
use compio::buf::{IoBuf, IoBufMut};
use compio::io::{AsyncRead, AsyncWrite};
use compio::BufResult;
use compio_io::compat::SyncStream;
use std::error::Error;
use std::fmt;
use std::io;
use std::mem::MaybeUninit;

pub use crate::async_callbacks::SslContextBuilderExt;
pub use boring::ssl::{
    AsyncPrivateKeyMethod, AsyncPrivateKeyMethodError, AsyncSelectCertError, BoxGetSessionFinish,
    BoxGetSessionFuture, BoxPrivateKeyMethodFinish, BoxPrivateKeyMethodFuture, BoxSelectCertFinish,
    BoxSelectCertFuture, ExDataFuture,
};

/// Asynchronously performs a client-side TLS handshake over the provided stream.
///
/// This function automatically sets the task waker on the `Ssl` from `config` to
/// allow to make use of async callbacks provided by the boring crate.
pub async fn connect<S>(
    config: ConnectConfiguration,
    domain: &str,
    stream: S,
) -> Result<SslStream<S>, HandshakeError<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let res = config.connect(domain, SyncStream::new(stream));
    perform_tls_handshake(res).await
}

/// Asynchronously performs a server-side TLS handshake over the provided stream.
///
/// This function automatically sets the task waker on the `Ssl` from `config` to
/// allow to make use of async callbacks provided by the boring crate.
pub async fn accept<S>(acceptor: &SslAcceptor, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let res = acceptor.accept(SyncStream::new(stream));
    perform_tls_handshake(res).await
}

/// A partially constructed `SslStream`, useful for unusual handshakes.
pub struct SslStreamBuilder<S> {
    inner: ssl::SslStreamBuilder<SyncStream<S>>,
}

impl<S> SslStreamBuilder<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Begins creating an `SslStream` atop `stream`.
    pub fn new(ssl: ssl::Ssl, stream: S) -> Self {
        Self {
            inner: ssl::SslStreamBuilder::new(ssl, SyncStream::new(stream)),
        }
    }

    /// Initiates a client-side TLS handshake.
    pub async fn accept(self) -> Result<SslStream<S>, HandshakeError<S>> {
        let res = self.inner.connect();
        perform_tls_handshake(res).await
    }

    /// Initiates a server-side TLS handshake.
    pub async fn connect(self) -> Result<SslStream<S>, HandshakeError<S>> {
        let res = self.inner.connect();
        perform_tls_handshake(res).await
    }
}

impl<S> SslStreamBuilder<S> {
    /// Returns a shared reference to the `Ssl` object associated with this builder.
    #[must_use]
    pub fn ssl(&self) -> &SslRef {
        self.inner.ssl()
    }

    /// Returns a mutable reference to the `Ssl` object associated with this builder.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.inner.ssl_mut()
    }
}

/// A wrapper around an underlying raw stream which implements the SSL
/// protocol.
///
/// A `SslStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `SslStream` are decrypted from `S` and bytes written
/// to a `SslStream` are encrypted when passing through to `S`.
#[derive(Debug)]
pub struct SslStream<S>(ssl::SslStream<SyncStream<S>>);

impl<S> SslStream<S> {
    /// Returns a shared reference to the `Ssl` object associated with this stream.
    #[must_use]
    pub fn ssl(&self) -> &SslRef {
        self.0.ssl()
    }

    /// Returns a mutable reference to the `Ssl` object associated with this stream.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.0.ssl_mut()
    }

    /// Returns a shared reference to the underlying stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        self.0.get_ref().get_ref()
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut().get_mut()
    }
}

impl<S> SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Constructs an `SslStream` from a pointer to the underlying OpenSSL `SSL` struct.
    ///
    /// This is useful if the handshake has already been completed elsewhere.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is valid.
    pub unsafe fn from_raw_parts(ssl: *mut ffi::SSL, stream: S) -> Self {
        Self(ssl::SslStream::from_raw_parts(ssl, SyncStream::new(stream)))
    }
}

impl<S: AsyncRead> AsyncRead for SslStream<S> {
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        let slice = buf.as_mut_slice();

        let mut f = {
            slice.fill(MaybeUninit::new(0));
            // SAFETY: The memory has been initialized
            let slice =
                unsafe { std::slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), slice.len()) };
            |s: &mut _| std::io::Read::read(s, slice)
        };

        loop {
            match f(&mut self.0) {
                Ok(res) => {
                    unsafe { buf.set_buf_init(res) };
                    return BufResult(Ok(res), buf);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match self.0.get_mut().fill_read_buf().await {
                        Ok(_) => continue,
                        Err(e) => return BufResult(Err(e), buf),
                    }
                }
                res => return BufResult(res, buf),
            }
        }
    }

    // OpenSSL does not support vectored reads
}

/// `AsyncRead` is needed for shutting down stream.
impl<S: AsyncWrite + AsyncRead> AsyncWrite for SslStream<S> {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let slice = buf.as_slice();
        loop {
            let res = io::Write::write(&mut self.0, slice);
            match res {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => match self.flush().await {
                    Ok(_) => continue,
                    Err(e) => return BufResult(Err(e), buf),
                },
                _ => return BufResult(res, buf),
            }
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        loop {
            match io::Write::flush(&mut self.0) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.0.get_mut().flush_write_buf().await?;
                }
                Err(e) => return Err(e),
            }
        }
        self.0.get_mut().flush_write_buf().await?;
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.flush().await?;
        self.0.get_mut().get_mut().shutdown().await
    }
}

/// The error type returned after a failed handshake.
pub enum HandshakeError<S> {
    /// An error that occurred during the handshake.
    Inner(ssl::HandshakeError<SyncStream<S>>),
    /// An I/O error that occurred during the handshake.
    Io(io::Error),
}

impl<S> HandshakeError<S> {
    /// Returns a shared reference to the `Ssl` object associated with this error.
    #[must_use]
    pub fn ssl(&self) -> Option<&SslRef> {
        match self {
            HandshakeError::Inner(ssl::HandshakeError::Failure(s)) => Some(s.ssl()),
            _ => None,
        }
    }

    /// Returns the error code, if any.
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            HandshakeError::Inner(ssl::HandshakeError::Failure(s)) => Some(s.error().code()),
            _ => None,
        }
    }

    /// Returns a reference to the inner I/O error, if any.
    #[must_use]
    pub fn as_io_error(&self) -> Option<&io::Error> {
        match self {
            HandshakeError::Inner(ssl::HandshakeError::Failure(s)) => s.error().io_error(),
            HandshakeError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl<S> fmt::Debug for HandshakeError<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::Inner(e) => fmt::Debug::fmt(e, fmt),
            HandshakeError::Io(e) => fmt::Debug::fmt(e, fmt),
        }
    }
}

impl<S> fmt::Display for HandshakeError<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::Inner(e) => fmt::Display::fmt(e, fmt),
            HandshakeError::Io(e) => fmt::Display::fmt(e, fmt),
        }
    }
}

impl<S> Error for HandshakeError<S>
where
    S: fmt::Debug,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HandshakeError::Inner(e) => e.source(),
            HandshakeError::Io(e) => Some(e),
        }
    }
}

async fn perform_tls_handshake<S: AsyncRead + AsyncWrite>(
    mut res: Result<ssl::SslStream<SyncStream<S>>, ssl::HandshakeError<SyncStream<S>>>,
) -> Result<SslStream<S>, HandshakeError<S>> {
    loop {
        match res {
            Ok(mut s) => {
                s.get_mut()
                    .flush_write_buf()
                    .await
                    .map_err(HandshakeError::Io)?;
                return Ok(SslStream(s));
            }
            Err(e) => match e {
                ssl::HandshakeError::Failure(_) => return Err(HandshakeError::Inner(e)),
                ssl::HandshakeError::SetupFailure(_) => {
                    return Err(HandshakeError::Inner(e));
                }
                ssl::HandshakeError::WouldBlock(mut mid_stream) => {
                    if mid_stream
                        .get_mut()
                        .flush_write_buf()
                        .await
                        .map_err(HandshakeError::Io)?
                        == 0
                    {
                        mid_stream
                            .get_mut()
                            .fill_read_buf()
                            .await
                            .map_err(HandshakeError::Io)?;
                    }
                    res = mid_stream.handshake();
                }
            },
        }
    }
}
