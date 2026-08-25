//! The one RTSP connection a RAOP session owns, shared with its background tasks.
//!
//! `RaopPlaybackManager` holds an `HttpConnection` and an `RtspSession` and hands both to the
//! `StreamClient`, the `StreamProtocol` and the feedback task (`raop/__init__.py:143-157`). Python
//! gets away with sharing them freely because a single-threaded event loop interleaves at `await`
//! points only; here they sit behind one `tokio::sync::Mutex`, for the same reason
//! [`crate::ap2::session::Ap2Session`] does it — the connection answers strictly one request at a
//! time, and the keepalive task must not interleave with a verb the streaming loop is sending.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::Result;
use crate::http::HttpConnection;
use crate::rtsp::RtspSession;

/// An RTSP connection and the session state riding on it.
#[derive(Debug)]
pub struct RaopConnection {
    /// The TCP connection to the receiver's RAOP port.
    pub http: HttpConnection,
    /// The RTSP session: `CSeq`, the DACP identifiers, and any digest challenge answered.
    pub rtsp: RtspSession,
}

/// A [`RaopConnection`] shared with the feedback and streaming tasks.
pub type SharedConnection = Arc<Mutex<RaopConnection>>;

/// Open a connection to a receiver's RAOP port.
///
/// `http_connect(str(config.address), core.service.port)` (`raop/__init__.py:143-145`) — the
/// **RAOP** service's own port from its `_raop._tcp` SRV record, not the AirPlay one.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if the receiver is unreachable.
pub async fn connect(address: SocketAddr) -> Result<SharedConnection> {
    tracing::debug!(%address, "opening RAOP connection");

    Ok(Arc::new(Mutex::new(RaopConnection {
        http: HttpConnection::connect(address).await?,
        rtsp: RtspSession::new(),
    })))
}

/// Run one RTSP exchange against a shared connection.
///
/// A convenience for the many call sites that lock, borrow both halves, and send one verb. The
/// lock is held across the `await`, which is the point: it is what serialises the connection.
///
/// # Errors
///
/// Whatever `body` returns.
pub async fn with_connection<T, F>(connection: &SharedConnection, body: F) -> Result<T>
where
    F: AsyncFnOnce(&mut RtspSession, &mut HttpConnection) -> Result<T>,
{
    let mut guard = connection.lock().await;
    let RaopConnection { http, rtsp } = &mut *guard;
    body(rtsp, http).await
}
