//! The one TCP connection a `play_url` session runs on.
//!
//! `AirPlayStream.play_url` opens a fresh `HttpConnection` and wraps it in an `RtspSession`
//! (`pyatv/protocols/airplay/__init__.py:124-127`); everything after that — pair-verify, `SETUP`,
//! `RECORD`, `/play`, `/playback-info`, `/feedback` and the `setProperty` calls — travels on it.
//!
//! This is *not* [`crate::ap2::Ap2Session`]. That type drives the remote-control tunnel's own
//! sequence, with its own `SETUP` body and its own keepalive semantics, and upstream keeps the two
//! apart as well (`docs/research/airplay-playurl-raop-port-spec.md` §2.3.1, §0 point 5): a device
//! being tunnelled *and* played to gets two independent connections, each with its own pair-verify.
//!
//! # Why a lock
//!
//! Upstream's `HttpConnection` multiplexes: a `CSeq`-keyed table lets the two-second `/feedback`
//! loop and the one-second `/playback-info` poll be in flight together. This port's connection
//! answers one request at a time, so the two share a [`Mutex`] instead. A request is short and
//! neither caller is latency-sensitive, so contention only ever costs one round trip.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use pyatv_pairing::HapCredentials;
use tokio::sync::Mutex;

use crate::Result;
use crate::auth::{PairVerifyProcedure, verify_connection};
use crate::codec::Response;
use crate::http::{HttpConnection, RequestSpec};
use crate::rtsp::RtspSession;

/// The connection and the RTSP state that rides on it.
#[derive(Debug)]
struct Inner {
    http: HttpConnection,
    rtsp: RtspSession,
}

/// A shareable handle to one play session's control connection.
#[derive(Debug, Clone)]
pub struct PlayControl {
    inner: Arc<Mutex<Inner>>,
    address: SocketAddr,
}

impl PlayControl {
    /// Open the connection.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the device cannot be reached.
    pub async fn connect(address: SocketAddr) -> Result<Self> {
        let http = HttpConnection::connect(address).await?;

        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                http,
                rtsp: RtspSession::new(),
            })),
            address,
        })
    }

    /// The device this connection was opened to.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// This socket's own source address, which the timing server binds to (`player.py:26`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket has no local address.
    pub async fn local_ip(&self) -> Result<IpAddr> {
        Ok(self.inner.lock().await.http.local_address()?.ip())
    }

    /// Run pair-verify, encrypting the connection if the credentials produce keys.
    ///
    /// Both versions do this on **every** `play_url` call — there is no verify-once-and-reuse path
    /// anywhere in upstream (`airplayv1.py:120-121`, `airplayv2.py:52-54`, and
    /// `docs/research/airplay-playurl-raop-port-spec.md` §0 point 6).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotAuthenticated`] if the device rejects the credentials and
    /// [`crate::Error::Pairing`] if a proof does not verify.
    pub async fn verify(&self, credentials: &HapCredentials) -> Result<PairVerifyProcedure> {
        let mut inner = self.inner.lock().await;
        verify_connection(credentials, &mut inner.http).await
    }

    /// Send `SETUP` with a property-list body and decode the reply.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Status`] if the receiver refuses it and [`crate::Error::Plist`] if either body
    /// fails to encode or decode.
    pub async fn setup(&self, body: &plist::Value) -> Result<plist::Value> {
        let mut inner = self.inner.lock().await;
        let Inner { http, rtsp } = &mut *inner;
        rtsp.setup(http, body).await
    }

    /// Send a bodyless `RECORD` against the session URI (`airplayv2.py:212`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Status`] if the receiver refuses it.
    pub async fn record(&self) -> Result<Response> {
        let mut inner = self.inner.lock().await;
        let Inner { http, rtsp } = &mut *inner;
        rtsp.record(http).await
    }

    /// Post the keepalive (`airplayv2.py:172`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Status`] for a non-success status and [`crate::Error::Io`] on a transport failure.
    pub async fn feedback(&self) -> Result<Response> {
        let mut inner = self.inner.lock().await;
        let Inner { http, rtsp } = &mut *inner;
        rtsp.feedback(http, false).await
    }

    /// Run one RTSP exchange — the `setProperty` and `/rate` calls (`airplayv2.py:246-272`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Status`] for a non-success status unless `allow_error` is set, and
    /// [`crate::Error::Io`] on a transport failure.
    pub async fn exchange(
        &self,
        method: &str,
        uri: &str,
        body: Option<&plist::Value>,
        allow_error: bool,
    ) -> Result<Response> {
        let mut inner = self.inner.lock().await;
        let Inner { http, rtsp } = &mut *inner;
        rtsp.exchange(http, method, Some(uri), body, allow_error)
            .await
    }

    /// Send one plain HTTP message — `/play` and `/playback-info`, which are not RTSP verbs and
    /// carry none of the `CSeq`/DACP header block (`player.py:84`, `airplayv2.py:257-262`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotAuthenticated`] on `401`/`403` and [`crate::Error::Status`] on any other
    /// non-`2xx`, unless `spec.allow_error` is set. Also [`crate::Error::Io`] on a transport failure.
    pub async fn send(&self, spec: &RequestSpec<'_>) -> Result<Response> {
        let mut inner = self.inner.lock().await;
        inner.http.send(spec).await
    }

    /// Close the connection.
    ///
    /// This is what `AirPlayStream.play_url`'s `finally` does (`__init__.py:136-138`), and — since
    /// there is no `/stop` request anywhere in upstream's play path — it is also the whole of
    /// `AirPlayStream.stop` (`__init__.py:96-99`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket could not be shut down cleanly.
    pub async fn close(&self) -> Result<()> {
        self.inner.lock().await.http.close().await
    }
}
