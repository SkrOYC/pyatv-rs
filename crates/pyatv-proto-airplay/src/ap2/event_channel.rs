//! The AirPlay 2 event channel.
//!
//! Port of `EventChannel` (`pyatv/protocols/airplay/channels.py:34-97`) and the half of
//! `AP2Session._setup_event_channel` that follows the `SETUP` reply (`ap2_session.py:137-149`).
//!
//! Three facts shape this module, all of them upstream's:
//!
//! - **The controller dials, then acts as the server.** `setup_channel` opens the TCP connection
//!   (`hap_channel.py:92-96`), but every message on it is a request *from* the receiver that the
//!   controller answers `200 OK`. Nothing is ever sent unprompted.
//! - **The two info strings are swapped.** `setup_channel(..., EVENTS_SALT, EVENTS_READ_INFO,
//!   EVENTS_WRITE_INFO)` (`ap2_session.py:140-148`) passes `read` where `output_info` is expected
//!   and `write` where `input_info` is. [`event_channel_keys`] reproduces the call site's literal
//!   argument order rather than re-deriving which way round it should be — see
//!   `docs/research/hap-pairing-port-spec.md` §4.3.
//! - **The payloads are never interpreted.** Upstream's comment is "Event channel is not used so we
//!   don't care about it (must be set up though)". This port still surfaces each request on a
//!   channel so a caller can log or assert on it, but nothing in the tunnel depends on it, and a
//!   receiver that says nothing at all is the expected case.

use std::net::SocketAddr;

use bytes::BytesMut;
use pyatv_pairing::hkdf_derive::transport::AIRPLAY_EVENTS;
use pyatv_pairing::pairing::SessionKeys;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::Result;
use crate::auth::PairVerifyProcedure;
use crate::codec::{Frame, Request, Response, encode_frame, parse_frame};

use super::channel::{self, HapReader, HapWriter};

/// `Server` header value this port answers event-channel requests with.
///
/// Upstream sends `pyatv-www/{version}` (`pyatv/support/http.py:34`, emitted by `format_response`
/// at `http.py:151-153` only when the caller supplied no `Server` of its own). This port names
/// itself for the same reason [`crate::http::DEFAULT_USER_AGENT`] does: claiming to be pyatv would
/// be a claim about a codebase this is not.
pub const SERVER_NAME: &str = concat!("pyatv-rs-www/", env!("CARGO_PKG_VERSION"));

/// How many unread event requests are held before the oldest are dropped.
///
/// The channel is decorative — upstream discards every request after answering it — so a consumer
/// that never drains must not be able to stall the reply loop or grow without bound.
const EVENT_QUEUE_DEPTH: usize = 32;

/// The `(salt, output_info, input_info)` triple the event channel derives with.
///
/// Split out from [`event_channel_keys`] so the swap is assertable on its own, against the
/// `airplay_events` row of `crates/pyatv-pairing/tests/kat/hap_srp_kat.json` — a vector generated
/// from pyatv, not from this port. The `output_info` slot really does hold the *read* string; that
/// is `ap2_session.py:145-147`'s literal argument order, not a transcription slip.
#[must_use]
pub fn event_channel_key_spec() -> (&'static str, &'static str, &'static str) {
    (
        AIRPLAY_EVENTS.salt,
        AIRPLAY_EVENTS.read_info,
        AIRPLAY_EVENTS.write_info,
    )
}

/// Derive the event channel's transport keys, with the info strings swapped.
///
/// # Errors
///
/// Returns [`crate::Error::NoEncryptionKeys`] if `verifier` ran an exchange that derives none, and
/// [`crate::Error::Pairing`] if it has not completed.
pub fn event_channel_keys(verifier: &PairVerifyProcedure) -> Result<SessionKeys> {
    let (salt, output_info, input_info) = event_channel_key_spec();
    verifier.encryption_keys(salt, output_info, input_info)
}

/// A running event channel.
///
/// Dropping it aborts the read loop and closes the socket.
#[derive(Debug)]
pub struct EventChannel {
    address: SocketAddr,
    inbound: Mutex<mpsc::Receiver<Request>>,
    task: JoinHandle<()>,
}

impl Drop for EventChannel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl EventChannel {
    /// Dial the receiver's `eventPort` and start answering whatever arrives.
    ///
    /// Returns as soon as the socket is up: a receiver that never sends anything is normal, so
    /// nothing here waits for traffic and session bring-up is never blocked by this channel.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the port cannot be reached.
    pub async fn connect(address: SocketAddr, keys: &SessionKeys) -> Result<Self> {
        let (reader, writer) = channel::connect(address, keys).await?;
        let (sender, inbound) = mpsc::channel(EVENT_QUEUE_DEPTH);

        let task = tokio::spawn(async move {
            run(reader, writer, sender, address).await;
        });

        Ok(Self {
            address,
            inbound: Mutex::new(inbound),
            task,
        })
    }

    /// The receiver-side address this channel was opened to.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Await the next request the receiver sent, after it has already been answered.
    ///
    /// `None` means the channel is closed and no further request can arrive.
    pub async fn recv(&self) -> Option<Request> {
        self.inbound.lock().await.recv().await
    }

    /// Stop the read loop and close the socket.
    pub fn close(&self) {
        self.task.abort();
    }
}

/// Read requests, answer each one, and forward it to the consumer.
async fn run(
    mut reader: HapReader,
    mut writer: HapWriter,
    sender: mpsc::Sender<Request>,
    address: SocketAddr,
) {
    let mut buffer = BytesMut::new();

    loop {
        match reader.read().await {
            Ok(Some(plaintext)) => buffer.extend_from_slice(&plaintext),
            Ok(None) => break,
            Err(error) => {
                tracing::debug!(%address, %error, "event channel read failed");
                break;
            }
        }

        match drain(&mut buffer, &mut writer, &sender, address).await {
            Ok(()) => {}
            Err(error) => {
                // Upstream catches per-request and keeps going (`channels.py:96-97`). A parse
                // failure on a byte stream is a desynchronisation, not a recoverable single bad
                // message, so this port tears the channel down instead of looping on garbage.
                tracing::debug!(%address, %error, "event channel torn down");
                break;
            }
        }
    }

    let _ = writer.shutdown().await;
}

/// Answer every complete request currently in `buffer`.
async fn drain(
    buffer: &mut BytesMut,
    writer: &mut HapWriter,
    sender: &mpsc::Sender<Request>,
    address: SocketAddr,
) -> Result<()> {
    while let Some((frame, consumed)) = parse_frame(buffer)? {
        let _ = buffer.split_to(consumed);

        let Frame::Request(request) = frame else {
            tracing::debug!(%address, "ignoring a response on the event channel");
            continue;
        };

        tracing::debug!(
            %address,
            method = %request.method,
            uri = %request.uri,
            "event channel request"
        );

        writer.send(&encode_reply(&request)).await?;

        // A full queue means the consumer is not draining; the reply above is what the receiver
        // actually needs, so the request itself is dropped rather than blocking the loop.
        if let Err(mpsc::error::TrySendError::Full(dropped)) = sender.try_send(request) {
            tracing::debug!(%address, uri = %dropped.uri, "dropping an undrained event");
        }
    }

    Ok(())
}

/// Build the `200 OK` every request gets.
///
/// `EventChannel.handle_received` (`channels.py:75-95`) fed through `format_response`
/// (`pyatv/support/http.py:141-167`). The resulting header order is load-bearing and is not the
/// order the Python dict literal suggests:
///
/// 1. `Server`, first, but **only if the request carried none** — `format_response` inserts it
///    ahead of the caller's headers in that case.
/// 2. `Content-Length: 0`, then `Audio-Latency: 0`, the two literals upstream always sets.
/// 3. `Server` echoed back, if the request had one, in the position the dict put it.
/// 4. `CSeq` echoed back, if the request had one.
///
/// The protocol token is echoed from the request (`HttpResponse(request.protocol,
/// request.version, ...)`), so an `RTSP/1.0` request is answered `RTSP/1.0`.
fn encode_reply(request: &Request) -> Vec<u8> {
    let server = request.header("Server");

    let mut headers: Vec<(String, String)> = Vec::with_capacity(4);
    if server.is_none() {
        headers.push(("Server".to_owned(), SERVER_NAME.to_owned()));
    }
    headers.push(("Content-Length".to_owned(), "0".to_owned()));
    headers.push(("Audio-Latency".to_owned(), "0".to_owned()));
    if let Some(server) = server {
        headers.push(("Server".to_owned(), server.to_owned()));
    }
    if let Some(cseq) = request.header("CSeq") {
        headers.push(("CSeq".to_owned(), cseq.to_owned()));
    }

    let mut out = BytesMut::new();
    encode_frame(
        &Frame::Response(Response {
            protocol: request.protocol.clone(),
            status: 200,
            reason: "OK".to_owned(),
            headers,
            body: bytes::Bytes::new(),
        }),
        &mut out,
    );
    out.to_vec()
}

/// Case-insensitive header lookup, matching upstream's `CaseInsensitiveDict`.
trait RequestHeaders {
    fn header(&self, name: &str) -> Option<&str>;
}

impl RequestHeaders for Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestHeaders as _, encode_reply};
    use crate::codec::Request;

    fn request(headers: &[(&str, &str)]) -> Request {
        Request {
            method: "POST".to_owned(),
            uri: "/event".to_owned(),
            protocol: "RTSP/1.0".to_owned(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: bytes::Bytes::new(),
        }
    }

    /// A request with no `Server` gets one synthesised in first position, ahead of the two
    /// literals upstream always sets (`pyatv/support/http.py:151-153`).
    #[test]
    fn a_request_without_a_server_header_is_answered_with_ours_first() {
        let wire = String::from_utf8(encode_reply(&request(&[("CSeq", "7")]))).expect("utf-8");

        assert_eq!(
            wire,
            format!(
                "RTSP/1.0 200 OK\r\n\
                 Server: {}\r\n\
                 Content-Length: 0\r\n\
                 Audio-Latency: 0\r\n\
                 CSeq: 7\r\n\r\n",
                super::SERVER_NAME
            )
        );
    }

    /// A request that carried a `Server` gets it echoed back in the dict's own position — after
    /// the two literals, not before them (`channels.py:76-83`).
    #[test]
    fn a_server_header_is_echoed_after_the_literals() {
        let wire = String::from_utf8(encode_reply(&request(&[
            ("Server", "AirTunes/980.67.2"),
            ("CSeq", "0"),
        ])))
        .expect("utf-8");

        assert_eq!(
            wire,
            "RTSP/1.0 200 OK\r\n\
             Content-Length: 0\r\n\
             Audio-Latency: 0\r\n\
             Server: AirTunes/980.67.2\r\n\
             CSeq: 0\r\n\r\n"
        );
    }

    /// `CSeq` is optional; the reply is still well formed without it.
    #[test]
    fn a_request_without_a_cseq_is_still_answered() {
        let wire = String::from_utf8(encode_reply(&request(&[("Server", "X")]))).expect("utf-8");

        assert_eq!(
            wire,
            "RTSP/1.0 200 OK\r\nContent-Length: 0\r\nAudio-Latency: 0\r\nServer: X\r\n\r\n"
        );
    }

    /// The protocol token is echoed, so an `HTTP/1.1` request is not answered `RTSP/1.0`.
    #[test]
    fn the_protocol_token_is_echoed() {
        let mut request = request(&[]);
        request.protocol = "HTTP/1.1".to_owned();

        let wire = String::from_utf8(encode_reply(&request)).expect("utf-8");

        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn header_lookup_ignores_case() {
        let request = request(&[("cseq", "3")]);
        assert_eq!(request.header("CSeq"), Some("3"));
        assert_eq!(request.header("Missing"), None);
    }
}
