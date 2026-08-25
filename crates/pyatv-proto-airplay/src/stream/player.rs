//! The version-agnostic driver: retry the play, then poll until the media ends.
//!
//! Port of `AirPlayPlayer` (`pyatv/protocols/airplay/player.py`, the whole 119-line file),
//! specified in `docs/research/airplay-playurl-raop-port-spec.md` §2.1. Both protocol versions sit
//! under it and the only thing that differs between them is what one `play_url` call sends.

use std::net::{IpAddr, SocketAddr};

use plist::Dictionary;
use pyatv_pairing::HapCredentials;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::http::RequestSpec;
use crate::rtsp::{decode_plist, method};
use crate::stream::ap1::AirPlayV1;
use crate::stream::ap2::AirPlayV2;
use crate::stream::control::PlayControl;
use crate::stream::{PlayOptions, PlayTiming, bodies};
use crate::{Error, Result};

/// Total `/play` attempts, not retries after the first (`player.py:14`).
///
/// The loop is `while retry < PLAY_RETRIES` with `retry` starting at zero, so a receiver that
/// answers `500` three times gets three requests and then a failure.
pub const PLAY_RETRIES: u32 = 3;

/// Polls of `/playback-info` allowed before playback is assumed never to have started
/// (`player.py:15`).
pub const WAIT_RETRIES: i32 = 5;

/// The status that earns a retry rather than a failure (`player.py:53`).
const RETRY_STATUS: u16 = 500;

/// Which protocol version is driving this session.
#[derive(Debug)]
enum Protocol {
    /// One `POST /play` after a pair-verify.
    V1(AirPlayV1),
    /// The full `SETUP`/event-channel/`RECORD`/`/play` sequence. Boxed because it is much the
    /// larger of the two and an enum is as big as its widest variant.
    V2(Box<AirPlayV2>),
}

/// A connected play session.
///
/// Holds the control connection open for the whole of [`AirPlayPlayer::play_url`], which does not
/// return until the receiver stops reporting a duration — upstream's docstring puts it as "the
/// Apple TV requires the request to stay open during the entire play duration"
/// (`pyatv/protocols/airplay/__init__.py:104-108`).
#[derive(Debug)]
pub struct AirPlayPlayer {
    control: PlayControl,
    protocol: Protocol,
    credentials: HapCredentials,
    timing: PlayTiming,
}

impl AirPlayPlayer {
    /// Open the control connection and pick the protocol version.
    ///
    /// Nothing is sent yet: pair-verify happens inside the first `play_url` attempt, because
    /// upstream re-verifies on every one (`docs/research/airplay-playurl-raop-port-spec.md` §0
    /// point 6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the device cannot be reached.
    pub async fn connect(options: &PlayOptions) -> Result<Self> {
        let control = PlayControl::connect(options.address).await?;

        let protocol = if options.version == pyatv_core::airplay::AirPlayMajorVersion::V1 {
            Protocol::V1(AirPlayV1::new(control.clone()))
        } else {
            Protocol::V2(Box::new(AirPlayV2::new(control.clone(), options.timing)))
        };

        Ok(Self {
            control,
            protocol,
            credentials: options.credentials.clone(),
            timing: options.timing,
        })
    }

    /// The device this session is playing to.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.control.address()
    }

    /// Play `url` and do not return until it has finished.
    ///
    /// The outer loop of `AirPlayPlayer.play_url` (`player.py:44-71`): up to [`PLAY_RETRIES`]
    /// attempts one [`PlayTiming::retry_delay`] apart while the receiver answers `500`, an error
    /// for any other `4xx`/`5xx`, and otherwise the `/playback-info` poll until playback ends.
    ///
    /// `stop` cuts the call short. Upstream has no `/stop` request — `AirPlayRemoteControl.stop()`
    /// closes the connection out from under the poll, which makes the next `GET /playback-info`
    /// fail and the loop treat that as "playback stopped" (`__init__.py:96-99`, `player.py:85-87`).
    /// This port waits on a notification instead, which cancels the in-flight request rather than
    /// racing a socket shutdown against it; either way the call returns `Ok(())`. Notify the handle
    /// with `notify_one`, not `notify_waiters`, so that a stop arriving before the poll starts is
    /// still seen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAuthenticated`] for any non-`500` `4xx`/`5xx` answer to `/play` — which
    /// is upstream's own coarse mapping, `# TODO: Should be more fine-grained` and all
    /// (`player.py:63-65`) — [`Error::Playback`] if the receiver reports an error in
    /// `/playback-info` or if every attempt was refused with `500`, and [`Error::Io`] on a
    /// transport failure.
    pub async fn play_url(&mut self, url: &str, position: f64, stop: &Notify) -> Result<()> {
        // Bound for the whole call, including the poll loop, exactly as upstream's `async with`
        // is (`player.py:47-68`). AirPlay 1 never uses the port and AirPlay 2 only quotes it in
        // the base `SETUP`; neither receives traffic on it during a `play_url`.
        let timing_server = bind_timing_server(self.control.local_ip().await?).await?;
        let timing_port = timing_server.local_addr()?.port();
        let credentials = self.credentials.clone();

        for attempt in 1..=PLAY_RETRIES {
            let response = match &mut self.protocol {
                Protocol::V1(protocol) => protocol.play_url(&credentials, url, position).await?,
                Protocol::V2(protocol) => {
                    protocol
                        .play_url(&credentials, timing_port, url, position)
                        .await?
                }
            };

            if response.status == RETRY_STATUS {
                tracing::debug!(url, attempt, retries = PLAY_RETRIES, "failed to stream");
                tokio::time::sleep(self.timing.retry_delay).await;
                continue;
            }
            if (400..600).contains(&response.status) {
                return Err(Error::NotAuthenticated {
                    status: response.status,
                });
            }

            return tokio::select! {
                outcome = self.wait_for_media_to_end() => outcome,
                () = stop.notified() => {
                    tracing::debug!(address = %self.control.address(), "playback stopped by caller");
                    Ok(())
                }
            };
        }

        Err(Error::Playback("Max retries exceeded".to_owned()))
    }

    /// Poll `/playback-info` once a second until the media ends (`player.py:75-118`).
    ///
    /// The counter semantics are upstream's and are easy to misread. Playback must start within
    /// [`WAIT_RETRIES`] polls or the call returns — quietly, with no error, as if it had played.
    /// Once a `duration` has appeared even once the counter is pinned below zero, so the loop then
    /// ends on the very first poll that lacks one, with no debounce. Only `error` and `duration`
    /// are read; `readyToPlay`, `position` and `rate` are real keys a receiver sends and upstream
    /// ignores all of them.
    async fn wait_for_media_to_end(&self) -> Result<()> {
        let mut attempts = WAIT_RETRIES;
        let mut video_started;

        loop {
            let parsed = match self.playback_info().await {
                Ok(parsed) => parsed,
                Err(error) if is_connection_lost(&error) => {
                    tracing::debug!(%error, "connection was lost, assuming playback stopped");
                    return Ok(());
                }
                Err(error) => return Err(error),
            };

            if let Some(reported) = parsed.get("error") {
                return Err(Error::Playback(describe(reported)));
            }

            if parsed.contains_key("duration") {
                video_started = true;
                attempts = -1;
            } else {
                video_started = false;
                if attempts >= 0 {
                    attempts -= 1;
                }
            }

            if !video_started && attempts < 0 {
                tracing::debug!(address = %self.control.address(), "media playback ended");
                return Ok(());
            }

            tokio::time::sleep(self.timing.poll_interval).await;
        }
    }

    /// One `GET /playback-info`, decoded.
    ///
    /// A bodyless answer reads as an empty dictionary rather than as a failure
    /// (`player.py:88-92`); upstream sends this without `allow_error`, so a non-`2xx` really does
    /// propagate, which is how a `403` here surfaces as an authentication error.
    async fn playback_info(&self) -> Result<Dictionary> {
        let response = self
            .control
            .send(&RequestSpec {
                method: method::GET,
                uri: bodies::PLAYBACK_INFO_PATH,
                ..RequestSpec::default()
            })
            .await?;

        if response.body.is_empty() {
            tracing::debug!("got playback-info response without content");
            return Ok(Dictionary::new());
        }

        decode_plist(&response.body)?
            .into_dictionary()
            .ok_or_else(|| Error::Plist("playback-info is not a dictionary".to_owned()))
    }

    /// Close the event channel, the keepalive and the connection.
    ///
    /// `AirPlayStream.play_url`'s `finally` (`__init__.py:133-139`). Upstream's player never calls
    /// `AirPlayV2.teardown()` itself, so its feedback task and event channel survive until the
    /// facade closes the socket; doing both here removes the window
    /// (`docs/research/airplay-playurl-raop-port-spec.md` §16.2).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket could not be shut down cleanly.
    pub async fn close(&mut self) -> Result<()> {
        if let Protocol::V2(protocol) = &mut self.protocol {
            protocol.teardown();
        }
        self.control.close().await
    }
}

/// Bind the ephemeral UDP timing socket (`player.py:24-32`).
///
/// Upstream binds it on the local address the RTSP connection uses, port zero. It is pure interface
/// uniformity — no `SETUP` for audio happens during a `play_url`, so a receiver has no reason to
/// query it — but the socket is real and the port number reaches the receiver, so it is bound here
/// too rather than passing a made-up number.
async fn bind_timing_server(local_ip: IpAddr) -> Result<UdpSocket> {
    Ok(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?)
}

/// Whether an error means the receiver hung up, which upstream reads as "playback stopped".
///
/// Upstream catches `RuntimeError` and `ConnectionLostError` only (`player.py:85-87`), so a
/// *timeout* propagates rather than ending the wait quietly. This keeps that distinction: only the
/// kinds a closed socket produces count as a stop.
fn is_connection_lost(error: &Error) -> bool {
    let Error::Io(error) = error else {
        return false;
    };

    matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
    )
}

/// Render the `error` dictionary the way upstream phrases it (`player.py:97-102`).
///
/// `code` and `domain` fall back to `unknown` and `unknown domain`, and a value that is not a
/// dictionary at all still produces a message rather than a decode failure.
fn describe(reported: &plist::Value) -> String {
    let Some(dictionary) = reported.as_dictionary() else {
        return format!("got error {} when playing video", scalar(reported));
    };

    let code = dictionary.get("code").map_or("unknown".to_owned(), scalar);
    let domain = dictionary
        .get("domain")
        .map_or("unknown domain".to_owned(), scalar);

    format!("got error {code} ({domain}) when playing video")
}

/// One property-list scalar as Python would print it.
fn scalar(value: &plist::Value) -> String {
    if let Some(text) = value.as_string() {
        return text.to_owned();
    }

    value
        .as_signed_integer()
        .map_or_else(|| format!("{value:?}"), |number| number.to_string())
}

#[cfg(test)]
mod tests {
    use super::{PLAY_RETRIES, RETRY_STATUS, WAIT_RETRIES, describe, is_connection_lost};
    use crate::Error;

    /// `PLAY_RETRIES = 3`, `WAIT_RETRIES = 5` (`player.py:14-15`).
    #[test]
    fn the_constants_match_upstream() {
        assert_eq!(PLAY_RETRIES, 3);
        assert_eq!(WAIT_RETRIES, 5);
        assert_eq!(RETRY_STATUS, 500);
    }

    /// The message is upstream's, including both fallbacks (`player.py:97-102`).
    #[test]
    fn an_error_dictionary_reads_the_way_upstream_phrases_it() {
        let mut error = plist::Dictionary::new();
        error.insert("code".to_owned(), (-12_345i64).into());
        error.insert("domain".to_owned(), "NSURLErrorDomain".into());

        assert_eq!(
            describe(&plist::Value::Dictionary(error)),
            "got error -12345 (NSURLErrorDomain) when playing video"
        );

        assert_eq!(
            describe(&plist::Value::Dictionary(plist::Dictionary::new())),
            "got error unknown (unknown domain) when playing video"
        );
    }

    /// A hung-up socket ends the wait; a timeout does not.
    #[test]
    fn only_a_closed_socket_counts_as_a_lost_connection() {
        for kind in [
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionReset,
        ] {
            assert!(is_connection_lost(&Error::Io(std::io::Error::new(
                kind, "closed"
            ))));
        }

        assert!(!is_connection_lost(&Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "no answer"
        ))));
        assert!(!is_connection_lost(&Error::NotAuthenticated {
            status: 403
        }));
    }
}
