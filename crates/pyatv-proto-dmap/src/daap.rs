//! `DaapRequester`: login, session bookkeeping, URL construction and the retry state machine.
//!
//! Port of `pyatv/protocols/dmap/daap.py:75-185`.

pub mod convert;
pub mod url;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Mutex;

use crate::http::{HttpClient, HttpRequest, Method};
use crate::parser::{self, DmapEntry};
use crate::{Error, Result};

pub use convert::{media_kind, ms_to_s, playstate};
pub use url::{Credential, LOGIN_CMD};

/// The headers on every DAAP request, in pyatv's order.
///
/// `_DMAP_HEADERS` (`daap.py:17-25`), byte-identical to the independent copy the fake device
/// asserts against (`tests/fake_device/dmap.py:17-25`). No test upstream checks header *order* on
/// the wire, but reproducing the dict's insertion order costs nothing and makes a capture from
/// either implementation comparable.
///
/// On `Accept-Encoding: gzip`, and why it is still here rather than dropped, see [`crate::http`].
pub const DMAP_HEADERS: [(&str, &str); 7] = [
    ("Accept", "*/*"),
    ("Accept-Encoding", "gzip"),
    ("Client-DAAP-Version", "3.13"),
    ("Client-ATV-Sharing-Version", "1.2"),
    ("Client-iTunes-Sharing-Version", "3.15"),
    ("User-Agent", "Remote/1021"),
    ("Viewer-Only-Client", "1"),
];

/// The extra header a `POST` carries, added to a *copy* of [`DMAP_HEADERS`] (`daap.py:123-124`).
/// A `GET` never sends a `Content-Type`.
pub const POST_CONTENT_TYPE: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");

/// The session id that means "not logged in yet" (`daap.py:85`).
///
/// A real device could in principle hand back session id `0`, which this check could not tell from
/// "no session". Upstream has the same hole and no test covers it; it is noted rather than fixed,
/// because inventing a separate flag would diverge from the state machine every other behaviour
/// here is matched against.
pub const NO_SESSION: u64 = 0;

/// One request, described so it can be re-issued after a re-login with a freshly built URL.
///
/// This is what pyatv's `_login_request`/`_get_request`/`_post_request` closures are: `_do` calls
/// the closure again on retry, and the closure rebuilds the URL from `self._session_id`, so the
/// retry carries the *new* session id rather than the one that just failed. Keeping the request as
/// data rather than as a closure makes that explicit.
#[derive(Debug, Clone)]
struct Action {
    method: Method,
    /// A command template still containing the `[AUTH]` placeholder.
    command: String,
    body: Option<Vec<u8>>,
    /// Whether `[AUTH]` gets `session-id=`.
    session: bool,
    /// Whether `[AUTH]` gets `pairing-guid=`/`hsgid=`.
    login_id: bool,
}

/// Performs DAAP requests against one device, logging in as needed.
#[derive(Debug)]
pub struct DaapRequester {
    http: HttpClient,
    credential: String,
    session_id: AtomicU64,
    /// Serialises re-login so that several requests failing at once produce one login, not several.
    ///
    /// Upstream has no such guard: two coroutines that both get a 403 both call `login()`, and the
    /// second one's session id wins by luck. That race is reachable here too — the push updater's
    /// long poll runs alongside every command — so it is closed. Nothing observable changes when
    /// there is only one request in flight, which is the case every upstream test covers.
    login_lock: Mutex<()>,
}

impl DaapRequester {
    /// A requester for the device at `peer`, authenticating with `credential`.
    ///
    /// The credential string is not validated here. `_mkurl` decides at *login* time whether it is
    /// a pairing GUID or a Home Sharing ID (`daap.py:154-170`), and `DaapRequester.__init__` takes
    /// whatever `BaseService.credentials` holds — so a device configured with nonsense fails on
    /// first use, not on construction, exactly as upstream.
    #[must_use]
    pub fn new(peer: SocketAddr, credential: impl Into<String>) -> Self {
        Self {
            http: HttpClient::new(peer),
            credential: credential.into(),
            session_id: AtomicU64::new(NO_SESSION),
            login_lock: Mutex::new(()),
        }
    }

    /// The current session id, or [`NO_SESSION`].
    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.session_id.load(Ordering::SeqCst)
    }

    /// The device being talked to.
    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        self.http.peer()
    }

    /// Log in and record the session id (`login`, `daap.py:87-104`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCredentials`] if the stored credential is neither a pairing GUID nor
    /// a Home Sharing ID, [`Error::Authentication`] if the device refuses twice, [`Error::Io`] if
    /// it is unreachable, and [`Error::Malformed`] if the response carries no `mlog.mlid`.
    pub async fn login(&self) -> Result<u64> {
        let _guard = self.login_lock.lock().await;
        self.login_locked().await
    }

    /// The login itself, with the caller already holding [`Self::login_lock`].
    async fn login_locked(&self) -> Result<u64> {
        let action = Action {
            method: Method::Get,
            command: LOGIN_CMD.to_owned(),
            body: None,
            // `session=False, login_id=True` (`daap.py:93`): there is no session yet, and the
            // credential is sent on this request and no other.
            session: false,
            login_id: true,
        };

        // `is_login=True` skips `_do`'s implicit re-login branch, so a failing login is retried
        // exactly once by re-issuing the same request rather than recursing into itself
        // (`daap.py:143-152`).
        let mut retry = true;
        loop {
            let (status, body) = self.attempt(&action).await?;
            if (200..300).contains(&status) {
                let parsed = parser::parse(&body)?;
                let session = parser::first_uint(&parsed, &["mlog", "mlid"]).ok_or_else(|| {
                    Error::Malformed("login response carries no mlog.mlid".to_owned())
                })?;
                self.session_id.store(session, Ordering::SeqCst);
                tracing::debug!(session, "logged in");
                return Ok(session);
            }
            if status == 500 {
                return Err(Error::NotSupported);
            }
            if retry {
                retry = false;
                continue;
            }
            return Err(Error::Authentication(status));
        }
    }

    /// A DAAP `GET`, returning the raw body (`get`, `daap.py:106-115`).
    ///
    /// `command` is a template still containing `[AUTH]`.
    ///
    /// # Errors
    ///
    /// See [`Self::login`], plus [`Error::NotSupported`] on HTTP 500 and [`Error::Authentication`]
    /// once the one retry is used up.
    pub async fn get(&self, command: &str) -> Result<Vec<u8>> {
        self.assure_logged_in().await?;
        self.perform(&Action {
            method: Method::Get,
            command: command.to_owned(),
            body: None,
            session: true,
            login_id: false,
        })
        .await
    }

    /// A DAAP `GET` whose body is parsed as DMAP.
    ///
    /// # Errors
    ///
    /// See [`Self::get`], plus [`Error::Malformed`] if the body is not decodable DMAP.
    pub async fn get_daap(&self, command: &str) -> Result<Vec<DmapEntry>> {
        let body = self.get(command).await?;
        let parsed = parser::parse(&body)?;
        log_response(&parsed);
        Ok(parsed)
    }

    /// A DAAP `POST` (`post`, `daap.py:117-128`).
    ///
    /// # Errors
    ///
    /// See [`Self::get`].
    pub async fn post(&self, command: &str, body: Option<&[u8]>) -> Result<Vec<DmapEntry>> {
        self.assure_logged_in().await?;
        let raw = self
            .perform(&Action {
                method: Method::Post,
                command: command.to_owned(),
                body: body.map(<[u8]>::to_vec),
                session: true,
                login_id: false,
            })
            .await?;
        let parsed = parser::parse(&raw)?;
        log_response(&parsed);
        Ok(parsed)
    }

    /// `_assure_logged_in` (`daap.py:172-176`): the first `get`/`post` after construction logs in.
    ///
    /// # Errors
    ///
    /// See [`Self::login`].
    async fn assure_logged_in(&self) -> Result<()> {
        if self.session_id() != NO_SESSION {
            return Ok(());
        }
        self.login().await.map(|_| ())
    }

    /// `_do` (`daap.py:130-152`), for a request that is not the login itself.
    ///
    /// Three outcomes, in this order:
    ///
    /// 1. **2xx** — return the body.
    /// 2. **exactly 500** — [`Error::NotSupported`] immediately: no re-login, no retry.
    /// 3. **any other non-2xx** — log in again, then re-issue *this* request once with the new
    ///    session id. If that fails too, log in once more (upstream does, because the guard it
    ///    skips is `is_login`, not `retry`) and then give up with [`Error::Authentication`].
    ///
    /// # Errors
    ///
    /// See [`Self::get`].
    async fn perform(&self, action: &Action) -> Result<Vec<u8>> {
        let mut retry = true;
        loop {
            let (status, body) = self.attempt(action).await?;
            if (200..300).contains(&status) {
                return Ok(body);
            }
            if status == 500 {
                // Upstream's own comment on this mapping is "Seems to be the case?".
                return Err(Error::NotSupported);
            }

            tracing::debug!(status, "implicitly logged out, logging in again");
            self.relogin().await?;

            if retry {
                retry = false;
                continue;
            }
            return Err(Error::Authentication(status));
        }
    }

    /// Log in again unless another task already did while this one was failing.
    ///
    /// The comparison is against the session id the failing request was built with; if it has
    /// already moved on, the retry can just use the new one.
    async fn relogin(&self) -> Result<()> {
        let stale = self.session_id();
        let _guard = self.login_lock.lock().await;
        if self.session_id() != stale {
            return Ok(());
        }
        self.login_locked().await.map(|_| ())
    }

    /// One request/response round trip, with no retry logic at all.
    async fn attempt(&self, action: &Action) -> Result<(u16, Vec<u8>)> {
        let url = url::mkurl(
            &action.command,
            &self.credential,
            self.session_id(),
            action.session,
            action.login_id,
        )?;
        tracing::debug!(method = ?action.method, url, "DAAP request");

        let mut headers: Vec<(&str, &str)> = DMAP_HEADERS.to_vec();
        if action.method == Method::Post {
            headers.push(POST_CONTENT_TYPE);
        }

        let response = self
            .http
            .send(&HttpRequest {
                method: action.method,
                path: &url,
                headers: &headers,
                body: action.body.as_deref(),
                // No deadline. `daap.py:28` declares one and never applies it; see
                // [`crate::http::CONNECT_TIMEOUT`]. `playstatusupdate` depends on this: it is a
                // long poll the device holds open until playback state changes.
                timeout: None,
            })
            .await?;

        Ok((response.status, response.body))
    }
}

/// `_log_response` (`daap.py:178-184`), which writes the same indented tree pyatv's debug log has.
fn log_response(parsed: &[DmapEntry]) {
    if tracing::enabled!(tracing::Level::TRACE) {
        tracing::trace!("{}", parser::pprint(parsed, &crate::tags::lookup_tag));
    }
}

#[cfg(test)]
mod tests;
