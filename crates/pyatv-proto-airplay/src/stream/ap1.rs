//! The `AirPlay` 1 half of `play_url`.
//!
//! Port of `AirPlayV1.play_url` (`pyatv/protocols/raop/protocols/airplayv1.py:119-137`), specified
//! in `docs/research/airplay-playurl-raop-port-spec.md` §2.2.
//!
//! There is nothing else to it: pair-verify, then one `POST /play`. No `SETUP`, no `RECORD`, no
//! event channel, no keepalive, and the timing-server port the caller hands over is accepted for
//! interface parity and never used — upstream's is not either.

use pyatv_pairing::HapCredentials;

use crate::codec::Response;
use crate::http::RequestSpec;
use crate::rtsp::{encode_plist, method};
use crate::stream::bodies;
use crate::stream::control::PlayControl;
use crate::{Result, stream::random_session_id};

/// One `AirPlay` 1 play session's protocol state, which is to say none.
#[derive(Debug, Clone)]
pub struct AirPlayV1 {
    control: PlayControl,
}

impl AirPlayV1 {
    /// A protocol bound to one control connection.
    #[must_use]
    pub fn new(control: PlayControl) -> Self {
        Self { control }
    }

    /// Verify, then play. Returns the `/play` response whatever its status.
    ///
    /// For null credentials pair-verify is a no-op that sends nothing, and for legacy credentials
    /// it proves identity without deriving transport keys, so the `/play` that follows is
    /// plaintext in both cases — which is what an `AirPlay` 1 receiver expects.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotAuthenticated`] if the device rejects the credentials,
    /// [`crate::Error::Pairing`] if a signature does not verify, [`crate::Error::Plist`] if the
    /// body cannot be encoded, and [`crate::Error::Io`] on a transport failure.
    pub async fn play_url(
        &mut self,
        credentials: &HapCredentials,
        url: &str,
        position: f64,
    ) -> Result<Response> {
        self.control.verify(credentials).await?;

        let session_id = random_session_id();
        let body = encode_plist(&bodies::v1_play_body(url, position, &session_id))?;

        tracing::debug!(address = %self.control.address(), url, position, "starting to play");
        self.control
            .send(&RequestSpec {
                method: method::POST,
                uri: bodies::PLAY_PATH,
                headers: &bodies::v1_play_headers(),
                body: &body,
                allow_error: true,
                ..RequestSpec::default()
            })
            .await
    }
}
