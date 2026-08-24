//! Transient pairing: pair-setup M1–M4 with a fixed PIN and nothing persisted.
//!
//! Port of `AirPlayHapTransientPairVerifyProcedure`
//! (`pyatv/protocols/airplay/auth/hap_transient.py:33-99`). It is filed under "verify" because
//! that is where it fits pyatv's class hierarchy, not because a pair-verify round happens: the
//! whole exchange is pair-setup's first four states, run inline against the fixed PIN `3939`
//! (`hap_transient.py:1-7,30`).
//!
//! Two things separate it from every other flow and neither can be generalised away
//! (`docs/research/hap-pairing-port-spec.md` §4.4):
//!
//! - `X-Apple-HKP: 4`, which is what tells the receiver to run the transient branch
//!   (`pyatv/protocols/airplay/server_auth.py:169-170`).
//! - The transport keys come from the SRP session key `K`, not from an X25519 ECDH output, because
//!   no ECDH ever happens. [`pyatv_pairing::TransientPairSetup::encryption_keys`] handles that.
//!
//! pyatv has **no test coverage for this path at all** (`hap-pairing-port-spec.md` §11 finding 7),
//! so the hermetic round trip in this crate's tests is the only check that exists.

use pyatv_pairing::TransientPairSetup;
use pyatv_pairing::pairing::SessionKeys;

use crate::auth::{HKP_TRANSIENT, PAIR_SETUP_PATH, PIN_START_PATH, hap_headers};
use crate::http::HttpConnection;
use crate::{Error, Result};

/// Drives transient pairing for one AirPlay service.
#[derive(Debug, Default)]
pub struct TransientPairVerify {
    setup: Option<TransientPairSetup>,
}

impl TransientPairVerify {
    /// A procedure that has not contacted the device yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `/pair-pin-start` and pair-setup M1–M4 in one go.
    ///
    /// No PIN is prompted for or displayed; the fixed [`pyatv_pairing::pairing::TRANSIENT_PIN`] is
    /// both sides' shared secret, which is what makes the pairing "transient" rather than secure.
    ///
    /// pyatv returns `True` immediately after posting M3 without reading the reply
    /// (`hap_transient.py:78-82`), so a device that rejected the fixed PIN looks identical to one
    /// that accepted it until the first encrypted frame fails to decrypt. The M4 reply is consumed
    /// here instead, and its error code and SRP proof are both checked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the device refuses a request, or [`Error::Pairing`] if it
    /// reports a HAP error or its proof does not verify.
    pub async fn verify_credentials(&mut self, http: &mut HttpConnection) -> Result<()> {
        let headers = hap_headers(HKP_TRANSIENT);

        http.post(PIN_START_PATH, &headers, b"").await?;

        let (mut setup, m1) = TransientPairSetup::start();
        let m2 = http.post(PAIR_SETUP_PATH, &headers, &m1).await?;

        let m3 = setup.handle_m2(&m2.body)?;
        let m4 = http.post(PAIR_SETUP_PATH, &headers, &m3).await?;

        setup.handle_m4(&m4.body)?;
        tracing::debug!("transient pairing completed");

        self.setup = Some(setup);
        Ok(())
    }

    /// Derive one channel's transport keys from the SRP session key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotStarted`] if the exchange has not completed.
    pub fn encryption_keys(
        &self,
        salt: &str,
        output_info: &str,
        input_info: &str,
    ) -> Result<SessionKeys> {
        let setup = self
            .setup
            .as_ref()
            .ok_or(Error::NotStarted("transient pairing"))?;
        Ok(setup.encryption_keys(salt, output_info, input_info)?)
    }
}
