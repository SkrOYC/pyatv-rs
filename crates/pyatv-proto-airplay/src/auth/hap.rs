//! HAP pair-setup and pair-verify over `/pair-setup` and `/pair-verify`.
//!
//! Port of `pyatv/protocols/airplay/auth/hap.py:35-151`. Every message body is raw TLV8 posted with
//! `X-Apple-HKP: 3`; the state machines that produce and consume them are
//! [`pyatv_pairing::PairSetup`] and [`pyatv_pairing::PairVerify`].
//!
//! # Where this reads a reply pyatv throws away
//!
//! Upstream discards the response to pair-setup M3 (`hap.py:80-82` awaits the POST and ignores its
//! value) and leaves `# TODO: check status code` after pair-verify M3 (`hap.py:136`). Both replies
//! are consumed here, because M4 is where the accessory's SRP proof and its `Error` TLV live: a
//! wrong PIN comes back as `{SeqNo: 4, Error: Authentication}` and is otherwise invisible until a
//! later step fails for an unrelated-looking reason. See `docs/research/hap-pairing-port-spec.md`
//! §11 findings 1 and 3.

use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::{HapCredentials, PairSetup, PairVerify};

use crate::auth::{HKP_HAP, PAIR_SETUP_PATH, PAIR_VERIFY_PATH, PIN_START_PATH, hap_headers};
use crate::http::HttpConnection;
use crate::{Error, Result};

/// Drives HAP pair-setup for one AirPlay service.
#[derive(Debug, Default)]
pub struct HapPairSetup {
    /// Created by [`HapPairSetup::start_pairing`]; the PIN is supplied later.
    setup: Option<PairSetup>,
    /// The M2 body the device answered M1 with, held until the PIN arrives.
    device_m2: Option<Vec<u8>>,
}

impl HapPairSetup {
    /// A procedure that has not contacted the device yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Post `/pair-pin-start` and pair-setup M1, keeping the device's M2 reply.
    ///
    /// Splitting here is what makes the PIN prompt possible: the device only puts the PIN on screen
    /// in response to these two requests, so M3 cannot be built until the user has read it. pyatv
    /// splits at the same point (`hap.py:45-61` versus `hap.py:63-94`).
    ///
    /// The M5 `Name` TLV pyatv sends is deliberately omitted. Upstream stores
    /// `opack.pack({"name": name})` there (`pyatv/auth/hap_srp.py:193-196`) and this workspace's
    /// OPACK encoder does not yet emit containers. The accessory treats it as optional — MRP pairs
    /// through the same `step3` with `name=None` (`pyatv/protocols/mrp/pairing.py:63`) — so the
    /// only effect is the label the device shows for this controller.
    /// TODO(step-2): send the `Name` TLV once `pyatv-opack`'s dictionary encoder lands.
    ///
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the device refuses either request, or [`Error::Pairing`] if its
    /// M2 is not a well-formed TLV8 message.
    pub async fn start_pairing(&mut self, http: &mut HttpConnection) -> Result<()> {
        let headers = hap_headers(HKP_HAP);

        http.post(PIN_START_PATH, &headers, b"").await?;

        let (setup, m1) = PairSetup::start(None);
        let response = http.post(PAIR_SETUP_PATH, &headers, &m1).await?;
        tracing::debug!(bytes = response.body.len(), "received pair-setup M2");

        self.setup = Some(setup);
        self.device_m2 = Some(response.body.to_vec());
        Ok(())
    }

    /// Run M3 through M6 and return the credentials to persist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotStarted`] if [`HapPairSetup::start_pairing`] has not run, and
    /// [`Error::Pairing`] if the device rejects the PIN or a proof or signature fails to verify.
    pub async fn finish_pairing(
        &mut self,
        http: &mut HttpConnection,
        pin: u32,
    ) -> Result<HapCredentials> {
        let (Some(setup), Some(device_m2)) = (self.setup.as_mut(), self.device_m2.as_deref())
        else {
            return Err(Error::NotStarted("pair-setup"));
        };
        let headers = hap_headers(HKP_HAP);

        setup.set_pin(pin);
        let m3 = setup.handle_m2(device_m2)?;
        let m4 = http.post(PAIR_SETUP_PATH, &headers, &m3).await?;

        let m5 = setup.handle_m4(&m4.body)?;
        let m6 = http.post(PAIR_SETUP_PATH, &headers, &m5).await?;

        let credentials = setup.handle_m6(&m6.body)?;
        tracing::debug!("HAP pair-setup completed");
        Ok(credentials)
    }
}
/// Drives HAP pair-verify for one AirPlay service.
#[derive(Debug)]
pub struct HapPairVerify {
    credentials: HapCredentials,
    verify: Option<PairVerify>,
}

impl HapPairVerify {
    /// A procedure that will verify against `credentials`.
    #[must_use]
    pub fn new(credentials: HapCredentials) -> Self {
        Self {
            credentials,
            verify: None,
        }
    }

    /// Run pair-verify M1 through M4.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAuthenticated`] if the device rejects the credentials, or
    /// [`Error::Pairing`] if the accessory's signature or identifier does not match.
    pub async fn verify_credentials(&mut self, http: &mut HttpConnection) -> Result<()> {
        let headers = hap_headers(HKP_HAP);

        let (mut verify, m1) = PairVerify::start(self.credentials.clone());
        let m2 = http.post(PAIR_VERIFY_PATH, &headers, &m1).await?;

        let m3 = verify.handle_m2(&m2.body)?;
        let m4 = http.post(PAIR_VERIFY_PATH, &headers, &m3).await?;

        verify.handle_m4(&m4.body)?;
        tracing::debug!("HAP pair-verify completed");

        self.verify = Some(verify);
        Ok(())
    }

    /// Derive one channel's transport keys from the pair-verify shared secret.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pairing`] if the exchange has not completed.
    pub fn encryption_keys(
        &self,
        salt: &str,
        output_info: &str,
        input_info: &str,
    ) -> Result<SessionKeys> {
        let verify = self
            .verify
            .as_ref()
            .ok_or(Error::NotStarted("pair-verify"))?;
        Ok(verify.encryption_keys(salt, output_info, input_info)?)
    }
}
