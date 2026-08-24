//! Pre-HAP AirPlay device authentication over `/pair-setup-pin` and `/pair-verify`.
//!
//! Port of `pyatv/protocols/airplay/auth/legacy.py:25-113`. Only AirPlay 1 receivers speak it, and
//! only pair-*setup* uses binary property lists — pair-verify posts raw bytes with
//! `Content-Type: application/octet-stream` and no plist wrapper (`legacy.py:103-106`).
//!
//! No `X-Apple-HKP` header is sent at all. That absence is the wire signal: a receiver answers
//! `501 Not Implemented` to a `/pair-verify` whose `X-Apple-HKP` is not `3`, and pyatv's own fake
//! device uses that `501` to route the request to its legacy handler
//! (`tests/fake_device/airplay.py:193-197`).
//!
//! Legacy pairing learns nothing about the accessory: [`LegacyPairSetupDriver::finish_pairing`]
//! returns the credentials generated locally before the exchange started, because the PIN round
//! only proves the *controller's* pre-existing identity to the device (`legacy.py:69`,
//! `auth/__init__.py:64-67`).

use pyatv_pairing::HapCredentials;
use pyatv_pairing::legacy_auth::{
    BINARY_PLIST_CONTENT_TYPE, LegacyPairSetup, LegacyPairVerify, OCTET_STREAM_CONTENT_TYPE,
    PAIR_SETUP_PIN_PATH, PAIR_VERIFY_PATH,
};
use pyatv_pairing::srp_hap::random_seed;

use crate::auth::{PIN_START_PATH, legacy_headers};
use crate::http::HttpConnection;
use crate::{Error, Result};

/// Length of the random controller identifier stored as `client_id`.
const CLIENT_ID_LEN: usize = 8;

/// Generate the credentials legacy pairing starts from.
///
/// Port of `new_credentials` (`pyatv/protocols/airplay/srp.py:52-56`): an empty `ltpk` and
/// `atv_id`, 32 random bytes of seed and 8 random bytes of identifier. These are what gets
/// persisted after a successful pairing — the exchange itself adds nothing to them, since the
/// device never sends anything about its own identity down this path.
///
/// The identifier comes from a second CSPRNG draw rather than from the seed's own bytes, so the
/// public identifier reveals nothing about the secret stored beside it.
#[must_use]
pub fn new_legacy_credentials() -> HapCredentials {
    let seed = random_seed();
    let identifier = random_seed();

    HapCredentials {
        ltpk: Vec::new(),
        ltsk: seed.to_vec(),
        atv_id: Vec::new(),
        client_id: identifier[..CLIENT_ID_LEN].to_vec(),
    }
}

/// Drives legacy pair-setup for one AirPlay service.
#[derive(Debug)]
pub struct LegacyPairSetupDriver {
    setup: LegacyPairSetup,
    /// The same value `LegacyPairSetup::finish` would hand back. Kept separately because that
    /// method consumes the state machine while this driver is used through `&mut self`.
    credentials: HapCredentials,
    started: bool,
}

impl LegacyPairSetupDriver {
    /// Start a pairing for freshly generated credentials.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pairing`] if `credentials.ltsk` is not a 32-byte seed.
    pub fn new(credentials: HapCredentials) -> Result<Self> {
        Ok(Self {
            setup: LegacyPairSetup::new(credentials.clone())?,
            credentials,
            started: false,
        })
    }

    /// Ask the device to display its PIN.
    ///
    /// This is the whole of upstream's `start_pairing` (`legacy.py:35-40`): one bodyless POST.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the device refuses the request.
    pub async fn start_pairing(&mut self, http: &mut HttpConnection) -> Result<()> {
        http.post(PIN_START_PATH, &legacy_headers(), b"").await?;
        self.started = true;
        Ok(())
    }

    /// Run the three `/pair-setup-pin` exchanges.
    ///
    /// The PIN goes on the wire as `str(pin).zfill(4)`
    /// (`pyatv/protocols/airplay/pairing.py:89-91`), so `7` is `"0007"`. The SRP password is that
    /// string; an unpadded one produces a proof the device rejects.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotStarted`] if [`LegacyPairSetupDriver::start_pairing`] has not run,
    /// [`Error::NotAuthenticated`] if the device answers `403` to a wrong PIN, and
    /// [`Error::Pairing`] if a reply is not a well-formed property list or the device's proof does
    /// not verify.
    pub async fn finish_pairing(
        &mut self,
        http: &mut HttpConnection,
        pin: u32,
    ) -> Result<HapCredentials> {
        if !self.started {
            return Err(Error::NotStarted("legacy pair-setup"));
        }

        let step1 = self.setup.step1_body(&format_pin(pin))?;
        let response = post_plist(http, &step1).await?;

        let step2 = self.setup.step2_body(&response)?;
        let response = post_plist(http, &step2).await?;

        let step3 = self.setup.step3_body(&response)?;
        post_plist(http, &step3).await?;

        tracing::debug!("legacy pair-setup completed");
        Ok(self.credentials.clone())
    }
}

/// Drives legacy pair-verify for one AirPlay service.
#[derive(Debug)]
pub struct LegacyPairVerifyDriver {
    verify: LegacyPairVerify,
}

impl LegacyPairVerifyDriver {
    /// Verify against stored legacy credentials.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pairing`] if `credentials.ltsk` is not a 32-byte seed.
    pub fn new(credentials: &HapCredentials) -> Result<Self> {
        Ok(Self {
            verify: LegacyPairVerify::new(credentials)?,
        })
    }

    /// Run the two raw `/pair-verify` exchanges.
    ///
    /// The reply to the second is never read: pyatv awaits it only to learn that the POST did not
    /// raise (`legacy.py:100`, and `tests/fake_device/airplay.py:44` returns an empty body with the
    /// comment "Value not used by pyatv").
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAuthenticated`] if the device answers `403`, or [`Error::Pairing`] if
    /// its first reply is shorter than the 32-byte public key it must carry.
    pub async fn verify_credentials(&mut self, http: &mut HttpConnection) -> Result<()> {
        let step1 = self.verify.step1_body();
        let response = post_raw(http, &step1).await?;

        let step2 = self.verify.step2_body(&response)?;
        post_raw(http, &step2).await?;

        tracing::debug!("legacy pair-verify completed");
        Ok(())
    }
}

/// POST one binary property list to `/pair-setup-pin` and return the reply body.
async fn post_plist(http: &mut HttpConnection, body: &[u8]) -> Result<Vec<u8>> {
    let mut headers = legacy_headers().to_vec();
    headers.push(("Content-Type", BINARY_PLIST_CONTENT_TYPE));

    let response = http.post(PAIR_SETUP_PIN_PATH, &headers, body).await?;
    Ok(response.body.to_vec())
}

/// POST one raw body to `/pair-verify` and return the reply body.
async fn post_raw(http: &mut HttpConnection, body: &[u8]) -> Result<Vec<u8>> {
    let mut headers = legacy_headers().to_vec();
    headers.push(("Content-Type", OCTET_STREAM_CONTENT_TYPE));

    let response = http.post(PAIR_VERIFY_PATH, &headers, body).await?;
    Ok(response.body.to_vec())
}

/// Render a PIN the way pyatv does: decimal, zero-padded to four digits.
fn format_pin(pin: u32) -> String {
    format!("{pin:04}")
}

#[cfg(test)]
mod tests {
    use super::{format_pin, new_legacy_credentials};
    use pyatv_pairing::AuthenticationType;

    /// `str(pin).zfill(4)` (`pyatv/protocols/airplay/pairing.py:91`).
    #[test]
    fn pins_are_zero_padded_to_four_digits() {
        assert_eq!(format_pin(7), "0007");
        assert_eq!(format_pin(2271), "2271");
        assert_eq!(format_pin(0), "0000");
    }

    /// A PIN wider than four digits is not truncated; `zfill` only pads.
    #[test]
    fn longer_pins_are_left_alone() {
        assert_eq!(format_pin(12345), "12345");
    }

    #[test]
    fn generated_credentials_have_the_legacy_shape() {
        let credentials = new_legacy_credentials();

        assert_eq!(
            credentials.authentication_type(),
            AuthenticationType::Legacy
        );
        assert_eq!(credentials.ltsk.len(), 32);
        assert_eq!(credentials.client_id.len(), 8);
        assert!(credentials.ltpk.is_empty());
        assert!(credentials.atv_id.is_empty());
    }

    /// Two calls must not produce the same identity.
    #[test]
    fn generated_credentials_are_random() {
        assert_ne!(new_legacy_credentials(), new_legacy_credentials());
    }
}
