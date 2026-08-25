//! Pair-setup and pair-verify carried inside `CryptoPairingMessage`.
//!
//! Port of `pyatv/protocols/mrp/auth.py`. The HAP state machines themselves live in
//! [`pyatv_pairing`]; everything here is MRP's framing of them — a TLV8 blob in
//! `CryptoPairingMessage.pairingData`, sent as a `CRYPTO_PAIRING_MESSAGE` that correlates by
//! *type* rather than by identifier, because the device never echoes an identifier back on these
//! and only one exchange can be outstanding at a time (`protocol.py:246-252`, `auth.py:46`).
//!
//! # Stricter than upstream, deliberately
//!
//! `MrpPairVerifyProcedure.verify_credentials` ends with a bare `# TODO: check status code` and
//! returns `True` without looking at the device's M4 at all (`auth.py:110-114`).
//! [`pyatv_pairing::PairVerify::handle_m4`] does check it, and this port lets it: a device that
//! answers M3 with an error TLV, or with the wrong state, fails the connection here instead of
//! producing a session whose first encrypted frame is garbage. Same reasoning as
//! `pyatv-proto-companion`'s pairing handler, and the same class of `TODO` the project's own
//! guidance says to decide on rather than inherit.

use pyatv_pairing::hkdf_derive::transport::MRP;
use pyatv_pairing::{HapCredentials, PairSetup, PairVerify, SessionKeys};

use crate::message::MrpMessage;
use crate::protobuf::extensions;
use crate::protocol::MrpProtocol;
use crate::{Result, messages};

/// Exchange one TLV8 blob and return the device's.
///
/// `is_pairing` sets `CryptoPairingMessage.state = 2`, which upstream does for the very first
/// pair-setup message and nothing else (`messages.py:76`).
async fn exchange(protocol: &MrpProtocol, tlv: &[u8], is_pairing: bool) -> Result<Vec<u8>> {
    let response = protocol
        .exchange_untagged(messages::crypto_pairing(tlv, is_pairing)?)
        .await?;

    pairing_data(&response)
}

/// Pull `pairingData` out of a `CRYPTO_PAIRING_MESSAGE` response.
///
/// `_get_pairing_data` (`auth.py:19-22`) additionally raises on an `Error` TLV; here that check
/// happens inside the [`pyatv_pairing`] state machines, which decode the same TLV and report the
/// device's [`pyatv_pairing::tlv8::ErrorCode`] with the specific reason attached.
fn pairing_data(response: &MrpMessage) -> Result<Vec<u8>> {
    response.check_error_code()?;
    Ok(response
        .inner(&extensions::CRYPTO_PAIRING_MESSAGE)?
        .pairing_data
        .unwrap_or_default())
}

/// Run pair-verify and derive the MRP transport keys.
///
/// `MrpPairVerifyProcedure` (`auth.py:83-121`) plus `MrpProtocol._enable_encryption`'s key
/// derivation (`protocol.py:214-221`). The returned [`SessionKeys::output_key`] is what the client
/// **encrypts** with and [`SessionKeys::input_key`] what it **decrypts** with — the order pyatv
/// passes positionally into `enable_encryption` (`docs/research/hap-pairing-port-spec.md` §4.3).
///
/// # Errors
///
/// Returns [`Error::Pairing`] if the device refuses the credentials or its signature does not
/// verify, and [`Error::Timeout`] if it does not answer.
pub async fn verify_credentials(
    protocol: &MrpProtocol,
    credentials: HapCredentials,
) -> Result<SessionKeys> {
    let (mut verify, m1) = PairVerify::start(credentials);

    let m2 = exchange(protocol, &m1, false).await?;
    let m3 = verify.handle_m2(&m2)?;

    let m4 = exchange(protocol, &m3, false).await?;
    verify.handle_m4(&m4)?;

    Ok(verify.encryption_keys(MRP.salt, MRP.write_info, MRP.read_info)?)
}

/// Drives MRP pair-setup: `M1` before the PIN is known, `M3`-`M6` after.
///
/// `MrpPairSetupProcedure` (`auth.py:25-80`). Split across two calls because the device only shows
/// its PIN once it has answered M1, which is the whole reason the [`PairingHandler`] contract has
/// a `begin`/`pin`/`finish` shape.
///
/// [`PairingHandler`]: pyatv_core::interface::PairingHandler
#[derive(Debug)]
pub struct MrpPairSetupProcedure {
    setup: PairSetup,
    /// The device's M2, kept until the PIN arrives.
    challenge: Vec<u8>,
}

impl MrpPairSetupProcedure {
    /// Send `DEVICE_INFO_MESSAGE` and pair-setup M1, and keep the device's challenge.
    ///
    /// `start_pairing` (`auth.py:35-49`) reuses `MrpProtocol.start(skip_initial_messages=True)`,
    /// i.e. it opens the socket, sends the mandatory device information, and then hands over to
    /// the pairing exchange instead of continuing to encryption and the config messages.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pairing`] if the device refuses to start pairing, or [`Error::Timeout`] if
    /// it does not answer.
    pub async fn start(protocol: &MrpProtocol) -> Result<Self> {
        protocol.exchange_device_info().await?;

        let (setup, m1) = PairSetup::start(None);
        let challenge = exchange(protocol, &m1, true).await?;

        Ok(Self { setup, challenge })
    }

    /// The controller's pairing identifier, which becomes the credentials' `client_id`.
    #[must_use]
    pub fn client_id(&self) -> &[u8] {
        self.setup.client_id()
    }

    /// Finish pairing with the PIN the device displayed.
    ///
    /// `finish_pairing` (`auth.py:51-80`): M3 carries the client's SRP public key and proof, M5 the
    /// encrypted identity payload, and M6 yields the credentials.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pairing`] if the PIN is wrong or the device's proof does not verify, and
    /// [`Error::Timeout`] if it stops answering.
    pub async fn finish(mut self, protocol: &MrpProtocol, pin: u32) -> Result<HapCredentials> {
        self.setup.set_pin(pin);

        let m3 = self.setup.handle_m2(&self.challenge)?;
        let m4 = exchange(protocol, &m3, false).await?;

        let m5 = self.setup.handle_m4(&m4)?;
        let m6 = exchange(protocol, &m5, false).await?;

        Ok(self.setup.handle_m6(&m6)?)
    }
}
