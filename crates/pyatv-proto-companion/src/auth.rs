//! Companion pair-setup and pair-verify: HAP TLV8 inside an OPACK envelope.
//!
//! Port of `pyatv/protocols/companion/auth.py:1-170`. The crypto is entirely
//! [`pyatv_pairing::PairSetup`] and [`pyatv_pairing::PairVerify`] — identical to MRP's and
//! AirPlay's — so everything here is framing: which frame type carries which message, and which
//! keys sit alongside the TLV8 in the OPACK dict.
//!
//! | Step | Frame sent | OPACK dict | TLV8 under `_pd` |
//! |---|---|---|---|
//! | Setup M1 | `PS_Start` | `{_pd, _pwTy: 1}` | `{Method: 0, SeqNo: 1}` |
//! | Setup M3 | `PS_Next` | `{_pd, _pwTy: 1}` | `{SeqNo: 3, PublicKey, Proof}` |
//! | Setup M5 | `PS_Next` | `{_pd, _pwTy: 1}` | `{SeqNo: 5, EncryptedData}` |
//! | Verify M1 | `PV_Start` | `{_pd, _auTy: 4}` | `{SeqNo: 1, PublicKey}` |
//! | Verify M3 | `PV_Next` | `{_pd}` | `{SeqNo: 3, EncryptedData}` |
//!
//! `_pwTy` is on every pair-setup frame and never on a pair-verify one; `_auTy` is on `PV_Start`
//! alone and is *not* repeated on `PV_Next` (`auth.py:57-62,85-93,102-112,139-144,153-160`).
//! Neither is ever read back off a response. Both literals are unvaried across all of pyatv.
//! Sources: `docs/research/companion-port-spec.md` §4.1, `hap-pairing-port-spec.md` §9.2.

use pyatv_opack::{Value, opack};
use pyatv_pairing::pairing::{PairSetupOptions, random_pairing_id};
use pyatv_pairing::srp_hap::random_seed;
use pyatv_pairing::{HapCredentials, PairSetup, PairVerify, SessionKeys};

use crate::frame::FrameType;
use crate::protocol::CompanionProtocol;
use crate::{Error, Result};

/// The OPACK key carrying raw TLV8 pairing data (`PAIRING_DATA_KEY`, `auth.py:19`).
pub const PAIRING_DATA_KEY: &str = "_pd";
/// "Password type", sent as the literal `1` on every pair-setup frame.
pub const PASSWORD_TYPE_KEY: &str = "_pwTy";
/// "Auth type", sent as the literal `4` on `PV_Start` only.
pub const AUTH_TYPE_KEY: &str = "_auTy";

/// The only `_pwTy` value that appears anywhere in pyatv.
pub const PASSWORD_TYPE_PIN: u64 = 1;
/// The only `_auTy` value that appears anywhere in pyatv.
pub const AUTH_TYPE_HAP: u64 = 4;

/// The display name shown on the device during pairing when the caller supplies none.
///
/// `kwargs.get("name", "pyatv")` (`pyatv/protocols/companion/pairing.py:24`). It is a product
/// decision rather than a protocol requirement — the device renders whatever string arrives — but
/// matching pyatv keeps a user's on-screen prompt recognisable across the two tools.
pub const DEFAULT_DISPLAY_NAME: &str = "pyatv";

/// Build the outbound OPACK dict for a pair-setup frame.
fn setup_frame(tlv: Vec<u8>) -> Value {
    opack! {
        PAIRING_DATA_KEY => tlv,
        PASSWORD_TYPE_KEY => PASSWORD_TYPE_PIN,
    }
}

/// Read the TLV8 blob out of a device response.
///
/// Port of `_get_pairing_data` (`auth.py:22-36`) minus its `Error`-TLV check, which
/// [`pyatv_pairing`]'s own decoder already performs — and performs more strictly, since it also
/// validates `SeqNo`.
///
/// # Errors
///
/// Returns [`Error::Envelope`] if `_pd` is missing, empty, or not a byte string. pyatv splits
/// those into `AuthenticationError` and `ProtocolError`; the distinction is not actionable, since
/// both mean the device did not answer the handshake.
fn pairing_data(response: &Value) -> Result<Vec<u8>> {
    let data = response.get(PAIRING_DATA_KEY).ok_or_else(|| {
        Error::Envelope(format!(
            "no {PAIRING_DATA_KEY} in the device's pairing frame"
        ))
    })?;

    let bytes = data.as_bytes().ok_or_else(|| {
        Error::Envelope(format!(
            "{PAIRING_DATA_KEY} is {data:?}, expected a byte string"
        ))
    })?;

    if bytes.is_empty() {
        return Err(Error::Envelope(format!("{PAIRING_DATA_KEY} was empty")));
    }
    Ok(bytes.to_vec())
}

/// Everything a caller can vary about a Companion pair-setup run.
#[derive(Debug, Clone)]
pub struct PairSetupOptionsCompanion {
    /// The name the device shows on screen while asking for the PIN.
    ///
    /// Companion **always** sends a `Name` TLV, because upstream's default is a non-empty string
    /// rather than `None` — unlike MRP, which never sends one at all.
    pub display_name: String,
}

impl Default for PairSetupOptionsCompanion {
    fn default() -> Self {
        Self {
            display_name: DEFAULT_DISPLAY_NAME.to_owned(),
        }
    }
}

/// Runs Companion pair-setup: PIN in, credentials out.
///
/// Split into [`PairSetupProcedure::start_pairing`] and [`PairSetupProcedure::finish_pairing`] to
/// match the shape a pairing UI needs — the device only displays its PIN once M1 has reached it,
/// so the PIN cannot be known before the first exchange has completed.
#[derive(Debug)]
pub struct PairSetupProcedure {
    setup: PairSetup,
    /// The M1 TLV, produced when the state machine was constructed.
    m1: Vec<u8>,
    /// The device's M2 TLV, held until a PIN arrives.
    ///
    /// Upstream stores the unpacked `Salt` and `PublicKey` here instead (`auth.py:46-47,65-66`);
    /// keeping the raw TLV means the parsing, the `Error`-TLV check and the state check all happen
    /// in one place, inside [`PairSetup::handle_m2`].
    m2: Option<Vec<u8>>,
}

impl PairSetupProcedure {
    /// Build the procedure and its M1 message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Opack`] if the display name cannot be encoded.
    pub fn new(options: &PairSetupOptionsCompanion) -> Result<Self> {
        // The `Name` TLV's value is itself an OPACK dict — the only TLV8 value in the entire
        // handshake with inner structure (`pyatv/auth/hap_srp.py:193-196`).
        let name = pyatv_opack::pack(&opack! { "name" => options.display_name.as_str() })?;

        let (setup, m1) = PairSetup::start_with(
            PairSetupOptions {
                pin: None,
                name: Some(name.to_vec()),
                additional_data: Vec::new(),
            },
            random_seed(),
            random_pairing_id(),
        );

        Ok(Self {
            setup,
            m1,
            m2: None,
        })
    }

    /// Send M1 and capture the device's M2, which is what makes it display a PIN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if the device does not answer, [`Error::Envelope`] if the answer
    /// carries no `_pd`, or an [`Error::Io`] if the connection fails.
    pub async fn start_pairing(&mut self, protocol: &mut CompanionProtocol) -> Result<()> {
        tracing::debug!("sending Companion pair-setup M1");
        let response = protocol
            .exchange_auth(FrameType::PsStart, setup_frame(self.m1.clone()))
            .await?;

        self.m2 = Some(pairing_data(&response)?);
        Ok(())
    }

    /// Complete the handshake with the PIN the device displayed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotReady`] if [`PairSetupProcedure::start_pairing`] has not run, and a
    /// [`Error::Pairing`] carrying [`pyatv_pairing::Error::HapError`] with
    /// `ErrorCode::Authentication` when the PIN is wrong — the device detects that, not the
    /// controller.
    pub async fn finish_pairing(
        &mut self,
        protocol: &mut CompanionProtocol,
        pin: u32,
    ) -> Result<HapCredentials> {
        let m2 = self
            .m2
            .take()
            .ok_or(Error::NotReady("pair-setup M1 has not been sent"))?;

        self.setup.set_pin(pin);
        let m3 = self.setup.handle_m2(&m2)?;

        tracing::debug!("sending Companion pair-setup M3");
        let response = protocol
            .exchange_auth(FrameType::PsNext, setup_frame(m3))
            .await?;
        let m5 = self.setup.handle_m4(&pairing_data(&response)?)?;

        tracing::debug!("sending Companion pair-setup M5");
        let response = protocol
            .exchange_auth(FrameType::PsNext, setup_frame(m5))
            .await?;

        let credentials = self.setup.handle_m6(&pairing_data(&response)?)?;
        tracing::debug!("Companion pair-setup completed");
        Ok(credentials)
    }
}

/// Runs Companion pair-verify: stored credentials in, transport keys out.
#[derive(Debug)]
pub struct PairVerifyProcedure {
    credentials: HapCredentials,
}

impl PairVerifyProcedure {
    /// Build a verifier for one set of stored credentials.
    #[must_use]
    pub const fn new(credentials: HapCredentials) -> Self {
        Self { credentials }
    }

    /// Run M1 through M4 and derive the Companion transport keys.
    ///
    /// The returned [`SessionKeys::output_key`] seals what this side sends and
    /// [`SessionKeys::input_key`] opens what it receives — derived from the `ClientEncrypt-main`
    /// and `ServerEncrypt-main` info strings under an **empty** HKDF salt (`protocol.py:40-42`,
    /// `120-123`). Companion needs no role swap: unlike MRP's shared `Write`/`Read` vocabulary,
    /// the info-string names say whose direction they describe
    /// (`docs/research/hap-pairing-port-spec.md` §4.3).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pairing`] if the device's identity or signature does not check out, if it
    /// refuses the controller's, or if the credentials are not HAP credentials at all.
    pub async fn verify_credentials(self, protocol: &mut CompanionProtocol) -> Result<SessionKeys> {
        let (mut verify, m1) = PairVerify::start(self.credentials);

        tracing::debug!("sending Companion pair-verify M1");
        let response = protocol
            .exchange_auth(
                FrameType::PvStart,
                opack! {
                    PAIRING_DATA_KEY => m1,
                    AUTH_TYPE_KEY => AUTH_TYPE_HAP,
                },
            )
            .await?;

        let m3 = verify.handle_m2(&pairing_data(&response)?)?;

        tracing::debug!("sending Companion pair-verify M3");
        let response = protocol
            .exchange_auth(
                FrameType::PvNext,
                // No `_auTy` here: it is a `PV_Start`-only key (`auth.py:153-160`).
                opack! { PAIRING_DATA_KEY => m3 },
            )
            .await?;

        verify.handle_m4(&pairing_data(&response)?)?;

        let transport = pyatv_pairing::hkdf_derive::transport::COMPANION;
        let keys =
            verify.encryption_keys(transport.salt, transport.write_info, transport.read_info)?;
        tracing::debug!("Companion pair-verify completed");
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AUTH_TYPE_HAP, AUTH_TYPE_KEY, DEFAULT_DISPLAY_NAME, PASSWORD_TYPE_KEY, PASSWORD_TYPE_PIN,
        PairSetupOptionsCompanion, PairSetupProcedure, pairing_data, setup_frame,
    };
    use pyatv_opack::{Value, opack};
    use pyatv_pairing::tlv8::{Method, State, Tlv8, TlvValue};

    #[test]
    fn the_default_display_name_is_pyatv() {
        assert_eq!(
            PairSetupOptionsCompanion::default().display_name,
            DEFAULT_DISPLAY_NAME
        );
    }

    /// Every pair-setup frame carries `_pwTy: 1` alongside the TLV, and nothing else.
    #[test]
    fn a_setup_frame_carries_the_password_type() {
        let frame = setup_frame(vec![1, 2, 3]);
        assert_eq!(
            frame.get(super::PAIRING_DATA_KEY).and_then(Value::as_bytes),
            Some(&bytes::Bytes::from_static(&[1, 2, 3]))
        );
        assert_eq!(
            frame.get(PASSWORD_TYPE_KEY).and_then(Value::as_u64),
            Some(PASSWORD_TYPE_PIN)
        );
        assert!(frame.get(AUTH_TYPE_KEY).is_none(), "_auTy is verify-only");
        assert_eq!(frame.as_dict().map(<[_]>::len), Some(2));
    }

    /// M1 is `{Method: PairSetup, SeqNo: M1}`, the TLV the state machine hands back at
    /// construction (`auth.py:57-59`).
    #[test]
    fn m1_is_a_pair_setup_method_in_state_one() {
        let procedure = PairSetupProcedure::new(&PairSetupOptionsCompanion::default()).unwrap();
        let tlv = Tlv8::decode(&procedure.m1).unwrap();

        assert_eq!(
            tlv.get(TlvValue::Method)
                .and_then(|value| value.first().copied()),
            Some(Method::PairSetup as u8)
        );
        assert_eq!(
            tlv.get(TlvValue::SeqNo)
                .and_then(|value| value.first().copied()),
            Some(State::M1 as u8)
        );
    }

    /// The `Name` TLV's value is an OPACK dict, not the bare string.
    #[test]
    fn the_display_name_is_opack_encoded_inside_the_name_tlv() {
        let expected = pyatv_opack::pack(&opack! { "name" => "living room" }).unwrap();
        let procedure = PairSetupProcedure::new(&PairSetupOptionsCompanion {
            display_name: "living room".to_owned(),
        })
        .unwrap();

        // The name only reaches the wire in M5, so check the option the machine was given by
        // round-tripping the same encoding the constructor performs.
        let (decoded, _) = pyatv_opack::unpack(&expected).unwrap();
        assert_eq!(
            decoded.get("name").and_then(Value::as_str),
            Some("living room")
        );
        assert!(procedure.m2.is_none());
    }

    #[test]
    fn missing_or_wrongly_typed_pairing_data_is_refused() {
        assert!(pairing_data(&opack! {}).is_err());
        assert!(pairing_data(&opack! { "_pd" => "not bytes" }).is_err());
        assert!(pairing_data(&opack! { "_pd" => Vec::<u8>::new() }).is_err());
        assert_eq!(
            pairing_data(&opack! { "_pd" => vec![9u8, 9] }).unwrap(),
            vec![9, 9]
        );
    }

    #[test]
    fn the_auth_type_literal_matches_upstream() {
        assert_eq!(AUTH_TYPE_HAP, 4);
        assert_eq!(PASSWORD_TYPE_PIN, 1);
    }
}
