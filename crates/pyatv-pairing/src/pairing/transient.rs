//! Transient AirPlay pairing: pair-setup M1–M4 only, no persisted identity.
//!
//! Ported from `AirPlayHapTransientPairVerifyProcedure`
//! (`pyatv/protocols/airplay/auth/hap_transient.py:33-99`). Its own docstring explains the shape:
//! transient pairing *is* the first four states of pair-setup, with no M5/M6 and no separate
//! pair-verify round at all, so pyatv files it under "verify" purely because that fits its class
//! hierarchy.
//!
//! Two properties make this materially different from every other flow and neither can be
//! generalised away (`docs/research/hap-pairing-port-spec.md` §4.4):
//!
//! - **The transport keys come from the SRP session key `K`**, not from an X25519 ECDH output,
//!   because no ECDH ever happens (`hap_transient.py:91-99`).
//! - **M1 carries a `Flags` TLV** with `TransientPairing` (`0x10`), the only place in all of pyatv
//!   that tag is ever written (`hap_transient.py:51-57`).
//!
//! The PIN is the fixed constant [`TRANSIENT_PIN`]; nothing is ever displayed or typed.
//!
//! This path has **no test coverage in pyatv at all** (`hap-pairing-port-spec.md` §11 finding 7) and
//! no captured traffic to check against, so the round trip in `tests/hap_pairing.rs` proves only
//! that this port agrees with its own reference accessory.

use crate::{
    Error, Result,
    hkdf_derive::expand,
    srp_hap::HapSrpClient,
    tlv8::{FLAG_TRANSIENT_PAIRING, Method, State, Tlv8, TlvValue},
};

use super::{SessionKeys, decode_response, require_owned};

/// The fixed PIN transient pairing uses (`pyatv/protocols/airplay/auth/hap_transient.py:30`).
pub const TRANSIENT_PIN: u32 = 3939;

/// The controller half of transient pair-setup, as a sans-io state machine.
///
/// Drive it in order: [`TransientPairSetup::start`], [`TransientPairSetup::handle_m2`],
/// [`TransientPairSetup::handle_m4`], then [`TransientPairSetup::encryption_keys`].
#[derive(Debug)]
pub struct TransientPairSetup {
    srp: HapSrpClient,
    verified: bool,
}

impl TransientPairSetup {
    /// Begin transient pairing, returning the machine and the M1 TLV to send.
    ///
    /// The ephemeral secret is generated from the OS CSPRNG. There is no long-term identity here:
    /// the same bytes serve as the SRP exponent `a` and nothing else, because no Ed25519 signature
    /// is ever exchanged.
    #[must_use]
    pub fn start() -> (Self, Vec<u8>) {
        Self::start_with(crate::srp_hap::random_seed())
    }

    /// Begin transient pairing with a caller-chosen ephemeral secret, for reproducible tests.
    #[must_use]
    pub fn start_with(ephemeral_secret: [u8; 32]) -> (Self, Vec<u8>) {
        let request = Tlv8::new()
            .with_byte(TlvValue::Method, Method::PairSetup as u8)
            .with_byte(TlvValue::SeqNo, State::M1 as u8)
            .with_byte(TlvValue::Flags, FLAG_TRANSIENT_PAIRING)
            .encode()
            .to_vec();

        let setup = Self {
            srp: HapSrpClient::new(TRANSIENT_PIN, ephemeral_secret),
            verified: false,
        };

        (setup, request)
    }

    /// Consume M2 (`Salt` and `B`) and produce M3.
    ///
    /// # Errors
    ///
    /// As [`super::PairSetup::handle_m2`], minus the PIN case: the PIN is fixed.
    pub fn handle_m2(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let response = decode_response(payload, State::M2)?;
        let salt = require_owned(&response, TlvValue::Salt)?;
        let device_public_key = require_owned(&response, TlvValue::PublicKey)?;

        let proof = self.srp.process_challenge(&salt, &device_public_key)?;

        Ok(Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M3 as u8)
            .with(TlvValue::PublicKey, self.srp.public_key().to_vec())
            .with(TlvValue::Proof, proof)
            .encode()
            .to_vec())
    }

    /// Verify the accessory's M4 proof, completing the exchange.
    ///
    /// pyatv does not read this response at all: `verify_credentials` posts M3 and returns `True`
    /// without looking at the reply (`hap_transient.py:78-82`), so a device that rejects the fixed
    /// PIN is indistinguishable there from one that accepted it until the first encrypted frame
    /// fails. This port checks the state, the error TLV and the SRP proof.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HapError`] if the device refused, [`Error::UnexpectedState`] on a state
    /// mismatch and [`Error::ProofMismatch`] if the accessory's proof does not match.
    pub fn handle_m4(&mut self, payload: &[u8]) -> Result<()> {
        let response = decode_response(payload, State::M4)?;
        self.srp
            .verify_device_proof(&require_owned(&response, TlvValue::Proof)?)?;
        self.verified = true;

        Ok(())
    }

    /// Derive one channel's transport keys from the SRP session key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if the exchange has not completed.
    pub fn encryption_keys(
        &self,
        salt: &str,
        output_info: &str,
        input_info: &str,
    ) -> Result<SessionKeys> {
        if !self.verified {
            return Err(Error::OutOfOrder("transient pair-setup has not completed"));
        }
        let shared_secret = self
            .srp
            .session_key()
            .ok_or(Error::OutOfOrder("SRP session key is not available"))?;

        Ok(SessionKeys {
            shared_secret: shared_secret.to_vec(),
            output_key: expand(salt, output_info, shared_secret)?,
            input_key: expand(salt, input_info, shared_secret)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::TransientPairSetup;
    use crate::{
        Error,
        tlv8::{FLAG_TRANSIENT_PAIRING, State, Tlv8, TlvValue},
    };

    #[test]
    fn m1_sets_the_transient_flag() {
        let (_, request) = TransientPairSetup::start();
        let tlv = Tlv8::decode(&request).unwrap();

        assert_eq!(
            tlv.get(TlvValue::Flags).map(|value| value[0]),
            Some(FLAG_TRANSIENT_PAIRING)
        );
        assert_eq!(
            tlv.get(TlvValue::SeqNo).map(|value| value[0]),
            Some(State::M1 as u8)
        );
    }

    #[test]
    fn keys_are_refused_before_the_exchange_completes() {
        let (setup, _) = TransientPairSetup::start();
        assert!(matches!(
            setup.encryption_keys("Control-Salt", "out", "in"),
            Err(Error::OutOfOrder(_))
        ));
    }

    #[test]
    fn a_device_error_in_m4_is_surfaced() {
        let (mut setup, _) = TransientPairSetup::start();
        let m4 = Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M4 as u8)
            .with_byte(TlvValue::Error, 0x02)
            .encode();

        assert!(matches!(setup.handle_m4(&m4), Err(Error::HapError { .. })));
    }
}
