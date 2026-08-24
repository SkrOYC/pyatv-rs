//! Pair-setup M1 through M6: SRP over a PIN, ending in persistable credentials.
//!
//! Ported from `SRPAuthHandler.step1`–`step4` (`pyatv/auth/hap_srp.py:138-233`) driven by
//! `MrpPairSetupProcedure` (`pyatv/protocols/mrp/auth.py:26-82`); Companion and AirPlay drive the
//! identical sequence with different framing.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Error, HapCredentials, Result,
    hkdf_derive::{expand, pairing as salts},
    srp_hap::{
        HapSrpClient, PAIR_SETUP_M5_NONCE, PAIR_SETUP_M6_NONCE, ed25519_public_key, open,
        random_seed, seal, sign, verify_signature,
    },
    tlv8::{Method, State, Tlv8, TlvValue},
};

use super::{decode_response, random_pairing_id, require_owned};

/// Which message the machine is waiting for.
///
/// pyatv has no equivalent: `MrpPairSetupProcedure` infers its position from which coroutine the
/// caller happens to await next (`pyatv/protocols/mrp/auth.py:26-82`), so replaying an M2 or an M4
/// there quietly restarts or re-runs a step. Making the position explicit means a device (or a
/// MITM) that re-sends a message gets [`Error::OutOfOrder`] instead of a second SRP exchange keyed
/// on the same ephemeral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// M1 has been produced; the device must answer with M2.
    AwaitingM2,
    /// M3 has been produced; the device must answer with M4.
    AwaitingM4,
    /// M5 has been produced; the device must answer with M6.
    AwaitingM6,
    /// M6 has been accepted and credentials handed back.
    Complete,
}

/// Everything a caller can vary about a pair-setup run.
#[derive(Clone, Default)]
pub struct PairSetupOptions {
    /// The PIN shown on the device. May be supplied later with [`PairSetup::set_pin`], because the
    /// device only displays it in response to M1.
    pub pin: Option<u32>,

    /// The optional `Name` TLV for M5, **already OPACK-encoded**.
    ///
    /// pyatv stores `opack.pack({"name": name})` there rather than the bare string
    /// (`pyatv/auth/hap_srp.py:193-196`) — this is the one TLV value in the whole handshake that is
    /// itself a structured blob. It is passed in pre-encoded so that this crate does not depend on
    /// `pyatv-opack`. MRP never sends it (`pyatv/protocols/mrp/pairing.py:63` passes `None`);
    /// Companion and AirPlay always do.
    pub name: Option<Vec<u8>>,

    /// Extra raw TLV entries merged into the M5 inner payload after the mandatory ones.
    ///
    /// Present for parity with `step3`'s `additional_data` parameter
    /// (`pyatv/auth/hap_srp.py:197-198`), which no pyatv call site ever populates. Entries here can
    /// overwrite `Identifier`/`PublicKey`/`Signature`/`Name`, exactly as `dict.update` would.
    pub additional_data: Vec<(u8, Vec<u8>)>,
}

// Hand-written so that logging a caller's options cannot print the PIN. Whether a name and extra
// tags are present is useful in a log; their contents are the caller's business.
impl std::fmt::Debug for PairSetupOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairSetupOptions")
            .field(
                "pin",
                if self.pin.is_some() {
                    &"<set>"
                } else {
                    &"None"
                },
            )
            .field("name", &self.name.is_some())
            .field(
                "additional_tags",
                &self
                    .additional_data
                    .iter()
                    .map(|(tag, _)| *tag)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// The controller half of HAP pair-setup, as a sans-io state machine.
///
/// Drive it in order: [`PairSetup::start`], [`PairSetup::handle_m2`], [`PairSetup::handle_m4`],
/// [`PairSetup::handle_m6`]. Each `handle_*` takes the TLV8 body the device sent and returns the
/// TLV8 body to send next, except the last, which returns the credentials to persist. Taking a step
/// out of that order — including replaying one the device already answered — is
/// [`Error::OutOfOrder`], never a panic and never a silent restart.
///
/// ```
/// use pyatv_pairing::{Error, PairSetup};
///
/// // M1 exists the moment the machine does; send it and wait for the device's M2.
/// let (mut setup, m1) = PairSetup::start(None);
/// assert!(!m1.is_empty());
///
/// // The device only shows its PIN in response to M1, so it is supplied afterwards.
/// setup.set_pin(1111);
///
/// // From here it is strictly M2 -> M3, M4 -> M5, M6 -> credentials. Anything else is refused
/// // before a byte of crypto runs.
/// assert!(matches!(setup.handle_m4(&[]), Err(Error::OutOfOrder(_))));
/// assert!(matches!(setup.handle_m6(&[]), Err(Error::OutOfOrder(_))));
/// ```
pub struct PairSetup {
    options: PairSetupOptions,
    /// The controller's long-term Ed25519 seed, which is *also* the SRP ephemeral secret `a`.
    seed: [u8; 32],
    /// The controller's pairing identifier, persisted as `client_id`.
    client_id: Vec<u8>,
    srp: Option<HapSrpClient>,
    /// `Pair-Setup-Encrypt` key, derived in M4 and reused to open M6.
    setup_encrypt_key: Option<[u8; 32]>,
    phase: Phase,
}

// Hand-written: the derived `Debug` would print the controller's long-term Ed25519 seed — which is
// also the SRP exponent `a` and ends up persisted as `ltsk` — and the `Pair-Setup-Encrypt` key that
// opens M6. `options` is redacted wholesale because it carries the PIN.
impl std::fmt::Debug for PairSetup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairSetup")
            .field("phase", &self.phase)
            .field("seed", &"<redacted>")
            .field("setup_encrypt_key", &"<redacted>")
            .field("pin", &"<redacted>")
            .field("client_id", &hex::encode(&self.client_id))
            .field("name", &self.options.name.is_some())
            .field("additional_tags", &self.options.additional_data.len())
            .finish_non_exhaustive()
    }
}

// `Zeroize` is deliberately not implemented: a public `zeroize()` on a live state machine is a
// footgun, since the caller could wipe the seed and keep driving the exchange. Only the drop
// behaviour is exposed, through the `ZeroizeOnDrop` marker.
impl Drop for PairSetup {
    fn drop(&mut self) {
        self.seed.zeroize();
        if let Some(key) = self.setup_encrypt_key.as_mut() {
            key.zeroize();
        }
        // `options.pin` is a `u32` on the stack; clear it rather than leave the PIN behind.
        self.options.pin = None;
        // `HapSrpClient` wipes its own PIN, exponent and session key when it drops.
        self.srp = None;
    }
}

impl ZeroizeOnDrop for PairSetup {}

impl PairSetup {
    /// Begin pairing, returning the machine and the M1 TLV to send.
    ///
    /// A fresh Ed25519 seed and pairing identifier are generated from the OS CSPRNG. Pass `None`
    /// for `pin` when the device has not shown it yet and call [`PairSetup::set_pin`] before
    /// [`PairSetup::handle_m2`], which is the order every pyatv pairing handler uses.
    #[must_use]
    pub fn start(pin: Option<u32>) -> (Self, Vec<u8>) {
        Self::start_with(
            PairSetupOptions {
                pin,
                ..PairSetupOptions::default()
            },
            random_seed(),
            random_pairing_id(),
        )
    }

    /// Begin pairing with caller-chosen options and identity material.
    ///
    /// Supplying the seed and identifier explicitly is what makes the pairing flow reproducible in
    /// tests; production callers should prefer [`PairSetup::start`].
    #[must_use]
    pub fn start_with(
        options: PairSetupOptions,
        seed: [u8; 32],
        client_id: Vec<u8>,
    ) -> (Self, Vec<u8>) {
        let request = Tlv8::new()
            .with_byte(TlvValue::Method, Method::PairSetup as u8)
            .with_byte(TlvValue::SeqNo, State::M1 as u8)
            .encode()
            .to_vec();

        let setup = Self {
            options,
            seed,
            client_id,
            srp: None,
            setup_encrypt_key: None,
            phase: Phase::AwaitingM2,
        };

        (setup, request)
    }

    /// Supply the PIN the device displayed after M1.
    pub fn set_pin(&mut self, pin: u32) {
        self.options.pin = Some(pin);
    }

    /// The controller's pairing identifier, which ends up in the credentials as `client_id`.
    #[must_use]
    pub fn client_id(&self) -> &[u8] {
        &self.client_id
    }

    /// Consume M2 (`Salt` and the accessory's `B`) and produce M3.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if M2 has already been handled, [`Error::MissingPin`] if no
    /// PIN has been supplied, [`Error::HapError`] if the device refused,
    /// [`Error::UnexpectedState`] on a state mismatch, [`Error::MissingTlv`] if `Salt` or
    /// `PublicKey` is absent, and [`Error::SrpPublicKey`] if `B` is out of range or `B mod N == 0`.
    pub fn handle_m2(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.phase != Phase::AwaitingM2 {
            return Err(Error::OutOfOrder("pair-setup M2 has already been handled"));
        }

        let response = decode_response(payload, State::M2)?;
        let salt = require_owned(&response, TlvValue::Salt)?;
        let device_public_key = require_owned(&response, TlvValue::PublicKey)?;

        let pin = self.options.pin.ok_or(Error::MissingPin)?;
        let mut srp = HapSrpClient::new(pin, self.seed);
        let proof = srp.process_challenge(&salt, &device_public_key)?;

        let request = Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M3 as u8)
            .with(TlvValue::PublicKey, srp.public_key().to_vec())
            .with(TlvValue::Proof, proof)
            .encode()
            .to_vec();

        self.srp = Some(srp);
        self.phase = Phase::AwaitingM4;
        Ok(request)
    }

    /// Verify the accessory's M4 proof and produce the encrypted M5 identity payload.
    ///
    /// Unlike pyatv this really does check the accessory's SRP proof; see the
    /// [module documentation](super) for why.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if M2 has not been handled, [`Error::HapError`] with
    /// [`ErrorCode::Authentication`](crate::tlv8::ErrorCode::Authentication) when the PIN was
    /// wrong, [`Error::ProofMismatch`] if the accessory's proof does not match, and
    /// [`Error::Aead`] if the outgoing payload cannot be sealed.
    pub fn handle_m4(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        match self.phase {
            Phase::AwaitingM4 => {}
            Phase::AwaitingM2 => {
                return Err(Error::OutOfOrder("pair-setup M2 has not been handled"));
            }
            Phase::AwaitingM6 | Phase::Complete => {
                return Err(Error::OutOfOrder("pair-setup M4 has already been handled"));
            }
        }

        let srp = self
            .srp
            .as_ref()
            .ok_or(Error::OutOfOrder("pair-setup M2 has not been handled"))?;

        let response = decode_response(payload, State::M4)?;
        srp.verify_device_proof(&require_owned(&response, TlvValue::Proof)?)?;

        let session_key = srp
            .session_key()
            .ok_or(Error::OutOfOrder("SRP session key is not available"))?;

        // Both derivations take the SRP session key `K` as IKM (`pyatv/auth/hap_srp.py:165-181`).
        let controller_x = expand(
            salts::CONTROLLER_SIGN_SALT,
            salts::CONTROLLER_SIGN_INFO,
            session_key,
        )?;
        let setup_encrypt_key = expand(
            salts::SETUP_ENCRYPT_SALT,
            salts::SETUP_ENCRYPT_INFO,
            session_key,
        )?;

        // iOSDeviceX | iOSDevicePairingID | iOSDeviceLTPK, in that order (`hap_srp.py:183`).
        let public_key = ed25519_public_key(&self.seed);
        let mut signed = Vec::with_capacity(controller_x.len() + self.client_id.len() + 32);
        signed.extend_from_slice(&controller_x);
        signed.extend_from_slice(&self.client_id);
        signed.extend_from_slice(&public_key);

        let mut inner = Tlv8::new()
            .with(TlvValue::Identifier, self.client_id.clone())
            .with(TlvValue::PublicKey, public_key.to_vec())
            .with(TlvValue::Signature, sign(&self.seed, &signed).to_vec());

        if let Some(name) = &self.options.name {
            inner = inner.with(TlvValue::Name, name.clone());
        }
        for (tag, value) in &self.options.additional_data {
            inner = inner.with_raw(*tag, value.clone());
        }

        let encrypted = seal(&setup_encrypt_key, PAIR_SETUP_M5_NONCE, &inner.encode())?;
        self.setup_encrypt_key = Some(setup_encrypt_key);
        self.phase = Phase::AwaitingM6;

        Ok(Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M5 as u8)
            .with(TlvValue::EncryptedData, encrypted)
            .encode()
            .to_vec())
    }

    /// Consume M6 and return the credentials to persist.
    ///
    /// The accessory's signature over `AccessoryX | AccessoryPairingID | AccessoryLTPK` is verified
    /// here. pyatv does not do this — `pyatv/auth/hap_srp.py:229` is a `# TODO` — which means a
    /// device that decrypts M6 correctly but signs nonsense is accepted upstream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if M4 has not been handled, [`Error::Aead`] if the payload
    /// does not decrypt, [`Error::MissingTlv`] if the inner TLV is incomplete, and
    /// [`Error::SetupSignature`] if the accessory's signature does not verify.
    pub fn handle_m6(&mut self, payload: &[u8]) -> Result<HapCredentials> {
        match self.phase {
            Phase::AwaitingM6 => {}
            Phase::AwaitingM2 | Phase::AwaitingM4 => {
                return Err(Error::OutOfOrder("pair-setup M4 has not been handled"));
            }
            Phase::Complete => return Err(Error::OutOfOrder("pair-setup is already complete")),
        }

        let setup_encrypt_key = self
            .setup_encrypt_key
            .ok_or(Error::OutOfOrder("pair-setup M4 has not been handled"))?;
        let session_key = self
            .srp
            .as_ref()
            .and_then(HapSrpClient::session_key)
            .ok_or(Error::OutOfOrder("SRP session key is not available"))?;

        let response = decode_response(payload, State::M6)?;
        let encrypted = require_owned(&response, TlvValue::EncryptedData)?;
        let inner = Tlv8::decode(&open(&setup_encrypt_key, PAIR_SETUP_M6_NONCE, &encrypted)?)?;

        let atv_id = require_owned(&inner, TlvValue::Identifier)?;
        let atv_ltpk = require_owned(&inner, TlvValue::PublicKey)?;
        let signature = require_owned(&inner, TlvValue::Signature)?;

        let accessory_x = expand(
            salts::ACCESSORY_SIGN_SALT,
            salts::ACCESSORY_SIGN_INFO,
            session_key,
        )?;
        let mut signed = Vec::with_capacity(accessory_x.len() + atv_id.len() + atv_ltpk.len());
        signed.extend_from_slice(&accessory_x);
        signed.extend_from_slice(&atv_id);
        signed.extend_from_slice(&atv_ltpk);

        if !verify_signature(&atv_ltpk, &signed, &signature) {
            return Err(Error::SetupSignature);
        }

        self.phase = Phase::Complete;

        // Field order is (ltpk, ltsk, atv_id, client_id): the *accessory's* public key next to the
        // *controller's* private one (`pyatv/auth/hap_srp.py:231-233`).
        Ok(HapCredentials {
            ltpk: atv_ltpk.to_vec(),
            ltsk: self.seed.to_vec(),
            atv_id: atv_id.to_vec(),
            client_id: self.client_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
