//! A reference accessory, for hermetic tests only. Enabled by the `test-server` feature.
//!
//! This is a port of `pyatv/auth/server_auth.py` plus the pair-setup/pair-verify handlers the three
//! `pyatv/protocols/*/server_auth.py` files share (`mrp/server_auth.py:29-239` is the copy this was
//! written from; the Companion and AirPlay copies differ only in framing and in the transient
//! branch). It exists so the client state machines in [`crate::pairing`] can be driven end to end
//! with no device, no sockets and no captured traffic, using the same fixed key material pyatv's
//! own test suite uses.
//!
//! Like pyatv's, it takes TLV8 in and gives TLV8 out; the protocol crates' framing is out of scope.
//!
//! # This is not production accessory code
//!
//! The accessory's Ed25519 identity **and** its per-session X25519 "ephemeral" are the same fixed
//! 32 bytes, reinterpreted (`generate_keys`, `mrp/server_auth.py:29-45`). That makes every test run
//! deterministic and gives pair-verify no forward secrecy whatsoever. It is replicated exactly
//! because the fixed material is what makes `CLIENT_CREDENTIALS` a usable known-answer anchor
//! (`docs/research/hap-pairing-port-spec.md` §6, §8).
//!
//! # Where it is stricter than pyatv's
//!
//! pyatv's reference accessory never verifies the controller's M5 signature and never verifies the
//! controller's pair-verify M3 signature. This one does both, so that a client-side regression that
//! produces a well-formed but wrongly-signed payload fails a test instead of passing one.

use sha2::Sha512;
use srp::{Client, Server, groups::G3072};

use crate::{
    Error, Result,
    hkdf_derive::expand,
    pairing::SessionKeys,
    srp_hap::ed25519_public_key,
    tlv8::{ErrorCode, State, Tlv8, TlvValue},
};

/// Default PIN of the MRP and Companion reference accessories (`pyatv/auth/server_auth.py:1`).
pub const PIN_CODE: u32 = 1111;
/// PIN the AirPlay fake device overrides to (`tests/fake_device/airplay.py:22`).
pub const AIRPLAY_PIN: u32 = 2271;
/// Controller identifier baked into [`CLIENT_CREDENTIALS`] (`pyatv/auth/server_auth.py:2`).
pub const CLIENT_IDENTIFIER: &str = "4D797FD3-3538-427E-A47B-A32FC6CF3A6A";
/// Accessory identifier (`pyatv/auth/server_auth.py:11`).
pub const SERVER_IDENTIFIER: &str = "5D797FD3-3538-427E-A47B-A32FC6CF3A6A";
/// The accessory's fixed seed, used as both an Ed25519 seed and an X25519 scalar.
pub const PRIVATE_KEY: [u8; 32] = [0xAA; 32];

/// Credentials a controller would persist after pairing once with this accessory.
///
/// Verbatim from `pyatv/auth/server_auth.py:3-10`, lowercased. The `ltpk` field is exactly
/// `Ed25519(PRIVATE_KEY).public_key()`, and the last two fields are `SERVER_IDENTIFIER` and
/// `CLIENT_IDENTIFIER` as ASCII — see `docs/research/hap-pairing-port-spec.md` §8, which verified
/// all three independently.
pub const CLIENT_CREDENTIALS: &str = concat!(
    "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58:",
    "80fd8265b0748da90bc5c5294dabe394d3d47199994ae96ac73ee45c783537b1:",
    "35443739374644332d333533382d343237452d413437422d413332464336434633413641:",
    "34443739374644332d333533382d343237452d413437422d413332464336434633413641"
);

/// The transient pairing PIN the accessory substitutes when M1 sets the transient flag.
const TRANSIENT_PIN: u32 = crate::pairing::TRANSIENT_PIN;

mod setup;
mod verify;

type HapServer = Server<G3072, Sha512>;
type HapClient = Client<G3072, Sha512>;

/// Per-attempt pair-setup state.
#[derive(Debug)]
struct SetupSession {
    salt: [u8; 16],
    verifier: Vec<u8>,
    transient: bool,
    /// SRP session key `K`, present once M3 has been accepted.
    session_key: Option<Vec<u8>>,
}

/// A pairing this accessory has accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    /// The controller's pairing identifier.
    pub client_id: Vec<u8>,
    /// The controller's long-term Ed25519 public key.
    pub ltpk: Vec<u8>,
}

/// A HAP accessory that speaks pair-setup and pair-verify over raw TLV8.
#[derive(Debug)]
pub struct ReferenceAccessory {
    identifier: Vec<u8>,
    pin: u32,
    seed: [u8; 32],
    /// Normally the same as `seed`; differs only under [`ReferenceAccessory::corrupt_signatures`].
    signing_seed: [u8; 32],
    setup: Option<SetupSession>,
    pairings: Vec<Pairing>,
    shared_secret: Option<Vec<u8>>,
    /// The controller ephemeral key from pair-verify M1, needed to check its M3 signature.
    client_ephemeral: Option<Vec<u8>>,
}

impl Default for ReferenceAccessory {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferenceAccessory {
    /// An accessory with pyatv's default identity and PIN.
    #[must_use]
    pub fn new() -> Self {
        Self::with_pin(PIN_CODE)
    }

    /// An accessory with pyatv's default identity and a chosen PIN.
    #[must_use]
    pub fn with_pin(pin: u32) -> Self {
        Self {
            identifier: SERVER_IDENTIFIER.as_bytes().to_vec(),
            pin,
            seed: PRIVATE_KEY,
            signing_seed: PRIVATE_KEY,
            setup: None,
            pairings: Vec::new(),
            shared_secret: None,
            client_ephemeral: None,
        }
    }

    /// Pre-register a pairing, so pair-verify can run without a preceding pair-setup.
    ///
    /// This is what makes the [`CLIENT_CREDENTIALS`] anchor usable on its own: the controller's
    /// `ltpk` is the public half of that string's `ltsk` field.
    pub fn register_pairing(&mut self, client_id: &[u8], ltpk: &[u8]) {
        self.pairings.push(Pairing {
            client_id: client_id.to_vec(),
            ltpk: ltpk.to_vec(),
        });
    }

    /// Pairings accepted so far.
    #[must_use]
    pub fn pairings(&self) -> &[Pairing] {
        &self.pairings
    }

    /// Make the accessory sign with the wrong key while still advertising the right public one.
    ///
    /// Fault injection, for the tests that prove this port rejects what pyatv would accept: pyatv
    /// never checks the pair-setup M6 signature at all (`pyatv/auth/hap_srp.py:229`), so a device
    /// behaving like this is indistinguishable from an honest one upstream.
    pub fn corrupt_signatures(&mut self, corrupt: bool) {
        self.signing_seed = if corrupt { [0x00; 32] } else { self.seed };
    }

    /// The accessory's identifier, as it appears in the `Identifier` TLV.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }

    /// The accessory's long-term Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        ed25519_public_key(&self.seed)
    }

    /// Derive one channel's transport keys from the last completed exchange.
    ///
    /// The role swap is the caller's problem, exactly as it is in pyatv: pass the info strings in
    /// whichever order the protocol expects for the accessory side
    /// (`docs/research/hap-pairing-port-spec.md` §4.3).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if no exchange has completed.
    pub fn encryption_keys(
        &self,
        salt: &str,
        output_info: &str,
        input_info: &str,
    ) -> Result<SessionKeys> {
        let shared_secret = self
            .shared_secret
            .as_deref()
            .ok_or(Error::OutOfOrder("no exchange has completed"))?;

        Ok(SessionKeys {
            shared_secret: shared_secret.to_vec(),
            output_key: expand(salt, output_info, shared_secret)?,
            input_key: expand(salt, input_info, shared_secret)?,
        })
    }

    /// Handle one pair-setup message and return the response TLV.
    ///
    /// # Errors
    ///
    /// Returns an error only for malformed input or an internal inconsistency. A wrong PIN is a
    /// protocol outcome, not an error: it comes back as a `{SeqNo: 4, Error: Authentication}` TLV,
    /// which is what a real accessory sends and what the client must be able to parse.
    pub fn handle_pair_setup(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let request = Tlv8::decode(payload)?;
        match state_of(&request)? {
            State::M1 => Ok(self.setup_m1(&request)),
            State::M3 => self.setup_m3(&request),
            State::M5 => self.setup_m5(&request),
            other => Err(Error::UnexpectedState {
                expected: State::M1 as u8,
                actual: other as u8,
            }),
        }
    }

    /// Handle one pair-verify message and return the response TLV.
    ///
    /// # Errors
    ///
    /// As [`ReferenceAccessory::handle_pair_setup`]; a controller that fails to authenticate gets
    /// an error TLV rather than an `Err`.
    pub fn handle_pair_verify(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let request = Tlv8::decode(payload)?;
        match state_of(&request)? {
            State::M1 => self.verify_m1(&request),
            State::M3 => self.verify_m3(&request),
            other => Err(Error::UnexpectedState {
                expected: State::M1 as u8,
                actual: other as u8,
            }),
        }
    }
}

/// Read the `SeqNo` TLV as a [`State`].
fn state_of(tlv: &Tlv8) -> Result<State> {
    let value = tlv
        .get(TlvValue::SeqNo)
        .and_then(|value| value.first())
        .copied()
        .ok_or(Error::MissingTlv(TlvValue::SeqNo))?;

    match value {
        1 => Ok(State::M1),
        2 => Ok(State::M2),
        3 => Ok(State::M3),
        4 => Ok(State::M4),
        5 => Ok(State::M5),
        6 => Ok(State::M6),
        other => Err(Error::MalformedResponse(format!(
            "unknown pairing state {other}"
        ))),
    }
}

/// An accessory rejection: the state it would have replied with, plus the error code.
fn error_response(state: State, code: ErrorCode) -> Vec<u8> {
    Tlv8::new()
        .with_byte(TlvValue::SeqNo, state as u8)
        .with_byte(TlvValue::Error, code as u8)
        .encode()
        .to_vec()
}

/// Concatenate signing inputs, whose field order is load-bearing everywhere it appears.
fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}
