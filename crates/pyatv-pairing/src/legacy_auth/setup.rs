//! Legacy AirPlay pair-setup: the three `/pair-setup-pin` messages.
//!
//! Port of `AirPlayLegacyPairSetupProcedure` (`pyatv/protocols/airplay/auth/legacy.py:25-81`) and
//! the `LegacySRPAuthHandler.step1..step3` methods it drives
//! (`pyatv/protocols/airplay/srp.py:151-195`).
//!
//! The flow, with the I/O left to the caller:
//!
//! 1. POST `/pair-pin-start` with an empty body; the device shows a PIN.
//! 2. POST [`LegacyPairSetup::step1_body`] → device replies with `pk` (`B`) and `salt`.
//! 3. POST [`LegacyPairSetup::step2_body`] → device replies with its SRP `proof`.
//! 4. POST [`LegacyPairSetup::step3_body`] → device replies with its own `epk`/`authTag`, which
//!    pyatv discards.
//! 5. [`LegacyPairSetup::finish`] hands back the credentials.
//!
//! Nothing about the device's identity is learned here. `finish_pairing` returns
//! `self.srp.credentials` (`pyatv/protocols/airplay/auth/legacy.py:69`), i.e. the locally generated
//! `(seed, client_id)` pair the procedure was constructed with: legacy pairing only proves the
//! controller to the device, so there is nothing new to persist.

use ed25519_dalek::SigningKey;
use plist::{Dictionary, Value};

use super::{
    SETUP_AES_IV_LABEL, SETUP_AES_KEY_LABEL, derive_aes_material, gcm_encrypt, increment_setup_iv,
    seed_from_ltsk,
};
use crate::{Error, HapCredentials, Result, srp_legacy::LegacySrpClient};

/// Value of the `method` key in the first pair-setup message
/// (`pyatv/protocols/airplay/auth/legacy.py:55`).
pub const PIN_METHOD: &str = "pin";

/// Drives the legacy AirPlay pair-setup exchange, bytes in and bytes out.
#[derive(Debug)]
pub struct LegacyPairSetup {
    credentials: HapCredentials,
    signing_key: SigningKey,
    /// The client identifier as uppercase hex, which is both the plist `user` value and the SRP
    /// username (`pyatv/protocols/airplay/auth/legacy.py:51-54`).
    client_id_hex: String,
    pin: Option<String>,
    srp: Option<LegacySrpClient>,
}

impl LegacyPairSetup {
    /// Start a pair-setup for a freshly generated legacy credential.
    ///
    /// `credentials` is what `new_credentials()` produces: an empty `ltpk`/`atv_id`, a 32-byte
    /// random `ltsk` seed and an 8-byte random `client_id`
    /// (`pyatv/protocols/airplay/srp.py:52-56`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyLength`] if `ltsk` is not 32 bytes.
    pub fn new(credentials: HapCredentials) -> Result<Self> {
        let seed = seed_from_ltsk(&credentials.ltsk)?;
        let client_id_hex = hex::encode_upper(&credentials.client_id);

        Ok(Self {
            credentials,
            signing_key: SigningKey::from_bytes(&seed),
            client_id_hex,
            pin: None,
            srp: None,
        })
    }

    /// The SRP username, which is the client identifier as uppercase hex.
    #[must_use]
    pub fn client_identifier(&self) -> &str {
        &self.client_id_hex
    }

    /// Body of the first `/pair-setup-pin` POST: `{method: "pin", user: <client id>}`.
    ///
    /// `pin` is already the string pyatv would pass, i.e. `str(pin).zfill(4)`
    /// (`pyatv/protocols/airplay/pairing.py:88-90`); it is stored for the proof step rather than
    /// used here.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedResponse`] if the property list cannot be serialised, which
    /// cannot happen for these fixed string fields.
    pub fn step1_body(&mut self, pin: &str) -> Result<Vec<u8>> {
        self.pin = Some(pin.to_owned());
        self.srp = Some(LegacySrpClient::new(
            self.client_id_hex.clone(),
            self.signing_key.to_bytes().as_slice(),
        ));

        encode_plist(&[
            ("method", Value::String(PIN_METHOD.to_owned())),
            ("user", Value::String(self.client_id_hex.clone())),
        ])
    }

    /// Body of the second POST: `{pk: A, proof: M1}`, derived from the device's `pk` and `salt`.
    ///
    /// `A` and `M1` go on the wire as `binascii.unhexlify(session.public)` and
    /// `binascii.unhexlify(session.key_proof)` (`pyatv/protocols/airplay/auth/legacy.py:61-64`),
    /// i.e. in `srptools`' shortest big-endian form; see [`crate::srp_legacy`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if [`LegacyPairSetup::step1_body`] has not run,
    /// [`Error::MalformedResponse`] if the device's reply is not a property list with `pk` and
    /// `salt` data entries, or [`Error::SrpPublicKey`] if `B` is degenerate.
    pub fn step2_body(&mut self, response: &[u8]) -> Result<Vec<u8>> {
        let (Some(srp), Some(pin)) = (self.srp.as_mut(), self.pin.as_deref()) else {
            return Err(Error::OutOfOrder("legacy pair-setup step 1 has not run"));
        };

        let body = decode_plist(response)?;
        let device_public = take_data(&body, "pk")?;
        let salt = take_data(&body, "salt")?;

        let proof = srp.process_challenge(pin, salt, device_public)?;

        encode_plist(&[
            ("pk", Value::Data(srp.public_key())),
            ("proof", Value::Data(proof)),
        ])
    }

    /// Body of the third POST: `{authTag: <GCM tag>, epk: <encrypted public key>}`.
    ///
    /// The device's SRP proof in `response` **is** checked here, in constant time. pyatv does not:
    /// `step2` compares `srptools`' own value against itself
    /// (`pyatv/protocols/airplay/srp.py:177-178`, `srptools/client.py:40-42`). See
    /// [`LegacySrpClient::verify_device_proof`] for the rationale.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if the previous step has not run,
    /// [`Error::MalformedResponse`] if the reply has no `proof` entry, [`Error::ProofMismatch`] if
    /// the proof is wrong, or [`Error::Aead`] if the GCM seal fails.
    pub fn step3_body(&mut self, response: &[u8]) -> Result<Vec<u8>> {
        let srp = self
            .srp
            .as_ref()
            .ok_or(Error::OutOfOrder("legacy pair-setup step 2 has not run"))?;

        let body = decode_plist(response)?;
        srp.verify_device_proof(take_data(&body, "proof")?)?;

        let session_key = srp
            .session_key()
            .ok_or(Error::OutOfOrder("legacy pair-setup step 2 has not run"))?;

        let key = derive_aes_material(SETUP_AES_KEY_LABEL, session_key);
        let iv = increment_setup_iv(derive_aes_material(SETUP_AES_IV_LABEL, session_key));
        let (epk, tag) = gcm_encrypt(&key, &iv, self.signing_key.verifying_key().as_bytes())?;

        encode_plist(&[
            ("authTag", Value::Data(tag.to_vec())),
            ("epk", Value::Data(epk)),
        ])
    }

    /// The credentials to persist.
    ///
    /// The device's final `{epk, authTag}` reply carries its own long-term public key, but pyatv
    /// never decrypts or stores it (`pyatv/protocols/airplay/auth/legacy.py:68-69`), so there is
    /// nothing to feed in here.
    #[must_use]
    pub fn finish(self) -> HapCredentials {
        self.credentials
    }
}

/// Serialise a flat property list, emitting keys in sorted order.
///
/// `plistlib.dumps(..., fmt=FMT_BINARY)` sorts keys by default, and the object table it writes is
/// root dictionary, then all keys, then all values. Emitting keys in the order given here
/// reproduces that byte for byte, which the known-answer tests rely on.
fn encode_plist(entries: &[(&str, Value)]) -> Result<Vec<u8>> {
    let mut sorted: Vec<&(&str, Value)> = entries.iter().collect();
    sorted.sort_by_key(|(key, _)| *key);

    let mut dictionary = Dictionary::new();
    for (key, value) in sorted {
        dictionary.insert((*key).to_owned(), value.clone());
    }

    let mut body = Vec::new();
    plist::to_writer_binary(&mut body, &Value::Dictionary(dictionary)).map_err(|error| {
        Error::MalformedResponse(format!("cannot encode property list: {error}"))
    })?;
    Ok(body)
}

/// Parse a device reply as a binary property list dictionary.
fn decode_plist(body: &[u8]) -> Result<Dictionary> {
    Value::from_reader(std::io::Cursor::new(body))
        .map_err(|error| Error::MalformedResponse(format!("cannot decode property list: {error}")))?
        .into_dictionary()
        .ok_or_else(|| Error::MalformedResponse("property list is not a dictionary".to_owned()))
}

/// Read a required data entry out of a device reply.
fn take_data<'a>(body: &'a Dictionary, key: &str) -> Result<&'a [u8]> {
    body.get(key)
        .and_then(Value::as_data)
        .ok_or_else(|| Error::MalformedResponse(format!("missing `{key}` data entry")))
}

#[cfg(test)]
mod tests {
    use super::{LegacyPairSetup, decode_plist, encode_plist, take_data};
    use crate::{HapCredentials, legacy_auth::tests_support as fixture};
    use plist::Value;

    fn setup() -> LegacyPairSetup {
        LegacyPairSetup::new(HapCredentials {
            ltpk: Vec::new(),
            ltsk: fixture::unhex(fixture::DEVICE_AUTH_KEY),
            atv_id: Vec::new(),
            client_id: fixture::unhex(fixture::DEVICE_IDENTIFIER_HEX),
        })
        .expect("credentials are well formed")
    }

    /// Known-answer test: the first request body must be `_DEVICE_AUTH_STEP1`
    /// (`tests/fake_device/airplay.py:27`) byte for byte, which also proves the property-list
    /// encoder agrees with `plistlib`.
    #[test]
    fn step1_body_matches_the_capture() {
        let body = setup().step1_body(fixture::DEVICE_PIN).expect("step 1");

        assert_eq!(hex::encode(&body), fixture::AUTH_STEP1);
    }

    /// Known-answer test: given the captured `_DEVICE_AUTH_STEP1_RESP`, the second request must be
    /// `_DEVICE_AUTH_STEP2` (`tests/fake_device/airplay.py:29-30`) byte for byte. This pins the
    /// whole legacy SRP profile — group, hash, doubled `K`, unpadded `H(g)` — at once.
    #[test]
    fn step2_body_matches_the_capture() {
        let mut procedure = setup();
        procedure.step1_body(fixture::DEVICE_PIN).expect("step 1");

        let body = procedure
            .step2_body(&fixture::unhex(fixture::AUTH_STEP1_RESP))
            .expect("step 2");

        assert_eq!(hex::encode(&body), fixture::AUTH_STEP2);
    }

    /// Known-answer test: given the captured device proof, the third request must be
    /// `_DEVICE_AUTH_STEP3` (`tests/fake_device/airplay.py:31-32`) byte for byte. This pins the
    /// SHA-512 key/IV derivation, the last-byte IV increment and AES-128-GCM with a 16-byte IV.
    #[test]
    fn step3_body_matches_the_capture() {
        let mut procedure = setup();
        procedure.step1_body(fixture::DEVICE_PIN).expect("step 1");
        procedure
            .step2_body(&fixture::unhex(fixture::AUTH_STEP1_RESP))
            .expect("step 2");

        let body = procedure
            .step3_body(&fixture::unhex(fixture::AUTH_STEP2_RESP))
            .expect("step 3");

        assert_eq!(hex::encode(&body), fixture::AUTH_STEP3);
    }

    /// The credentials handed back are the ones passed in; legacy pairing learns nothing about the
    /// device.
    #[test]
    fn finish_returns_the_original_credentials() {
        let procedure = setup();
        let expected = fixture::unhex(fixture::DEVICE_AUTH_KEY);

        assert_eq!(procedure.finish().ltsk, expected);
    }

    /// A wrong PIN changes `M1`, so the device rejects the exchange; the client's own bytes must
    /// change too, which is what makes the capture a real test rather than a replay.
    #[test]
    fn a_wrong_pin_changes_the_proof_request() {
        let mut procedure = setup();
        procedure.step1_body("0000").expect("step 1");

        let body = procedure
            .step2_body(&fixture::unhex(fixture::AUTH_STEP1_RESP))
            .expect("step 2");

        assert_ne!(hex::encode(&body), fixture::AUTH_STEP2);
    }

    /// A device proof that does not match must be rejected rather than ignored, which is the
    /// documented deviation from pyatv.
    #[test]
    fn a_bad_device_proof_is_rejected() {
        let mut procedure = setup();
        procedure.step1_body(fixture::DEVICE_PIN).expect("step 1");
        procedure
            .step2_body(&fixture::unhex(fixture::AUTH_STEP1_RESP))
            .expect("step 2");

        let forged = encode_plist(&[("proof", Value::Data(vec![0u8; 20]))]).expect("encode");

        assert!(procedure.step3_body(&forged).is_err());
    }

    /// Steps must not be skipped.
    #[test]
    fn steps_out_of_order_are_refused() {
        let mut procedure = setup();

        assert!(procedure.step2_body(b"").is_err());
        assert!(procedure.step3_body(b"").is_err());
    }

    /// A reply that is not a property list, or is missing a field, must surface as an error rather
    /// than a panic.
    #[test]
    fn malformed_replies_are_refused() {
        let mut procedure = setup();
        procedure.step1_body(fixture::DEVICE_PIN).expect("step 1");

        assert!(procedure.step2_body(b"not a plist").is_err());

        let incomplete = encode_plist(&[("pk", Value::Data(vec![1, 2, 3]))]).expect("encode");
        assert!(procedure.step2_body(&incomplete).is_err());
    }

    /// The encoder sorts keys, so declaration order at the call site cannot change the wire bytes.
    #[test]
    fn plist_keys_are_emitted_in_sorted_order() {
        let unsorted = encode_plist(&[
            ("user", Value::String("b".to_owned())),
            ("method", Value::String("a".to_owned())),
        ])
        .expect("encode");
        let sorted = encode_plist(&[
            ("method", Value::String("a".to_owned())),
            ("user", Value::String("b".to_owned())),
        ])
        .expect("encode");

        assert_eq!(unsorted, sorted);

        let decoded = decode_plist(&sorted).expect("decode");
        assert_eq!(decoded.len(), 2);
        assert!(take_data(&decoded, "method").is_err());
    }
}
