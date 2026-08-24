//! Pair-verify M1 through M4: prove both stored identities and derive transport keys.
//!
//! Ported from `SRPAuthHandler.verify1`/`verify2` (`pyatv/auth/hap_srp.py:84-136`) driven by
//! `MrpPairVerifyProcedure` (`pyatv/protocols/mrp/auth.py:85-122`).
//!
//! Unlike pair-setup this exchange has no SRP and no PIN: it is an X25519 ECDH plus two Ed25519
//! signatures over the two ephemeral public keys, and its whole point is the shared secret that
//! [`PairVerify::encryption_keys`] turns into per-channel transport keys.

use crate::{
    Error, HapCredentials, Result,
    hkdf_derive::{KEY_LEN, expand, pairing as salts},
    srp_hap::{
        EphemeralExchange, PAIR_VERIFY_M2_NONCE, PAIR_VERIFY_M3_NONCE, X25519_LEN, open, seal,
        sign, verify_signature,
    },
    tlv8::{State, Tlv8, TlvValue},
};

use super::{decode_response, require_owned};

/// The transport keys one channel needs, plus the secret they came from.
///
/// `output_key` encrypts what this side sends and `input_key` decrypts what it receives; which
/// HKDF info string maps to which is per-protocol and is the caller's decision, because pyatv's own
/// info-string vocabularies disagree about whose "write" is whose
/// (`docs/research/hap-pairing-port-spec.md` §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// The X25519 ECDH output, or for transient pairing the SRP session key.
    pub shared_secret: Vec<u8>,
    /// Key for the direction this side writes.
    pub output_key: [u8; KEY_LEN],
    /// Key for the direction this side reads.
    pub input_key: [u8; KEY_LEN],
}

/// The controller half of HAP pair-verify, as a sans-io state machine.
///
/// Drive it in order: [`PairVerify::start`], [`PairVerify::handle_m2`], [`PairVerify::handle_m4`],
/// then [`PairVerify::encryption_keys`] once per channel.
#[derive(Debug)]
pub struct PairVerify {
    credentials: HapCredentials,
    /// Taken by value in [`PairVerify::handle_m2`]; the type enforces one ECDH per keypair.
    exchange: Option<EphemeralExchange>,
    public_key: [u8; X25519_LEN],
    shared_secret: Option<[u8; X25519_LEN]>,
}

impl PairVerify {
    /// Begin verification, returning the machine and the M1 TLV to send.
    ///
    /// M1 carries only `SeqNo` and the controller's fresh X25519 public key — no `Method` TLV. The
    /// reference accessory uses exactly that (a `PublicKey` in state 1) to tell a verify from a
    /// setup (`pyatv/protocols/mrp/server_auth.py:120-128`).
    #[must_use]
    pub fn start(credentials: HapCredentials) -> (Self, Vec<u8>) {
        Self::from_exchange(credentials, EphemeralExchange::generate())
    }

    /// Begin verification with a caller-supplied X25519 scalar, for known-answer tests only.
    ///
    /// Pinning the controller's ephemeral is what makes a captured pair-verify exchange replayable,
    /// since the accessory signs over it. Gated behind the test-only `test-server` feature so the
    /// shipping path can only ever use [`EphemeralExchange::generate`].
    #[cfg(feature = "test-server")]
    #[doc(hidden)]
    #[must_use]
    pub fn start_with(credentials: HapCredentials, scalar: [u8; X25519_LEN]) -> (Self, Vec<u8>) {
        Self::from_exchange(credentials, EphemeralExchange::from_scalar(scalar))
    }

    fn from_exchange(credentials: HapCredentials, exchange: EphemeralExchange) -> (Self, Vec<u8>) {
        let public_key = *exchange.public_key();

        let request = Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M1 as u8)
            .with(TlvValue::PublicKey, public_key.to_vec())
            .encode()
            .to_vec();

        let verify = Self {
            credentials,
            exchange: Some(exchange),
            public_key,
            shared_secret: None,
        };

        (verify, request)
    }

    /// Consume M2, verify the accessory, and produce the controller's signed M3.
    ///
    /// The sequence mirrors `verify1` exactly (`pyatv/auth/hap_srp.py:84-124`): ECDH, derive the
    /// `Pair-Verify-Encrypt` key, open the accessory's TLV, check its identifier against the stored
    /// credentials, verify its signature over
    /// `accessoryEphemeralPK | accessoryPairingID | controllerEphemeralPK`, then sign the mirrored
    /// `controllerEphemeralPK | controllerPairingID | accessoryEphemeralPK`. The two field orders
    /// are mirror images, not the same tuple relabelled.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if M1 was not sent by this instance, [`Error::InvalidKey`] if
    /// the accessory's ephemeral key is malformed, [`Error::Aead`] if M2 does not decrypt,
    /// [`Error::IdentifierMismatch`] if the accessory is not the paired device, and
    /// [`Error::VerifySignature`] if its signature does not verify.
    pub fn handle_m2(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let exchange = self
            .exchange
            .take()
            .ok_or(Error::OutOfOrder("pair-verify M2 has already been handled"))?;

        let response = decode_response(payload, State::M2)?;
        let accessory_public_key = require_owned(&response, TlvValue::PublicKey)?;
        let encrypted = require_owned(&response, TlvValue::EncryptedData)?;

        let shared_secret = exchange.exchange(&accessory_public_key)?;
        let session_key = expand(
            salts::VERIFY_ENCRYPT_SALT,
            salts::VERIFY_ENCRYPT_INFO,
            &shared_secret,
        )?;

        let inner = Tlv8::decode(&open(&session_key, PAIR_VERIFY_M2_NONCE, &encrypted)?)?;
        let identifier = require_owned(&inner, TlvValue::Identifier)?;
        let signature = require_owned(&inner, TlvValue::Signature)?;

        if identifier[..] != self.credentials.atv_id[..] {
            return Err(Error::IdentifierMismatch {
                expected: hex::encode(&self.credentials.atv_id),
                actual: hex::encode(&identifier),
            });
        }

        let mut accessory_info =
            Vec::with_capacity(accessory_public_key.len() + identifier.len() + X25519_LEN);
        accessory_info.extend_from_slice(&accessory_public_key);
        accessory_info.extend_from_slice(&identifier);
        accessory_info.extend_from_slice(&self.public_key);

        if !verify_signature(&self.credentials.ltpk, &accessory_info, &signature) {
            return Err(Error::VerifySignature);
        }

        let seed =
            <[u8; 32]>::try_from(&self.credentials.ltsk[..]).map_err(|_| Error::InvalidKey {
                kind: "controller Ed25519 seed",
            })?;

        let mut controller_info = Vec::with_capacity(
            X25519_LEN + self.credentials.client_id.len() + accessory_public_key.len(),
        );
        controller_info.extend_from_slice(&self.public_key);
        controller_info.extend_from_slice(&self.credentials.client_id);
        controller_info.extend_from_slice(&accessory_public_key);

        let inner = Tlv8::new()
            .with(TlvValue::Identifier, self.credentials.client_id.clone())
            .with(TlvValue::Signature, sign(&seed, &controller_info).to_vec());

        let encrypted = seal(&session_key, PAIR_VERIFY_M3_NONCE, &inner.encode())?;
        self.shared_secret = Some(shared_secret);

        Ok(Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M3 as u8)
            .with(TlvValue::EncryptedData, encrypted)
            .encode()
            .to_vec())
    }

    /// Check the accessory's final acknowledgement.
    ///
    /// pyatv leaves a `# TODO: check status code` here and treats "the send did not raise" as
    /// success (`pyatv/protocols/mrp/auth.py:112-116`). This port inspects the state and error TLVs
    /// instead, so an accessory that rejects the controller's signature is reported as a failure
    /// rather than as a successful verify that then cannot decrypt anything.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HapError`] if the device reported one, or [`Error::UnexpectedState`] if the
    /// response is not M4.
    pub fn handle_m4(&self, payload: &[u8]) -> Result<()> {
        decode_response(payload, State::M4).map(drop)
    }

    /// The X25519 shared secret, available once M2 has been handled.
    #[must_use]
    pub fn shared_secret(&self) -> Option<&[u8]> {
        self.shared_secret.as_ref().map(|secret| &secret[..])
    }

    /// Derive one channel's transport keys, the port of `verify2`
    /// (`pyatv/auth/hap_srp.py:126-136`).
    ///
    /// Both keys come from the raw ECDH output, not from the `Pair-Verify-Encrypt` key derived
    /// inside [`PairVerify::handle_m2`]: they are two independent expansions of the same IKM, not a
    /// chain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if M2 has not been handled yet.
    pub fn encryption_keys(
        &self,
        salt: &str,
        output_info: &str,
        input_info: &str,
    ) -> Result<SessionKeys> {
        let shared_secret = self
            .shared_secret
            .ok_or(Error::OutOfOrder("pair-verify M2 has not been handled"))?;

        Ok(SessionKeys {
            shared_secret: shared_secret.to_vec(),
            output_key: expand(salt, output_info, &shared_secret)?,
            input_key: expand(salt, input_info, &shared_secret)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::PairVerify;
    use crate::{
        Error, HapCredentials,
        tlv8::{State, Tlv8, TlvValue},
    };

    fn credentials() -> HapCredentials {
        HapCredentials {
            ltpk: vec![1; 32],
            ltsk: vec![2; 32],
            atv_id: b"accessory".to_vec(),
            client_id: b"controller".to_vec(),
        }
    }

    #[test]
    fn m1_carries_a_public_key_and_no_method() {
        let (_, request) = PairVerify::start(credentials());
        let tlv = Tlv8::decode(&request).unwrap();

        assert_eq!(
            tlv.get(TlvValue::PublicKey).map(bytes::Bytes::len),
            Some(32)
        );
        assert_eq!(
            tlv.get(TlvValue::SeqNo).map(|value| value[0]),
            Some(State::M1 as u8)
        );
        assert!(tlv.get(TlvValue::Method).is_none());
    }

    #[test]
    fn keys_are_unavailable_until_m2_is_handled() {
        let (verify, _) = PairVerify::start(credentials());

        assert!(verify.shared_secret().is_none());
        assert!(matches!(
            verify.encryption_keys("Control-Salt", "out", "in"),
            Err(Error::OutOfOrder(_))
        ));
    }

    #[test]
    fn the_ephemeral_keypair_is_single_use() {
        let (mut verify, _) = PairVerify::start(credentials());
        let m2 = Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M2 as u8)
            .with(TlvValue::PublicKey, vec![9u8; 32])
            .with(TlvValue::EncryptedData, vec![0u8; 48])
            .encode();

        // The first attempt consumes the keypair and fails at the AEAD tag.
        assert!(matches!(verify.handle_m2(&m2), Err(Error::Aead { .. })));
        assert!(matches!(verify.handle_m2(&m2), Err(Error::OutOfOrder(_))));
    }

    #[test]
    fn a_non_m4_acknowledgement_is_rejected() {
        let (verify, _) = PairVerify::start(credentials());
        let response = Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M2 as u8)
            .encode();

        assert!(matches!(
            verify.handle_m4(&response),
            Err(Error::UnexpectedState {
                expected: 4,
                actual: 2
            })
        ));
    }
}
