//! Pair-verify M1 through M4: prove both stored identities and derive transport keys.
//!
//! Ported from `SRPAuthHandler.verify1`/`verify2` (`pyatv/auth/hap_srp.py:84-136`) driven by
//! `MrpPairVerifyProcedure` (`pyatv/protocols/mrp/auth.py:85-122`).
//!
//! Unlike pair-setup this exchange has no SRP and no PIN: it is an X25519 ECDH plus two Ed25519
//! signatures over the two ephemeral public keys, and its whole point is the shared secret that
//! [`PairVerify::encryption_keys`] turns into per-channel transport keys.

use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Which message the machine is waiting for.
///
/// pyatv infers this from call order (`pyatv/protocols/mrp/auth.py:85-122`); making it explicit is
/// what turns a replayed M4 into [`Error::OutOfOrder`] instead of a second "verified" result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// M1 has been produced; the device must answer with M2.
    AwaitingM2,
    /// M3 has been produced; the device must answer with M4.
    AwaitingM4,
    /// M4 has been accepted; transport keys can be derived.
    Complete,
}

/// The transport keys one channel needs, plus the secret they came from.
///
/// `output_key` encrypts what this side sends and `input_key` decrypts what it receives; which
/// HKDF info string maps to which is per-protocol and is the caller's decision, because pyatv's own
/// info-string vocabularies disagree about whose "write" is whose
/// (`docs/research/hap-pairing-port-spec.md` §4.3).
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// The X25519 ECDH output, or for transient pairing the SRP session key.
    pub shared_secret: Vec<u8>,
    /// Key for the direction this side writes.
    pub output_key: [u8; KEY_LEN],
    /// Key for the direction this side reads.
    pub input_key: [u8; KEY_LEN],
}

// Hand-written: every field is key material. All three are redacted; the lengths are kept because
// distinguishing a 32-byte ECDH secret from a 64-byte SRP session key is the one thing worth seeing
// in a log (it tells transient pairing apart from the ordinary flow) and reveals nothing.
impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionKeys")
            .field("shared_secret_len", &self.shared_secret.len())
            .field("shared_secret", &"<redacted>")
            .field("output_key", &"<redacted>")
            .field("input_key", &"<redacted>")
            .finish()
    }
}

impl Zeroize for SessionKeys {
    fn zeroize(&mut self) {
        self.shared_secret.zeroize();
        self.output_key.zeroize();
        self.input_key.zeroize();
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SessionKeys {}

/// The controller half of HAP pair-verify, as a sans-io state machine.
///
/// Drive it in order: [`PairVerify::start`], [`PairVerify::handle_m2`], [`PairVerify::handle_m4`],
/// then [`PairVerify::encryption_keys`] once per channel. Steps taken out of that order, including
/// a replayed M2 or M4, are [`Error::OutOfOrder`].
///
/// ```
/// use pyatv_pairing::{Error, HapCredentials, PairVerify};
///
/// let credentials = HapCredentials::parse("aabb:ccdd:eeff:0011")?;
///
/// // M1 carries only the fresh X25519 public key; send it and wait for M2.
/// let (mut verify, m1) = PairVerify::start(credentials);
/// assert!(!m1.is_empty());
///
/// // Transport keys exist only after M2 has been handled, and M4 cannot precede it.
/// assert!(matches!(
///     verify.encryption_keys("MediaRemote-Salt", "out", "in"),
///     Err(Error::OutOfOrder(_)),
/// ));
/// assert!(matches!(verify.handle_m4(&[]), Err(Error::OutOfOrder(_))));
/// # Ok::<(), Error>(())
/// ```
pub struct PairVerify {
    credentials: HapCredentials,
    /// Taken by value in [`PairVerify::handle_m2`]; the type enforces one ECDH per keypair.
    exchange: Option<EphemeralExchange>,
    public_key: [u8; X25519_LEN],
    shared_secret: Option<[u8; X25519_LEN]>,
    phase: Phase,
}

// Hand-written: the derived `Debug` would print the ECDH shared secret, which is the IKM for every
// transport key in the session, and — through `HapCredentials` — nothing worse than that type
// already redacts. The controller's own ephemeral public key is public, but is shown only as a
// length because it is noise in a log line.
impl std::fmt::Debug for PairVerify {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairVerify")
            .field("phase", &self.phase)
            .field("credentials", &self.credentials)
            .field("public_key", &hex::encode(self.public_key))
            .field("shared_secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

// As in [`crate::PairSetup`], `Zeroize` is not implemented publicly: wiping a live machine and
// carrying on would be a bug the type system should not invite.
impl Drop for PairVerify {
    fn drop(&mut self) {
        if let Some(secret) = self.shared_secret.as_mut() {
            secret.zeroize();
        }
        // The controller's long-term seed came in through the credentials and is the one field of
        // them worth wiping; the rest are public keys and identifiers.
        self.credentials.ltsk.zeroize();
        // `EphemeralSecret` zeroizes itself on drop; the test-only pinned scalar does not, so the
        // keypair is dropped here explicitly rather than depending on which variant is in use.
        self.exchange = None;
    }
}

impl ZeroizeOnDrop for PairVerify {}

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
            phase: Phase::AwaitingM2,
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
        if self.phase != Phase::AwaitingM2 {
            return Err(Error::OutOfOrder("pair-verify M2 has already been handled"));
        }

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
        self.phase = Phase::AwaitingM4;

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
    /// Returns [`Error::OutOfOrder`] if M2 has not been handled or M4 already has,
    /// [`Error::HapError`] if the device reported one, or [`Error::UnexpectedState`] if the
    /// response is not M4.
    pub fn handle_m4(&mut self, payload: &[u8]) -> Result<()> {
        match self.phase {
            Phase::AwaitingM4 => {}
            Phase::AwaitingM2 => {
                return Err(Error::OutOfOrder("pair-verify M2 has not been handled"));
            }
            Phase::Complete => {
                return Err(Error::OutOfOrder("pair-verify M4 has already been handled"));
            }
        }

        decode_response(payload, State::M4)?;
        self.phase = Phase::Complete;
        Ok(())
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

    /// M4 cannot precede M2: there is nothing yet to acknowledge, and accepting it would leave the
    /// caller believing a verify completed with no shared secret behind it.
    #[test]
    fn m4_before_m2_is_refused() {
        let (mut verify, _) = PairVerify::start(credentials());
        let m4 = Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M4 as u8)
            .encode();

        assert!(matches!(
            verify.handle_m4(&m4),
            Err(Error::OutOfOrder("pair-verify M2 has not been handled"))
        ));
    }

    #[test]
    fn a_non_m4_acknowledgement_is_rejected() {
        let (mut verify, _) = PairVerify::start(credentials());
        // Force the machine past M2 without a real exchange; only the state check is under test.
        verify.phase = super::Phase::AwaitingM4;
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

    /// A replayed M4 must not report a second successful verify.
    #[test]
    fn a_replayed_m4_is_refused() {
        let (mut verify, _) = PairVerify::start(credentials());
        verify.phase = super::Phase::AwaitingM4;
        let m4 = Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M4 as u8)
            .encode();

        verify.handle_m4(&m4).expect("the first M4 is accepted");
        assert!(matches!(
            verify.handle_m4(&m4),
            Err(Error::OutOfOrder("pair-verify M4 has already been handled"))
        ));
    }

    /// A `Debug` print must not expose the controller's stored secret key or the ECDH output.
    #[test]
    fn debug_redacts_the_shared_secret_and_the_stored_key() {
        let (mut verify, _) = PairVerify::start(credentials());
        verify.shared_secret = Some([0x7Eu8; 32]);

        let rendered = format!("{verify:?}");
        assert!(!rendered.contains(&hex::encode([0x7Eu8; 32])), "{rendered}");
        assert!(!rendered.contains(&hex::encode([2u8; 32])), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    /// Every field of [`SessionKeys`] is key material, so none of it may appear in a log line.
    #[test]
    fn session_keys_debug_redacts_everything() {
        let keys = super::SessionKeys {
            shared_secret: vec![0x11; 32],
            output_key: [0x22; 32],
            input_key: [0x33; 32],
        };

        let rendered = format!("{keys:?}");
        assert!(!rendered.contains(&hex::encode([0x11u8; 32])));
        assert!(!rendered.contains(&hex::encode([0x22u8; 32])));
        assert!(!rendered.contains(&hex::encode([0x33u8; 32])));
        // The raw byte-array rendering would show decimal, not hex; rule that out too.
        assert!(!rendered.contains("17, 17"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("shared_secret_len: 32"));
    }
}
