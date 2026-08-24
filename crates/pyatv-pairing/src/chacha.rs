//! ChaCha20-Poly1305 with pyatv's two counter-nonce layouts.
//!
//! Direct port of `pyatv/support/chacha20.py` (`Chacha20Cipher`, `Chacha20Cipher8byteNonce`). The
//! Python class is one type parameterised by `nonce_length`, and the difference between the two
//! instantiations is invisible at the call site — which is exactly how a port gets it wrong. Here
//! the layout is an explicit [`NonceLayout`] value with a named zero-prefix width, so no caller can
//! pick a width by accident.
//!
//! Three consumers, three framings, all built on this one primitive
//! (`docs/research/hap-pairing-port-spec.md` §4.0, §5.1–§5.4):
//!
//! - **AirPlay** control/events/data-stream channels: [`NonceLayout::PaddedCounter`], wrapped in
//!   the 1024-byte framing of [`crate::session::HapSession`], AAD = the 2 length bytes.
//! - **MRP**: [`NonceLayout::PaddedCounter`] applied to a whole serialised protobuf message, **no
//!   AAD and no frame cap** (`pyatv/protocols/mrp/connection.py:114-136`). The varint length prefix
//!   MRP puts on the wire is computed over the ciphertext and is not authenticated.
//! - **Companion**: [`NonceLayout::BareCounter`] with the 4-byte frame header as AAD
//!   (`pyatv/protocols/companion/connection.py:90-119`).
//!
//! The pairing handshakes themselves do not use counters at all: they pass one of the fixed ASCII
//! nonces in [`fixed_nonce`] (`pyatv/auth/hap_srp.py:97-124,151-233`).

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::{Error, Result};

/// Nonce size ChaCha20-Poly1305 requires, `pyatv/support/chacha20.py:9`.
pub const NONCE_LENGTH: usize = 12;

/// Poly1305 tag length appended to every ciphertext.
pub const AUTH_TAG_LENGTH: usize = 16;

/// How the 12-byte nonce is assembled from a message counter.
///
/// Both variants write the counter little-endian; they differ only in how many zero bytes sit in
/// front of it, and therefore produce completely different nonces for the same counter value. See
/// `pyatv/support/chacha20.py:23-51,76-106`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NonceLayout {
    /// Four zero bytes then an 8-byte little-endian counter.
    ///
    /// `Chacha20Cipher8byteNonce`, i.e. `Struct("<LQ").pack(0, counter)`
    /// (`pyatv/support/chacha20.py:76,79-106`). Used by the AirPlay HAP channels and by MRP.
    PaddedCounter,
    /// A bare 12-byte little-endian counter with no zero prefix.
    ///
    /// `Chacha20Cipher(..., nonce_length=12)`, where `_pad_nonce` is never reached because the
    /// counter is already full width (`pyatv/support/chacha20.py:30-34`). Used by Companion only.
    BareCounter,
}

impl NonceLayout {
    /// How many zero bytes precede the counter.
    #[must_use]
    pub const fn zero_prefix_len(self) -> usize {
        match self {
            Self::PaddedCounter => NONCE_LENGTH - 8,
            Self::BareCounter => 0,
        }
    }

    /// How many bytes of counter the layout carries.
    #[must_use]
    pub const fn counter_len(self) -> usize {
        NONCE_LENGTH - self.zero_prefix_len()
    }

    /// Build the nonce for `counter`.
    ///
    /// Counters above `u64::MAX` cannot occur: pyatv's counters are Python ints written into a
    /// fixed-width buffer, and no session comes close to `2^64` frames.
    #[must_use]
    pub fn nonce(self, counter: u64) -> [u8; NONCE_LENGTH] {
        let mut nonce = [0u8; NONCE_LENGTH];
        let start = self.zero_prefix_len();
        nonce[start..start + 8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
}

/// The fixed ASCII nonces used during pair-setup and pair-verify.
///
/// These are literal strings rather than counters, and pyatv passes them to the same `encrypt`
/// entry point, where `_pad_nonce` left-pads them to 12 bytes
/// (`pyatv/support/chacha20.py:49-51,60-61`).
pub mod fixed_nonce {
    /// Decrypt the device's pair-verify M2 payload (`pyatv/auth/hap_srp.py:97`).
    pub const PV_MSG02: &[u8; 8] = b"PV-Msg02";
    /// Encrypt the controller's pair-verify M3 payload (`pyatv/auth/hap_srp.py:124`).
    pub const PV_MSG03: &[u8; 8] = b"PV-Msg03";
    /// Encrypt the controller's pair-setup M5 payload (`pyatv/auth/hap_srp.py:203`).
    pub const PS_MSG05: &[u8; 8] = b"PS-Msg05";
    /// Decrypt the device's pair-setup M6 payload (`pyatv/auth/hap_srp.py:211`).
    pub const PS_MSG06: &[u8; 8] = b"PS-Msg06";

    /// Left-pad a short fixed nonce to the 12 bytes ChaCha20-Poly1305 requires.
    ///
    /// Port of `_pad_nonce` (`pyatv/support/chacha20.py:49-51`): the zeros go in *front*.
    #[must_use]
    pub fn pad(nonce: &[u8; 8]) -> [u8; super::NONCE_LENGTH] {
        let mut padded = [0u8; super::NONCE_LENGTH];
        padded[super::NONCE_LENGTH - nonce.len()..].copy_from_slice(nonce);
        padded
    }
}

/// A ChaCha20-Poly1305 channel with independent keys and counters per direction.
///
/// Port of `Chacha20Cipher` (`pyatv/support/chacha20.py:12-73`). "Out" is the direction this side
/// encrypts, "in" the direction it decrypts; the two never share a counter, so the same nonce is
/// legitimately reused once under two different keys.
pub struct Chacha20Cipher {
    out_cipher: ChaCha20Poly1305,
    in_cipher: ChaCha20Poly1305,
    out_counter: u64,
    in_counter: u64,
    layout: NonceLayout,
}

// Hand-written: `ChaCha20Poly1305` has no `Debug`, and printing key material would be a leak
// anyway. Only the counters and the layout are safe to show.
impl std::fmt::Debug for Chacha20Cipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Chacha20Cipher")
            .field("layout", &self.layout)
            .field("out_counter", &self.out_counter)
            .field("in_counter", &self.in_counter)
            .finish_non_exhaustive()
    }
}

impl Chacha20Cipher {
    /// Build a cipher for the two transport keys under an explicit nonce layout.
    #[must_use]
    pub fn new(out_key: &[u8; 32], in_key: &[u8; 32], layout: NonceLayout) -> Self {
        Self {
            out_cipher: ChaCha20Poly1305::new(&Key::from(*out_key)),
            in_cipher: ChaCha20Poly1305::new(&Key::from(*in_key)),
            out_counter: 0,
            in_counter: 0,
            layout,
        }
    }

    /// Build the `Chacha20Cipher8byteNonce` variant (`pyatv/support/chacha20.py:79-88`).
    ///
    /// This is what MRP and the AirPlay HAP channels use.
    #[must_use]
    pub fn with_padded_counter(out_key: &[u8; 32], in_key: &[u8; 32]) -> Self {
        Self::new(out_key, in_key, NonceLayout::PaddedCounter)
    }

    /// Build the Companion variant: a bare 12-byte counter.
    #[must_use]
    pub fn with_bare_counter(out_key: &[u8; 32], in_key: &[u8; 32]) -> Self {
        Self::new(out_key, in_key, NonceLayout::BareCounter)
    }

    /// The nonce layout in use.
    #[must_use]
    pub const fn layout(&self) -> NonceLayout {
        self.layout
    }

    /// The nonce the next counter-based [`Chacha20Cipher::encrypt`] will use.
    ///
    /// Port of the `out_nonce` property (`pyatv/support/chacha20.py:23-34,90-97`).
    #[must_use]
    pub fn out_nonce(&self) -> [u8; NONCE_LENGTH] {
        self.layout.nonce(self.out_counter)
    }

    /// The nonce the next counter-based [`Chacha20Cipher::decrypt`] will use.
    ///
    /// Port of the `in_nonce` property (`pyatv/support/chacha20.py:36-47,99-106`).
    #[must_use]
    pub fn in_nonce(&self) -> [u8; NONCE_LENGTH] {
        self.layout.nonce(self.in_counter)
    }

    /// Encrypt with the outbound counter nonce, then advance that counter.
    ///
    /// pyatv increments *before* the AEAD call (`pyatv/support/chacha20.py:57-62`), so a failed
    /// encryption still burns a counter value. That is replicated here: a nonce is never reused
    /// even after an error, which is the safe direction to be wrong in.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aead`] if the AEAD seal fails, or [`Error::MalformedResponse`] if the
    /// outbound counter has reached `u64::MAX`. The latter is unreachable in any real session —
    /// `2^64` frames — but wrapping it would silently reuse a nonce under a live key, which for a
    /// stream cipher discloses the XOR of two plaintexts. `checked_add` makes the impossible case
    /// an error rather than a catastrophe; Python has no such edge, its counter is unbounded.
    pub fn encrypt(&mut self, data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce = self.out_nonce();
        self.out_counter = next_counter(self.out_counter, "outbound")?;
        seal(&self.out_cipher, &nonce, data, aad)
    }

    /// Encrypt under a caller-supplied nonce, leaving the counter untouched.
    ///
    /// This is the `nonce=` branch of `encrypt` (`pyatv/support/chacha20.py:57-62`), used by every
    /// pair-setup and pair-verify message via [`fixed_nonce`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aead`] if the AEAD seal fails.
    pub fn encrypt_with_nonce(
        &self,
        data: &[u8],
        nonce: &[u8; NONCE_LENGTH],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        seal(&self.out_cipher, nonce, data, aad)
    }

    /// Decrypt with the inbound counter nonce, then advance that counter.
    ///
    /// As with [`Chacha20Cipher::encrypt`], the counter advances even when the tag does not verify
    /// (`pyatv/support/chacha20.py:68-73`). A stream that has seen a corrupt frame is unrecoverable
    /// either way, since the peer's counter has moved on.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aead`] if the tag does not verify, or [`Error::MalformedResponse`] if the
    /// inbound counter has reached `u64::MAX`; see [`Chacha20Cipher::encrypt`].
    pub fn decrypt(&mut self, data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let nonce = self.in_nonce();
        self.in_counter = next_counter(self.in_counter, "inbound")?;
        open(&self.in_cipher, &nonce, data, aad)
    }

    /// Decrypt under a caller-supplied nonce, leaving the counter untouched.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aead`] if the tag does not verify.
    pub fn decrypt_with_nonce(
        &self,
        data: &[u8],
        nonce: &[u8; NONCE_LENGTH],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        open(&self.in_cipher, nonce, data, aad)
    }
}

/// Advance a direction's message counter, refusing to wrap.
fn next_counter(counter: u64, direction: &'static str) -> Result<u64> {
    counter.checked_add(1).ok_or_else(|| {
        Error::MalformedResponse(format!(
            "the {direction} ChaCha20 message counter is exhausted; the session must be torn down \
             rather than reuse a nonce"
        ))
    })
}

/// `aad=None` in Python means "no associated data", which the AEAD treats as an empty slice.
fn payload<'msg, 'aad>(msg: &'msg [u8], aad: Option<&'aad [u8]>) -> Payload<'msg, 'aad> {
    Payload {
        msg,
        aad: aad.unwrap_or(&[]),
    }
}

fn seal(
    cipher: &ChaCha20Poly1305,
    nonce: &[u8; NONCE_LENGTH],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    cipher
        .encrypt(&Nonce::from(*nonce), payload(data, aad))
        .map_err(|_| Error::Aead {
            operation: "encrypt",
        })
}

fn open(
    cipher: &ChaCha20Poly1305,
    nonce: &[u8; NONCE_LENGTH],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    cipher
        .decrypt(&Nonce::from(*nonce), payload(data, aad))
        .map_err(|_| Error::Aead {
            operation: "decrypt",
        })
}

#[cfg(test)]
mod tests {
    use super::{AUTH_TAG_LENGTH, Chacha20Cipher, NONCE_LENGTH, NonceLayout, fixed_nonce};

    /// `fake_key = b"k" * 32` (`tests/support/test_chacha20.py:7`).
    const FAKE_KEY: [u8; 32] = [b'k'; 32];

    /// Port of `test_12_bytes_nonce` (`tests/support/test_chacha20.py:10-15`).
    #[test]
    fn twelve_byte_nonce_round_trips() {
        let mut cipher = Chacha20Cipher::with_bare_counter(&FAKE_KEY, &FAKE_KEY);

        assert_eq!(cipher.out_nonce().len(), NONCE_LENGTH);
        assert_eq!(cipher.in_nonce().len(), NONCE_LENGTH);

        let result = cipher.encrypt(b"test", None).expect("encrypt");
        assert_eq!(cipher.decrypt(&result, None).expect("decrypt"), b"test");
    }

    /// Port of `test_8_bytes_nonce` (`tests/support/test_chacha20.py:18-23`).
    #[test]
    fn eight_byte_nonce_round_trips() {
        let mut cipher = Chacha20Cipher::with_padded_counter(&FAKE_KEY, &FAKE_KEY);

        assert_eq!(cipher.out_nonce().len(), NONCE_LENGTH);
        assert_eq!(cipher.in_nonce().len(), NONCE_LENGTH);

        let result = cipher.encrypt(b"test", None).expect("encrypt");
        assert_eq!(cipher.decrypt(&result, None).expect("decrypt"), b"test");
    }

    /// The zero prefix is the whole difference between the layouts, so the same counter must not
    /// produce the same nonce under both.
    #[test]
    fn the_two_layouts_disagree_for_the_same_counter() {
        assert_eq!(NonceLayout::PaddedCounter.zero_prefix_len(), 4);
        assert_eq!(NonceLayout::BareCounter.zero_prefix_len(), 0);
        assert_eq!(
            NonceLayout::PaddedCounter.nonce(1),
            [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            NonceLayout::BareCounter.nonce(1),
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    /// Counters are little-endian in both layouts.
    #[test]
    fn counters_are_little_endian() {
        assert_eq!(
            NonceLayout::PaddedCounter.nonce(0x0102),
            [0, 0, 0, 0, 0x02, 0x01, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            NonceLayout::BareCounter.nonce(0x0102),
            [0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    /// A fixed ASCII nonce lands in the same byte positions the padded counter uses.
    #[test]
    fn fixed_nonces_are_left_padded_to_twelve_bytes() {
        let padded = fixed_nonce::pad(fixed_nonce::PV_MSG02);

        assert_eq!(&padded[..4], &[0, 0, 0, 0]);
        assert_eq!(&padded[4..], b"PV-Msg02");
    }

    /// Each counter-based call must use a fresh nonce, so two encryptions of the same plaintext
    /// must differ, and decryption must follow in lockstep.
    #[test]
    fn counters_advance_independently_per_direction() {
        let mut cipher = Chacha20Cipher::with_padded_counter(&FAKE_KEY, &FAKE_KEY);

        let first = cipher.encrypt(b"same", None).expect("encrypt");
        let second = cipher.encrypt(b"same", None).expect("encrypt");
        assert_ne!(first, second);
        assert_eq!(cipher.out_nonce(), NonceLayout::PaddedCounter.nonce(2));
        assert_eq!(cipher.in_nonce(), NonceLayout::PaddedCounter.nonce(0));

        assert_eq!(cipher.decrypt(&first, None).expect("decrypt"), b"same");
        assert_eq!(cipher.decrypt(&second, None).expect("decrypt"), b"same");
    }

    /// pyatv increments before the AEAD call, so a failed decryption still consumes a counter.
    #[test]
    fn a_failed_decryption_still_advances_the_counter() {
        let mut cipher = Chacha20Cipher::with_padded_counter(&FAKE_KEY, &FAKE_KEY);

        assert!(cipher.decrypt(&[0u8; AUTH_TAG_LENGTH], None).is_err());
        assert_eq!(cipher.in_nonce(), NonceLayout::PaddedCounter.nonce(1));
    }

    /// A fixed nonce must not disturb the counters, or the pairing handshake would desynchronise
    /// the transport that follows it.
    #[test]
    fn fixed_nonce_calls_leave_the_counters_alone() {
        let cipher = Chacha20Cipher::with_padded_counter(&FAKE_KEY, &FAKE_KEY);
        let nonce = fixed_nonce::pad(fixed_nonce::PS_MSG05);

        let sealed = cipher
            .encrypt_with_nonce(b"tlv", &nonce, None)
            .expect("encrypt");

        assert_eq!(
            cipher
                .decrypt_with_nonce(&sealed, &nonce, None)
                .expect("decrypt"),
            b"tlv"
        );
        assert_eq!(cipher.out_nonce(), NonceLayout::PaddedCounter.nonce(0));
        assert_eq!(cipher.in_nonce(), NonceLayout::PaddedCounter.nonce(0));
    }

    /// AAD is authenticated but not encrypted: a mismatch must fail the open.
    #[test]
    fn associated_data_is_authenticated() {
        let cipher = Chacha20Cipher::with_bare_counter(&FAKE_KEY, &FAKE_KEY);
        let nonce = NonceLayout::BareCounter.nonce(7);

        let sealed = cipher
            .encrypt_with_nonce(b"body", &nonce, Some(b"header"))
            .expect("encrypt");

        assert!(
            cipher
                .decrypt_with_nonce(&sealed, &nonce, Some(b"header"))
                .is_ok()
        );
        assert!(
            cipher
                .decrypt_with_nonce(&sealed, &nonce, Some(b"heaper"))
                .is_err()
        );
        assert!(cipher.decrypt_with_nonce(&sealed, &nonce, None).is_err());
    }

    /// An exhausted counter must be an error, never a wrap: a wrapped nonce reused under a live key
    /// leaks the XOR of two plaintexts. Reaching this state honestly takes `2^64` frames, so the
    /// counters are set by hand.
    #[test]
    fn an_exhausted_counter_is_refused_rather_than_wrapping() {
        use crate::Error;

        let mut cipher = Chacha20Cipher::with_padded_counter(&FAKE_KEY, &FAKE_KEY);
        cipher.out_counter = u64::MAX;
        cipher.in_counter = u64::MAX;

        assert!(matches!(
            cipher.encrypt(b"one too many", None),
            Err(Error::MalformedResponse(_))
        ));
        assert!(matches!(
            cipher.decrypt(&[0u8; AUTH_TAG_LENGTH], None),
            Err(Error::MalformedResponse(_))
        ));
        // Neither direction may have wrapped back to zero.
        assert_eq!(
            cipher.out_nonce(),
            NonceLayout::PaddedCounter.nonce(u64::MAX)
        );
        assert_eq!(
            cipher.in_nonce(),
            NonceLayout::PaddedCounter.nonce(u64::MAX)
        );
    }

    /// `aad=None` and `aad=b""` are the same thing to the AEAD, which is what pyatv relies on when
    /// MRP omits the argument entirely.
    #[test]
    fn absent_and_empty_associated_data_agree() {
        let cipher = Chacha20Cipher::with_padded_counter(&FAKE_KEY, &FAKE_KEY);
        let nonce = NonceLayout::PaddedCounter.nonce(0);

        assert_eq!(
            cipher
                .encrypt_with_nonce(b"x", &nonce, None)
                .expect("encrypt"),
            cipher
                .encrypt_with_nonce(b"x", &nonce, Some(b""))
                .expect("encrypt")
        );
    }
}
