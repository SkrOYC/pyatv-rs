//! The pairing GUID and the MD5 the device proves the PIN with.
//!
//! Port of `_generate_random_guid` and `_verify_pin` (`pyatv/protocols/dmap/pairing.py:28-29`,
//! `:145-158`). Pure functions, no sockets, and the only place in DMAP where a hash is computed.

use md5::{Digest, Md5};

/// How many hex digits a pairing GUID has: sixty-four bits.
pub const PAIRING_GUID_DIGITS: usize = 16;

/// The `cmty` value sent in a successful pairing response (`pairing.py:321`).
///
/// Note that this is **not** the `DvTy` published over mDNS, which is `iPod`
/// ([`super::server::DEVICE_TYPE`]). pyatv presents itself as an iPod in the advertisement and as
/// an iPhone in the pairing body; the divergence is upstream's, not a transcription slip.
pub const RESPONSE_DEVICE_TYPE: &str = "iPhone";

/// Render a 64-bit value as a pairing GUID: uppercase hex, no `0x`, **zero-padded to sixteen**.
///
/// # Deliberate divergence: the padding
///
/// Upstream is `hex(random.getrandbits(64)).upper()[2:]` (`pairing.py:28-29,237-239`), and Python's
/// `hex()` does not pad. Roughly one GUID in sixteen therefore comes out with fewer than sixteen
/// digits — and `DaapRequester._mkurl`'s credential regex is `r"0x[0-9A-Fa-f]{16}"`, exactly
/// sixteen, anchored at the start (`daap.py:158`). Such a credential matches neither that pattern
/// nor the `hsgid` one, so the *next login after a successful pairing* raises
/// `InvalidCredentialsError`. That is a real, reproducible bug in pyatv, unexercised by its own
/// suite because none of its three GUID fixtures has a leading zero nibble; see
/// `docs/research/dmap-port-spec.md` §6.1.
///
/// Padding here fixes it. Nothing on the wire depends on the *width* of a client-generated random
/// identifier: what the device sees is the `Pair` TXT value and the `cmpg` integer in the pairing
/// response, and both are unaffected. The one observable consequence is that a credential string
/// this port persists may differ from the one pyatv would have persisted for the same random draw
/// — by leading zeros, which pyatv could not have used anyway.
#[must_use]
pub fn pairing_guid_from(value: u64) -> String {
    format!("{value:0PAIRING_GUID_DIGITS$X}")
}

/// A fresh random pairing GUID.
///
/// `random.getrandbits(64)` upstream. This is an identifier, not a secret — it is published in
/// cleartext in the `Pair` TXT record — but it is also the credential the device authenticates
/// with afterwards, so it comes from the OS entropy source rather than from a seeded PRNG.
#[must_use]
pub fn generate_pairing_guid() -> String {
    pairing_guid_from(rand::random::<u64>())
}

/// Normalise whatever a caller supplied into the internal form: uppercase hex, no `0x` prefix.
///
/// `(kwargs.get("pairing_guid", None) or _generate_random_guid())[2:].upper()`
/// (`pairing.py:237-239`) — the slice removes exactly two characters and *assumes* they are `0x`.
/// This checks instead, so a caller passing a bare hex string gets what they meant rather than
/// silently losing its first two digits.
#[must_use]
pub fn normalise_pairing_guid(pairing_guid: &str) -> String {
    pairing_guid
        .strip_prefix("0x")
        .or_else(|| pairing_guid.strip_prefix("0X"))
        .unwrap_or(pairing_guid)
        .to_uppercase()
}

/// The stored credential form: a lowercase `0x` in front of the uppercase digits.
///
/// `self.service.credentials = "0x" + self._pairing_guid` (`pairing.py:275`). The result is
/// mixed-case by construction — `"0x0000000000000001"` — and that is exactly the string
/// `test_succesful_pairing` asserts and `_mkurl`'s regex later matches.
#[must_use]
pub fn credentials(pairing_guid: &str) -> String {
    format!("0x{}", normalise_pairing_guid(pairing_guid))
}

/// The code the device must send, for a given GUID and PIN.
///
/// `_verify_pin`'s hash (`pairing.py:150-155`), spelled out as a byte recipe:
///
/// ```text
/// input  = pairing_guid_hex_uppercase_without_0x
///        + PIN_decimal_digit_0 + "\x00"
///        + PIN_decimal_digit_1 + "\x00"
///        + PIN_decimal_digit_2 + "\x00"
///        + PIN_decimal_digit_3 + "\x00"
/// digest = lowercase_hex(MD5(input))
/// ```
///
/// Two details that are easy to get wrong. The NUL follows **every** digit including the last, so
/// the input is `len(guid) + 8` bytes and not `+ 7`. And the PIN is `str(pin).zfill(4)`, so `1`
/// becomes `0001` — left-padded, never truncated; a PIN with more than four digits keeps all of
/// them and contributes two bytes per digit.
///
/// ```
/// use pyatv_proto_dmap::pairing::expected_code;
///
/// // Extracted from a real device (`tests/protocols/dmap/test_dmap_functional.py:37-39`).
/// assert_eq!(
///     expected_code("0000000000000001", 1234),
///     "690e6ff61e0d7c747654a42aed17047d"
/// );
/// ```
#[must_use]
pub fn expected_code(pairing_guid: &str, pin: u32) -> String {
    let mut input = normalise_pairing_guid(pairing_guid).into_bytes();
    for digit in format!("{pin:04}").bytes() {
        input.push(digit);
        input.push(0x00);
    }

    hex::encode(Md5::digest(&input))
}

/// Whether a code the device sent matches.
///
/// `_verify_pin` (`pairing.py:145-158`). `pin` of `None` is upstream's "no particular pin code is
/// specified, allow any pin" state — the one a handler is in before anyone called `pin(...)`, and
/// which `test_succesful_pairing_with_any_pin` covers
/// (`tests/protocols/dmap/test_dmap_pairing.py:467-473`).
///
/// The comparison is case-insensitive: the query parameter is lower-cased on arrival upstream
/// (`pairing.py:313`) while the constants in its own tests are uppercase.
#[must_use]
pub fn verify(pairing_guid: &str, pin: Option<u32>, received: &str) -> bool {
    let Some(pin) = pin else {
        return true;
    };
    received.eq_ignore_ascii_case(&expected_code(pairing_guid, pin))
}

#[cfg(test)]
mod tests {
    use md5::{Digest, Md5};

    use super::{
        PAIRING_GUID_DIGITS, credentials, expected_code, generate_pairing_guid,
        normalise_pairing_guid, pairing_guid_from, verify,
    };

    /// The four vectors from `tests/protocols/dmap/test_dmap_pairing.py:336-354`, independently
    /// re-derived in `docs/research/dmap-port-spec.md` §2.3 with a non-pyatv MD5.
    const VECTORS: [(&str, u32, &str); 4] = [
        ("0000000000000001", 1234, "690E6FF61E0D7C747654A42AED17047D"),
        ("1234ABCDE56789FF", 5555, "58AD1D195B6DAA58AA2EA29DC25B81C3"),
        // The PIN is zero-padded to four digits, not rejected.
        ("7D1324235F535AE7", 1, "A34C3361C7D57D61CA41F62A8042F069"),
        // From `random.getrandbits(64) == 6558272190156386627`.
        ("5B03A9CF4A983143", 1234, "7AF2D0B8629DE3C704D40A14C9E8CB93"),
    ];

    #[test]
    fn the_known_answer_vectors_all_match() {
        for (guid, pin, expected) in VECTORS {
            assert_eq!(
                expected_code(guid, pin),
                expected.to_lowercase(),
                "guid={guid} pin={pin}"
            );
        }
    }

    /// The device sends the code in whichever case it likes; upstream lower-cases on arrival.
    #[test]
    fn verification_ignores_case() {
        for (guid, pin, expected) in VECTORS {
            assert!(verify(guid, Some(pin), expected));
            assert!(verify(guid, Some(pin), &expected.to_lowercase()));
            assert!(!verify(guid, Some(pin), "wrong"));
        }
    }

    /// `test_succesful_pairing_with_any_pin` (`test_dmap_pairing.py:467-473`): before `pin(...)` is
    /// called, every code is accepted.
    #[test]
    fn an_unset_pin_accepts_anything() {
        assert!(verify("0000000000000001", None, "invalid_pairing_code"));
        assert!(verify("0000000000000001", None, ""));
    }

    /// A PIN and a GUID that both have leading zeros, which is what makes them worth testing.
    #[test]
    fn a_pin_is_left_padded_to_four_digits() {
        let guid = "7D1324235F535AE7";
        // `str(1).zfill(4) == "0001"`, so these two are the same pairing.
        assert_eq!(expected_code(guid, 1), expected_code(guid, 1));
        assert_eq!(expected_code(guid, 1), "a34c3361c7d57d61ca41f62a8042f069");
        assert_ne!(expected_code(guid, 1), expected_code(guid, 1000));
    }

    /// The NUL after the final digit is part of the input; dropping it changes the digest.
    #[test]
    fn the_input_length_is_the_guid_plus_eight_bytes() {
        // Same GUID, same digits, different separators would give a different answer — this pins
        // that the vectors above cannot be satisfied by a `+7`-byte construction.
        assert_ne!(
            expected_code("0000000000000001", 1234),
            hex::encode(Md5::digest(b"00000000000000011\x002\x003\x004")),
        );
    }

    /// A GUID whose top nibbles are zero must still render as sixteen digits — the whole point of
    /// diverging from `hex()`.
    #[test]
    fn a_generated_guid_is_always_sixteen_uppercase_hex_digits() {
        for value in [
            0u64,
            1,
            0x0F03_A9CF_4A98_3143,
            u64::MAX,
            6_558_272_190_156_386_627,
        ] {
            let guid = pairing_guid_from(value);
            assert_eq!(guid.len(), PAIRING_GUID_DIGITS, "{value:#x}");
            assert!(
                guid.bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()),
                "{guid} should be uppercase hex"
            );
        }

        assert_eq!(pairing_guid_from(1), "0000000000000001");
        assert_eq!(
            pairing_guid_from(6_558_272_190_156_386_627),
            "5B03A9CF4A983143",
            "`test_successful_pairing_random_pairing_guid_generated`'s fixture"
        );
    }

    /// The generated GUID must round-trip through the credential form the login regex matches.
    #[test]
    fn a_generated_guid_survives_the_credential_round_trip() {
        for _ in 0..64 {
            let credential = credentials(&generate_pairing_guid());
            assert!(
                crate::daap::url::classify(&credential).is_ok(),
                "{credential} must be usable as a login credential"
            );
        }
    }

    /// `"0x" + guid` (`pairing.py:275`), mixed case and all.
    #[test]
    fn the_credential_form_is_a_lowercase_prefix_on_uppercase_digits() {
        assert_eq!(credentials("0000000000000001"), "0x0000000000000001");
        assert_eq!(credentials("1234abcde56789ff"), "0x1234ABCDE56789FF");
        assert_eq!(credentials("0x1234ABCDE56789FF"), "0x1234ABCDE56789FF");
    }

    /// Upstream slices two characters off blindly; this checks for the prefix instead.
    #[test]
    fn normalising_only_strips_an_actual_prefix() {
        assert_eq!(normalise_pairing_guid("0x00ff"), "00FF");
        assert_eq!(normalise_pairing_guid("0X00ff"), "00FF");
        assert_eq!(
            normalise_pairing_guid("00ff"),
            "00FF",
            "a bare hex string keeps all of its digits"
        );
    }
}
