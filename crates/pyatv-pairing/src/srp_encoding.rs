//! `srptools`' minimal big-endian integer encoding, shared by both SRP profiles.
//!
//! Every integer `srptools` feeds to a hash goes through `int_to_bytes`
//! (`srptools/utils.py:46-53`), which is `unhexlify(hex_from(val))` where `hex_from` renders an
//! integer as `'%x' % val` zero-padded only to an even number of hex digits. The result is the
//! *shortest* big-endian encoding of the value: leading zero bytes are gone, and zero itself is the
//! single byte `0x00`.
//!
//! That matters because pyatv hands the wire bytes of the accessory's `B` straight to
//! `SRPClientSession.process`, which parses them as an integer (`srptools/common.py:126-131`) and
//! only ever re-serialises them minimally when hashing. So when `B` happens to have a leading zero
//! byte — roughly one exchange in 256 — `M1 = H(… | A | B | K)` is computed over 383 bytes of `B`,
//! not 384. RustCrypto's `srp` hashes whatever slice it is given, so a port that forwards the raw
//! wire bytes silently produces a different `M1` for those exchanges and the accessory rejects the
//! PIN. The same applies to `A`, both as hashed and as put on the wire: pyatv transmits
//! `binascii.unhexlify(session.public)` (`hap_srp.py:159`), i.e. the minimal form.
//!
//! Both profiles route through [`minimal_be`] so the rule has exactly one implementation and one
//! set of tests: [`crate::srp_hap`] applies it to byte slices coming off the wire, and
//! [`crate::srp_legacy`] applies it to its `num-bigint` values, whose `to_bytes_be` is already
//! minimal for every value except zero.

/// The encoding of zero: `hex_from(0)` is `"0"`, padded to `"00"`, so one byte rather than none.
const ZERO: &[u8] = &[0x00];

/// Re-encode a big-endian integer in `srptools`' minimal form.
///
/// Strips leading zero bytes; an all-zero (or empty) input becomes the single byte `0x00`, matching
/// `int_to_bytes(0)`. Borrows rather than allocates, because every caller either hashes the result
/// immediately or copies it once.
#[must_use]
pub(crate) fn minimal_be(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte != 0) {
        Some(first) => &bytes[first..],
        None => ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::minimal_be;

    #[test]
    fn a_value_without_leading_zeros_is_unchanged() {
        assert_eq!(minimal_be(&[0x01, 0x00, 0x00]), &[0x01, 0x00, 0x00]);
        assert_eq!(minimal_be(&[0xFF]), &[0xFF]);
    }

    #[test]
    fn leading_zero_bytes_are_stripped() {
        assert_eq!(minimal_be(&[0x00, 0x01, 0x02]), &[0x01, 0x02]);
        assert_eq!(minimal_be(&[0x00, 0x00, 0x00, 0xAB]), &[0xAB]);
    }

    /// `int_to_bytes(0)` is `unhexlify("00")`, one byte — not the empty string. Getting this wrong
    /// would only ever matter for a degenerate value both profiles reject, but the helper has to
    /// agree with `srptools` everywhere or it is not a faithful port of the rule.
    #[test]
    fn zero_encodes_as_one_zero_byte() {
        assert_eq!(minimal_be(&[0x00]), &[0x00]);
        assert_eq!(minimal_be(&[0x00; 384]), &[0x00]);
        assert_eq!(minimal_be(&[]), &[0x00]);
    }
}
