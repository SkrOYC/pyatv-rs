//! Punycode (RFC 3492) decoding for `xn--` labels.
//!
//! pyatv's `parse_domain_name` hands any label starting with `xn--` to Python's built-in `idna`
//! codec. Doing the same in Rust would mean pulling in the `idna` crate, which since 1.0 drags the
//! whole ICU4X stack (`icu_normalizer`, `icu_properties`, `icu_collections`, `zerovec`, ...) behind
//! it. That is a very large dependency for a path pyatv itself documents as never being exercised —
//! "Apple doesn't seem to use IDNA anywhere in their mDNS/DNS-SD stack". So the Bootstring decoder
//! is transcribed from the reference implementation in RFC 3492 section 6.2 / appendix C instead.
//!
//! **Deviation from pyatv:** Python's `idna` codec implements IDNA 2003 `ToUnicode`, which runs
//! Nameprep (case folding plus NFKC) over the result. This module performs the RFC 3492 decode and
//! nothing else. For the ASCII-lowercase ACE labels that exist in the wild the two agree; for
//! mixed-case ACE labels pyatv would additionally lowercase the basic code points.

/// Bootstring parameters for Punycode, RFC 3492 section 5.
const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;
const DELIMITER: u8 = b'-';

/// The ACE prefix that marks a Punycode-encoded label, RFC 3490 section 5.
pub const ACE_PREFIX: &str = "xn--";

/// Numeric value of a basic code point used as a digit, or `None` if it is not a digit.
///
/// RFC 3492 appendix C `decode_digit`, minus the branchless arithmetic.
const fn decode_digit(cp: u8) -> Option<u32> {
    match cp {
        b'0'..=b'9' => Some((cp - b'0') as u32 + 26),
        b'A'..=b'Z' => Some((cp - b'A') as u32),
        b'a'..=b'z' => Some((cp - b'a') as u32),
        _ => None,
    }
}

/// Bias adaptation, RFC 3492 section 6.1.
///
/// `numpoints` is always at least 1 at every call site, so the division is safe.
fn adapt(delta: u32, numpoints: u32, firsttime: bool) -> u32 {
    let mut delta = if firsttime { delta / DAMP } else { delta / 2 };
    delta += delta / numpoints;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
}

/// Decode the Punycode payload of an ACE label — the part *after* the `xn--` prefix.
///
/// Returns `None` for input that is not valid Punycode: a non-basic byte in the literal portion, a
/// non-digit in the extended portion, an arithmetic overflow, or a decoded value that is not a
/// Unicode scalar (a surrogate or a value above U+10FFFF).
///
/// This is RFC 3492 appendix C `punycode_decode`, with the case-flag bookkeeping dropped and every
/// arithmetic step checked.
// `n`, `i`, `w`, `k` and `t` are the RFC's own variable names. Renaming them to something clippy
// prefers would sever the correspondence with the reference implementation, which is the only thing
// making this function reviewable against the spec.
#[allow(
    clippy::many_single_char_names,
    reason = "variable names are taken verbatim from the RFC 3492 reference decoder"
)]
#[must_use]
pub fn decode(input: &str) -> Option<String> {
    let input = input.as_bytes();

    let mut n: u32 = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias: u32 = INITIAL_BIAS;
    let mut output: Vec<char> = Vec::new();

    // Copy the literal portion: everything before the last delimiter, or nothing if there is none.
    let basic_len = input.iter().rposition(|&cp| cp == DELIMITER).unwrap_or(0);
    for &cp in &input[..basic_len] {
        if !cp.is_ascii() {
            return None;
        }
        output.push(char::from(cp));
    }

    // Start just after the last delimiter if any literal code points were copied, else at 0.
    let mut in_pos = if basic_len > 0 { basic_len + 1 } else { 0 };

    while in_pos < input.len() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k: u32 = BASE;
        loop {
            let cp = *input.get(in_pos)?;
            in_pos += 1;
            let digit = decode_digit(cp)?;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }

        // `out + 1` in the reference; `output.len()` cannot overflow a u32 for any DNS label.
        let out_plus_one = u32::try_from(output.len()).ok()?.checked_add(1)?;
        bias = adapt(i - old_i, out_plus_one, old_i == 0);
        n = n.checked_add(i / out_plus_one)?;
        i %= out_plus_one;

        output.insert(usize::try_from(i).ok()?, char::from_u32(n)?);
        i += 1;
    }

    Some(output.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::decode;

    /// The fixture behind pyatv's `idna` domain-name test, taken from the Internationalized Domain
    /// Name Wikipedia page.
    #[test]
    fn decodes_the_pyatv_idna_fixture() {
        assert_eq!(decode("bcher-kva").as_deref(), Some("bücher"));
    }

    /// RFC 3492 section 7.1 sample strings, cases (A), (B), (D) and (L).
    ///
    /// The Arabic case is written with codepoint escapes rather than literal text: bidirectional
    /// text reorders visually in an editor, so a literal is very easy to corrupt while editing and
    /// impossible to eyeball against the RFC's `u+XXXX` list.
    #[test]
    fn decodes_rfc_3492_samples() {
        // (A) Arabic (Egyptian).
        assert_eq!(
            decode("egbpdaj6bu4bxfgehfvwxn").as_deref(),
            Some(
                "\u{644}\u{64A}\u{647}\u{645}\u{627}\u{628}\u{62A}\u{643}\u{644}\u{645}\u{648}\
                 \u{634}\u{639}\u{631}\u{628}\u{64A}\u{61F}"
            )
        );
        // (B) Chinese (simplified).
        assert_eq!(
            decode("ihqwcrb4cv8a8dqg056pqjye").as_deref(),
            Some("他们为什么不说中文")
        );
        // (D) Czech, which has a literal portion and therefore a delimiter.
        assert_eq!(
            decode("Proprostnemluvesky-uyb24dma41a").as_deref(),
            Some("Pročprostěnemluvíčesky")
        );
        // (L) Japanese, mixing ASCII and ideographs.
        assert_eq!(
            decode("3B-ww4c5e180e575a65lsy2b").as_deref(),
            Some("3年B組金八先生")
        );
        // A label with no extended portion at all.
        assert_eq!(decode("").as_deref(), Some(""));
    }

    #[test]
    fn rejects_malformed_input() {
        // '!' is not a Bootstring digit.
        assert_eq!(decode("bcher-kv!"), None);
        // Non-ASCII in the literal portion.
        assert_eq!(decode("bü-cher-kva"), None);
        // A digit run long enough to push the code point past U+10FFFF.
        assert_eq!(decode(&"z".repeat(63)), None);
        // Truncated: '9' is digit 35, which is never below the threshold, so the variable-length
        // integer runs off the end of the input instead of terminating.
        assert_eq!(decode("999"), None);
        // "zzz" by contrast is perfectly valid Punycode — 'z' is digit 25, not 35.
        assert_eq!(decode("zzz").as_deref(), Some("\u{7BA5}"));
    }

    /// Every byte a 63-byte DNS label could hold, in every position, must decode or fail — never
    /// panic. This is the only input path in the crate that does unchecked-looking arithmetic.
    #[test]
    fn never_panics_on_arbitrary_label_bytes() {
        for byte in 0u8..=127 {
            for length in [0usize, 1, 2, 3, 8, 32, 63] {
                let input: String = core::iter::repeat_n(char::from(byte), length).collect();
                let _ = decode(&input);
                let _ = decode(&format!("prefix-{input}"));
                let _ = decode(&format!("{input}-suffix"));
            }
        }
    }
}
