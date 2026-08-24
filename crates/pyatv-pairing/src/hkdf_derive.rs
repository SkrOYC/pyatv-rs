//! HKDF-SHA512 derivations and the exact salt/info string table.
//!
//! pyatv funnels every HAP-era derivation through one helper (`hap_srp.py::hkdf_expand`) with a
//! 32-byte output; only the legacy AirPlay path bypasses it in favour of raw SHA-512 concatenation
//! (see [`crate::legacy_auth`]). The string constants below are transcribed from
//! `docs/research/crypto-pairing.md` §3 and are load-bearing: a single wrong character produces a
//! key that decrypts to garbage with no earlier error to catch it.

use hkdf::Hkdf;
use sha2::Sha512;

use crate::{Error, Result};

/// Every derived key in the HAP stack is 32 bytes.
pub const KEY_LEN: usize = 32;

/// Derive 32 bytes with HKDF-SHA512.
///
/// # Errors
///
/// [`Hkdf::expand`] fails only when the requested output exceeds `255 * HashLen` — 16 320 bytes for
/// SHA-512 — which [`KEY_LEN`] cannot. The branch is unreachable and is reported as
/// [`Error::MalformedResponse`] rather than [`Error::KeyLength`]: the earlier `KeyLength { expected:
/// 32, actual: 0 }` described the *input* as being zero bytes long, which is both untrue (the IKM
/// is whatever the caller passed) and actively misleading during debugging, since an empty IKM is
/// perfectly legal for HKDF and never produces this error.
pub fn expand(salt: &str, info: &str, ikm: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut output = [0u8; KEY_LEN];
    Hkdf::<Sha512>::new(Some(salt.as_bytes()), ikm)
        .expand(info.as_bytes(), &mut output)
        .map_err(|_| {
            Error::MalformedResponse(format!(
                "HKDF-SHA512 refused a {KEY_LEN}-byte expansion for info {info:?}"
            ))
        })?;
    Ok(output)
}

/// Salt and info strings used during pair-setup and pair-verify.
///
/// Protocol-independent: MRP, Companion and AirPlay all use the same literals.
pub mod pairing {
    /// Salt for the controller's Ed25519 signing input (`iOSDeviceX`).
    pub const CONTROLLER_SIGN_SALT: &str = "Pair-Setup-Controller-Sign-Salt";
    /// Info for the controller's Ed25519 signing input.
    pub const CONTROLLER_SIGN_INFO: &str = "Pair-Setup-Controller-Sign-Info";

    /// Salt for the accessory's Ed25519 signing input. Only needed to implement the device role.
    pub const ACCESSORY_SIGN_SALT: &str = "Pair-Setup-Accessory-Sign-Salt";
    /// Info for the accessory's Ed25519 signing input.
    pub const ACCESSORY_SIGN_INFO: &str = "Pair-Setup-Accessory-Sign-Info";

    /// Salt for the M5/M6 TLV encryption key.
    pub const SETUP_ENCRYPT_SALT: &str = "Pair-Setup-Encrypt-Salt";
    /// Info for the M5/M6 TLV encryption key.
    pub const SETUP_ENCRYPT_INFO: &str = "Pair-Setup-Encrypt-Info";

    /// Salt for the M2/M3 pair-verify TLV encryption key.
    pub const VERIFY_ENCRYPT_SALT: &str = "Pair-Verify-Encrypt-Salt";
    /// Info for the M2/M3 pair-verify TLV encryption key.
    pub const VERIFY_ENCRYPT_INFO: &str = "Pair-Verify-Encrypt-Info";
}

/// The salt and the two direction info strings for one encrypted channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportKeys {
    /// HKDF salt.
    pub salt: &'static str,
    /// Info for the key this side writes with.
    pub write_info: &'static str,
    /// Info for the key this side reads with.
    pub read_info: &'static str,
}

/// Per-protocol transport key material, derived from the pair-verify X25519 shared secret.
pub mod transport {
    use super::TransportKeys;

    /// MRP's main connection.
    pub const MRP: TransportKeys = TransportKeys {
        salt: "MediaRemote-Salt",
        write_info: "MediaRemote-Write-Encryption-Key",
        read_info: "MediaRemote-Read-Encryption-Key",
    };

    /// Companion's main connection. The empty salt is not an oversight — pyatv passes `""`.
    pub const COMPANION: TransportKeys = TransportKeys {
        salt: "",
        write_info: "ClientEncrypt-main",
        read_info: "ServerEncrypt-main",
    };

    /// AirPlay's RTSP control connection.
    pub const AIRPLAY_CONTROL: TransportKeys = TransportKeys {
        salt: "Control-Salt",
        write_info: "Control-Write-Encryption-Key",
        read_info: "Control-Read-Encryption-Key",
    };

    /// AirPlay's event channel.
    ///
    /// The receiver opens this TCP connection, so the roles are physically reversed relative to
    /// every other channel and pyatv swaps which info string it uses for output versus input. The
    /// swap is applied at the call site, not here, so this constant keeps the same field meanings
    /// as its siblings — see `docs/research/crypto-pairing.md` §3 before wiring it up.
    pub const AIRPLAY_EVENTS: TransportKeys = TransportKeys {
        salt: "Events-Salt",
        write_info: "Events-Write-Encryption-Key",
        read_info: "Events-Read-Encryption-Key",
    };

    /// AirPlay's data-stream channel, which tunnels MRP over AirPlay 2.
    ///
    /// The salt is not this string alone: the client picks a random 64-bit seed per session,
    /// appends its decimal representation to `DataStream-Salt`, and sends the same seed to the
    /// device as an integer `seed` field in the RTSP `SETUP` body so both sides can reconstruct it.
    /// Use [`super::data_stream_salt`] to build it.
    pub const AIRPLAY_DATA_STREAM: TransportKeys = TransportKeys {
        salt: "DataStream-Salt",
        write_info: "DataStream-Output-Encryption-Key",
        read_info: "DataStream-Input-Encryption-Key",
    };
}

/// Build the AirPlay data-stream salt for a session seed, e.g. `DataStream-Salt3141592653589793`.
#[must_use]
pub fn data_stream_salt(seed: u64) -> String {
    format!("{}{seed}", transport::AIRPLAY_DATA_STREAM.salt)
}

#[cfg(test)]
mod tests {
    use super::{KEY_LEN, data_stream_salt, expand};

    #[test]
    fn expand_produces_a_thirty_two_byte_key() {
        let key = expand("Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", b"ikm").unwrap();
        assert_eq!(key.len(), KEY_LEN);
    }

    /// Deriving with a different salt or info must produce a different key; this is what makes the
    /// exact string constants matter.
    #[test]
    fn salt_and_info_both_affect_the_output() {
        let base = expand("salt", "info", b"ikm").unwrap();
        assert_ne!(base, expand("other", "info", b"ikm").unwrap());
        assert_ne!(base, expand("salt", "other", b"ikm").unwrap());
        assert_ne!(base, expand("salt", "info", b"other").unwrap());
    }

    /// Companion derives with an empty salt, which HKDF treats as a zero-filled salt block.
    #[test]
    fn empty_salt_is_accepted() {
        assert!(expand("", "ClientEncrypt-main", b"shared").is_ok());
    }

    #[test]
    fn data_stream_salt_appends_the_decimal_seed() {
        assert_eq!(
            data_stream_salt(3_141_592_653_589_793),
            "DataStream-Salt3141592653589793"
        );
    }
}
