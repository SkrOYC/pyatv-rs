//! URL construction and the credential-format dispatch.
//!
//! Port of `_mkurl` (`pyatv/protocols/dmap/daap.py:154-170`). Every DAAP command is a template
//! carrying an `[AUTH]` placeholder, which is replaced by the authentication parameters the
//! particular call needs — the credential on the login request, the session id on every other.

use crate::{Error, Result};

/// The login command template (`daap.py:93`).
///
/// Substituted, it is one of exactly two shapes:
///
/// ```text
/// login?pairing-guid=0xXXXXXXXXXXXXXXXX&hasFP=1
/// login?hsgid=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX&hasFP=1
/// ```
pub const LOGIN_CMD: &str = "login?[AUTH]&hasFP=1";

/// The placeholder every command template carries.
pub const AUTH_PLACEHOLDER: &str = "[AUTH]";

/// Which kind of credential a stored string is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// A pairing GUID from a DMAP pairing exchange: `0x` and sixteen hex digits.
    PairingGuid,
    /// A Home Sharing GUID, taken straight off the `hG` TXT property at scan time.
    HomeSharing,
}

impl Credential {
    /// The query parameter name this credential is sent as.
    #[must_use]
    pub const fn parameter(self) -> &'static str {
        match self {
            Self::PairingGuid => "pairing-guid",
            Self::HomeSharing => "hsgid",
        }
    }
}

/// Classify a stored credential string.
///
/// Reproduces `_mkurl`'s two `re.match` calls exactly, including that they are **prefix** matches:
/// `re.match` anchors at the start of the string but not at the end, so trailing junk after a
/// well-formed credential is accepted and sent as-is. That is upstream behaviour and a device would
/// reject the resulting login anyway.
///
/// # Errors
///
/// Returns [`Error::InvalidCredentials`] when the string matches neither shape, which is upstream's
/// `InvalidCredentialsError` (`daap.py:165-167`).
pub fn classify(credential: &str) -> Result<Credential> {
    if is_pairing_guid(credential) {
        Ok(Credential::PairingGuid)
    } else if is_home_sharing_id(credential) {
        Ok(Credential::HomeSharing)
    } else {
        Err(Error::InvalidCredentials(credential.to_owned()))
    }
}

/// `r"0x[0-9A-Fa-f]{16}"`, anchored at the start.
fn is_pairing_guid(credential: &str) -> bool {
    let Some(digits) = credential.strip_prefix("0x") else {
        return false;
    };
    digits.len() >= 16 && digits.as_bytes()[..16].iter().all(u8::is_ascii_hexdigit)
}

/// `r"[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}"`, anchored at the start.
fn is_home_sharing_id(credential: &str) -> bool {
    // The canonical 8-4-4-4-12 hyphenation.
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

    let bytes = credential.as_bytes();
    let mut offset = 0usize;
    for (index, width) in GROUPS.into_iter().enumerate() {
        if index > 0 {
            if bytes.get(offset) != Some(&b'-') {
                return false;
            }
            offset += 1;
        }
        let Some(group) = bytes.get(offset..offset + width) else {
            return false;
        };
        if !group.iter().all(u8::is_ascii_hexdigit) {
            return false;
        }
        offset += width;
    }
    true
}

/// Substitute `[AUTH]` in a command template.
///
/// `session` and `login_id` select which parameters go in, and the order is upstream's: the
/// credential is appended first and the session id is *inserted at position zero*
/// (`parameters.insert(0, ...)`, `daap.py:169`), so a hypothetical request carrying both would read
/// `session-id=...&pairing-guid=...`. No call site actually asks for both — the credential is sent
/// on the login request and nowhere else — but the ordering is reproduced rather than assumed away.
///
/// # Errors
///
/// Returns [`Error::InvalidCredentials`] when `login_id` is set and the credential matches neither
/// recognised shape.
pub fn mkurl(
    command: &str,
    credential: &str,
    session_id: u64,
    session: bool,
    login_id: bool,
) -> Result<String> {
    let mut parameters: Vec<String> = Vec::new();

    if login_id {
        let kind = classify(credential)?;
        parameters.push(format!("{}={credential}", kind.parameter()));
    }
    if session {
        parameters.insert(0, format!("session-id={session_id}"));
    }

    Ok(command.replace(AUTH_PLACEHOLDER, &parameters.join("&")))
}

#[cfg(test)]
mod tests {
    use super::{Credential, LOGIN_CMD, classify, mkurl};
    use crate::Error;

    const PAIRING_GUID: &str = "0x0000000000000001";
    const HSGID: &str = "12345678-6789-1111-2222-012345678911";

    /// The two credential shapes, from `tests/protocols/dmap/test_dmap_functional.py:27-28`.
    #[test]
    fn the_two_credential_shapes_are_recognised() {
        assert_eq!(
            classify(PAIRING_GUID).expect("valid"),
            Credential::PairingGuid
        );
        assert_eq!(classify(HSGID).expect("valid"), Credential::HomeSharing);
        assert_eq!(
            classify("0x1234ABCDE56789FF").expect("valid"),
            Credential::PairingGuid
        );
    }

    /// `re.match` anchors at the start only, so trailing junk is accepted upstream and here.
    #[test]
    fn matching_is_anchored_at_the_start_only() {
        assert_eq!(
            classify("0x0000000000000001-and-more").expect("prefix matches"),
            Credential::PairingGuid
        );
        assert_eq!(
            classify(&format!("{HSGID}trailing")).expect("prefix matches"),
            Credential::HomeSharing
        );
        assert!(classify(&format!("prefix{PAIRING_GUID}")).is_err());
    }

    /// A GUID that renders as fifteen digits is what pyatv's own generator can produce and its own
    /// login regex then rejects — see `docs/research/dmap-port-spec.md` §6.1, and
    /// [`crate::pairing`] for the side of that this port fixes.
    #[test]
    fn a_short_pairing_guid_is_rejected_exactly_as_upstream_rejects_it() {
        assert!(matches!(
            classify("0xF03A9CF4A983143"),
            Err(Error::InvalidCredentials(_))
        ));
    }

    #[test]
    fn anything_else_is_invalid() {
        for bad in [
            "",
            "0x",
            "0xZZZZZZZZZZZZZZZZ",
            "0000000000000001",
            "12345678-6789-1111-2222-01234567891",
            "12345678_6789_1111_2222_012345678911",
        ] {
            assert!(
                matches!(classify(bad), Err(Error::InvalidCredentials(_))),
                "{bad:?} should be invalid"
            );
        }
    }

    /// The two login URLs, verbatim (`daap.py:154-170`).
    #[test]
    fn the_login_url_carries_the_credential_and_no_session() {
        assert_eq!(
            mkurl(LOGIN_CMD, PAIRING_GUID, 0, false, true).expect("valid"),
            "login?pairing-guid=0x0000000000000001&hasFP=1"
        );
        assert_eq!(
            mkurl(LOGIN_CMD, HSGID, 0, false, true).expect("valid"),
            "login?hsgid=12345678-6789-1111-2222-012345678911&hasFP=1"
        );
    }

    /// Every other request carries the session id and never the credential.
    #[test]
    fn command_urls_carry_only_the_session_id() {
        assert_eq!(
            mkurl(
                "ctrl-int/1/playstatusupdate?[AUTH]&revision-number=0",
                PAIRING_GUID,
                55_555,
                true,
                false
            )
            .expect("valid"),
            "ctrl-int/1/playstatusupdate?session-id=55555&revision-number=0"
        );
        assert_eq!(
            mkurl(
                "ctrl-int/1/nowplayingartwork?mw=123&mh=456&[AUTH]",
                PAIRING_GUID,
                55_555,
                true,
                false
            )
            .expect("valid"),
            "ctrl-int/1/nowplayingartwork?mw=123&mh=456&session-id=55555"
        );
        assert_eq!(
            mkurl(
                "ctrl-int/1/setproperty?dacp.playingtime=45000&[AUTH]",
                PAIRING_GUID,
                55_555,
                true,
                false
            )
            .expect("valid"),
            "ctrl-int/1/setproperty?dacp.playingtime=45000&session-id=55555"
        );
    }

    /// `parameters.insert(0, ...)` puts the session id first (`daap.py:169`).
    #[test]
    fn the_session_id_is_inserted_before_the_credential() {
        assert_eq!(
            mkurl("x?[AUTH]", PAIRING_GUID, 7, true, true).expect("valid"),
            "x?session-id=7&pairing-guid=0x0000000000000001"
        );
    }

    /// A credential is only validated when it is actually going to be sent.
    #[test]
    fn a_bad_credential_only_matters_on_the_login_request() {
        assert!(mkurl("x?[AUTH]", "nonsense", 7, true, false).is_ok());
        assert!(mkurl("x?[AUTH]", "nonsense", 7, false, true).is_err());
    }
}
