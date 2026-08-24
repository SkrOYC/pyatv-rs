//! AirPlay pairing and verification over HTTP.
//!
//! Port of `pyatv/protocols/airplay/auth/` (`__init__.py`, `hap.py`, `hap_transient.py`,
//! `legacy.py`). The crypto itself is `pyatv-pairing`'s; everything here is HTTP framing, route
//! selection and the choice of which of three exchanges to run.
//!
//! # Two independent decision axes
//!
//! `docs/research/hap-pairing-port-spec.md` §9.3 warns not to conflate these, and pyatv keeps them
//! in different files:
//!
//! - **Which exchange pair-*setup* runs** is chosen by AirPlay major version alone
//!   (`pyatv/protocols/airplay/pairing.py:50-57`): AirPlay 2 → [`AuthenticationType::Hap`],
//!   AirPlay 1 → [`AuthenticationType::Legacy`]. mDNS pairing flags play no part.
//! - **Which exchange pair-*verify* runs** is chosen by the credentials in hand, falling back to
//!   the advertised feature bits when there are none — see [`extract_credentials`].
//!
//! # The `X-Apple-HKP` header is the server-side switch
//!
//! `3` selects HAP, `4` selects transient, and legacy sends the header not at all
//! (`pyatv/protocols/airplay/server_auth.py:166-178,234-242`). A receiver answers `501 Not
//! Implemented` to a `/pair-verify` carrying anything other than `3`, and that `501` is precisely
//! how pyatv's own fake device routes a request to its legacy handler
//! (`tests/fake_device/airplay.py:193-197`) — the absence of a recognised value *is* the legacy
//! signal, not a separate route.

mod hap;
mod legacy;
mod transient;

use pyatv_core::airplay::{AirPlayFlags, parse_features};
use pyatv_core::models::BaseService;
use pyatv_pairing::hkdf_derive::transport::AIRPLAY_CONTROL;
use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::session::HapSession;
use pyatv_pairing::{AuthenticationType, HapCredentials};

pub use hap::{HapPairSetup, HapPairVerify};
pub use legacy::{LegacyPairSetupDriver, LegacyPairVerifyDriver, new_legacy_credentials};
pub use transient::TransientPairVerify;

use crate::codec::OCTET_STREAM_CONTENT_TYPE;
use crate::http::HttpConnection;
use crate::{Error, Result};

/// User agent every pairing request carries (`pyatv/protocols/airplay/auth/hap.py:21`).
///
/// Deliberately older than the [`crate::codec::USER_AGENT`] the RTSP and playback connections send;
/// pyatv uses two different strings and this port keeps both.
pub const PAIRING_USER_AGENT: &str = "AirPlay/320.20";

/// Route that makes the device display its PIN. All three exchanges post it first.
pub const PIN_START_PATH: &str = "/pair-pin-start";

/// Route carrying the HAP and transient pair-setup TLV8 messages.
pub const PAIR_SETUP_PATH: &str = "/pair-setup";

/// Route carrying the pair-verify messages, HAP and legacy alike.
pub const PAIR_VERIFY_PATH: &str = "/pair-verify";

/// `X-Apple-HKP` value selecting the HAP exchange.
pub const HKP_HAP: &str = "3";

/// `X-Apple-HKP` value selecting the transient exchange.
pub const HKP_TRANSIENT: &str = "4";

/// The four headers HAP and transient pairing send, in pyatv's dict order.
///
/// `_AIRPLAY_HEADERS` (`pyatv/protocols/airplay/auth/hap.py:20-25`,
/// `hap_transient.py:23-28`). `Content-Type` is present even on the bodyless `/pair-pin-start`
/// POST, because it sits in the same dict.
#[must_use]
pub fn hap_headers(hkp: &'static str) -> [(&'static str, &'static str); 4] {
    [
        ("User-Agent", PAIRING_USER_AGENT),
        ("Connection", "keep-alive"),
        ("X-Apple-HKP", hkp),
        ("Content-Type", OCTET_STREAM_CONTENT_TYPE),
    ]
}

/// The two headers legacy pairing sends (`pyatv/protocols/airplay/auth/legacy.py:19-22`).
///
/// No `X-Apple-HKP` and no `Content-Type`; each legacy request adds its own content type on top.
#[must_use]
pub fn legacy_headers() -> [(&'static str, &'static str); 2] {
    [
        ("User-Agent", PAIRING_USER_AGENT),
        ("Connection", "keep-alive"),
    ]
}

/// The controller half of one pair-setup exchange.
///
/// Only [`AuthenticationType::Hap`] and [`AuthenticationType::Legacy`] can be *set up*: there is
/// nothing to establish for a null or an ephemeral pairing (`auth/__init__.py:64-75`).
#[derive(Debug)]
pub enum PairSetupProcedure {
    /// Modern HAP pair-setup, M1–M6 over `/pair-setup`.
    Hap(Box<HapPairSetup>),
    /// Pre-HAP device authentication, three binary plists over `/pair-setup-pin`.
    Legacy(Box<LegacyPairSetupDriver>),
}

impl PairSetupProcedure {
    /// Build the procedure for an authentication type.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedAuthentication`] for [`AuthenticationType::Null`] and
    /// [`AuthenticationType::Transient`], matching pyatv's `NotSupportedError`
    /// (`auth/__init__.py:73-75`).
    pub fn new(auth_type: AuthenticationType) -> Result<Self> {
        tracing::debug!(?auth_type, "setting up AirPlay pair-setup procedure");

        match auth_type {
            AuthenticationType::Hap => Ok(Self::Hap(Box::new(HapPairSetup::new()))),
            AuthenticationType::Legacy => Ok(Self::Legacy(Box::new(LegacyPairSetupDriver::new(
                new_legacy_credentials(),
            )?))),
            AuthenticationType::Null | AuthenticationType::Transient => {
                Err(Error::UnsupportedAuthentication { auth_type })
            }
        }
    }

    /// Ask the device to show its PIN and exchange whatever precedes the PIN entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the device refuses a request, or [`Error::Pairing`] if its
    /// reply is not a well-formed message for this step.
    pub async fn start_pairing(&mut self, http: &mut HttpConnection) -> Result<()> {
        match self {
            Self::Hap(procedure) => procedure.start_pairing(http).await,
            Self::Legacy(procedure) => procedure.start_pairing(http).await,
        }
    }

    /// Complete the exchange with the PIN the user read off the screen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pairing`] if the device rejects the PIN or any proof fails to verify.
    pub async fn finish_pairing(
        &mut self,
        http: &mut HttpConnection,
        pin: u32,
    ) -> Result<HapCredentials> {
        match self {
            Self::Hap(procedure) => procedure.finish_pairing(http, pin).await,
            Self::Legacy(procedure) => procedure.finish_pairing(http, pin).await,
        }
    }
}

/// The controller half of one pair-verify exchange.
///
/// pyatv reaches the transient arm through a bare `else` (`auth/__init__.py:93-97`); this port
/// matches on it explicitly, as `hap-pairing-port-spec.md` §9.3 recommends, so that adding a fifth
/// authentication type would be a compile error rather than a silent misroute.
#[derive(Debug)]
pub enum PairVerifyProcedure {
    /// No credentials, so no verification and no keys.
    Null,
    /// Legacy device authentication, which proves identity but derives no transport keys.
    Legacy(LegacyPairVerifyDriver),
    /// HAP pair-verify against stored credentials.
    Hap(Box<HapPairVerify>),
    /// Transient pair-setup M1–M4, standing in for a verify.
    Transient(TransientPairVerify),
}

impl PairVerifyProcedure {
    /// Build the procedure the credentials call for.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pairing`] if legacy credentials carry a malformed seed.
    pub fn new(credentials: &HapCredentials) -> Result<Self> {
        let auth_type = credentials.authentication_type();
        tracing::debug!(?auth_type, "setting up AirPlay pair-verify procedure");

        Ok(match auth_type {
            AuthenticationType::Null => Self::Null,
            AuthenticationType::Legacy => Self::Legacy(LegacyPairVerifyDriver::new(credentials)?),
            AuthenticationType::Hap => Self::Hap(Box::new(HapPairVerify::new(credentials.clone()))),
            AuthenticationType::Transient => Self::Transient(TransientPairVerify::new()),
        })
    }

    /// Run the exchange, returning whether transport keys can now be derived.
    ///
    /// The legacy and null arms return `false`: legacy device authentication establishes no
    /// session keys at all (`auth/legacy.py:101,108-113`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAuthenticated`] if the device rejects the credentials, or
    /// [`Error::Pairing`] if a proof or signature does not verify.
    pub async fn verify_credentials(&mut self, http: &mut HttpConnection) -> Result<bool> {
        match self {
            Self::Null => {
                tracing::debug!("performing null pair-verify");
                Ok(false)
            }
            Self::Legacy(procedure) => procedure.verify_credentials(http).await.map(|()| false),
            Self::Hap(procedure) => procedure.verify_credentials(http).await.map(|()| true),
            Self::Transient(procedure) => procedure.verify_credentials(http).await.map(|()| true),
        }
    }

    /// Derive one channel's transport keys.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoEncryptionKeys`] for the null and legacy arms, and [`Error::Pairing`] if
    /// the exchange has not completed.
    pub fn encryption_keys(
        &self,
        salt: &str,
        output_info: &str,
        input_info: &str,
    ) -> Result<SessionKeys> {
        match self {
            Self::Null => Err(Error::NoEncryptionKeys("null pair-verify")),
            Self::Legacy(_) => Err(Error::NoEncryptionKeys("legacy device authentication")),
            Self::Hap(procedure) => Ok(procedure.encryption_keys(salt, output_info, input_info)?),
            Self::Transient(procedure) => {
                Ok(procedure.encryption_keys(salt, output_info, input_info)?)
            }
        }
    }
}

/// Verify a connection and, if that produced keys, encrypt it from here on.
///
/// Port of `verify_connection` (`pyatv/protocols/airplay/auth/__init__.py:100-117`). The salt and
/// info strings are the AirPlay control channel's; the returned procedure is kept so the caller can
/// derive the event and data-stream channels' keys from the same shared secret.
///
/// # Errors
///
/// Returns [`Error::NotAuthenticated`] if the device rejects the credentials, or [`Error::Pairing`]
/// if the exchange fails.
pub async fn verify_connection(
    credentials: &HapCredentials,
    http: &mut HttpConnection,
) -> Result<PairVerifyProcedure> {
    let mut verifier = PairVerifyProcedure::new(credentials)?;

    if verifier.verify_credentials(http).await? {
        let keys = verifier.encryption_keys(
            AIRPLAY_CONTROL.salt,
            AIRPLAY_CONTROL.write_info,
            AIRPLAY_CONTROL.read_info,
        )?;
        http.enable_encryption(HapSession::new(&keys.output_key, &keys.input_key));
    }

    Ok(verifier)
}

/// Decide which credentials to verify a service with.
///
/// Port of `extract_credentials` (`pyatv/protocols/airplay/auth/__init__.py:120-133`): stored
/// credentials win outright; otherwise a device advertising either AirPlay 2 pairing bit gets
/// transient credentials, and anything else gets none.
///
/// A feature string that will not parse reads as no flags here, where upstream would raise. One
/// malformed TXT record should not stop a connection attempt that may not need credentials at all.
///
/// # Errors
///
/// Returns [`Error::Pairing`] if the service's stored credential string is malformed.
pub fn extract_credentials(service: &BaseService) -> Result<HapCredentials> {
    if let Some(stored) = service.credentials.as_deref() {
        return Ok(HapCredentials::parse(stored)?);
    }

    let raw = service
        .property("features")
        .or_else(|| service.property("ft"))
        .unwrap_or("0x0");
    let flags = parse_features(raw).unwrap_or_else(|error| {
        tracing::debug!(%error, "unparsable AirPlay feature string, assuming no flags");
        AirPlayFlags::empty()
    });

    if flags.intersects(
        AirPlayFlags::SUPPORTS_SYSTEM_PAIRING
            | AirPlayFlags::SUPPORTS_CORE_UTILS_PAIRING_AND_ENCRYPTION,
    ) {
        return Ok(HapCredentials::transient());
    }

    Ok(HapCredentials::null())
}
