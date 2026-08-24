//! Pure helpers for interpreting `AirPlay` and RAOP mDNS TXT records.
//!
//! ## Why these live in `pyatv-core`
//!
//! Upstream keeps them in `pyatv/protocols/airplay/utils.py` and `pyatv/protocols/raop/parsers.py`,
//! but pyatv has no layering rule to break: `pyatv/core/scan.py` imports straight from the protocol
//! packages. This workspace does have one — `pyatv-mdns` may not depend on a protocol crate — and
//! discovery genuinely needs these functions, because a scan handler has to answer "does this
//! service need a password, does it need pairing, is it `AirPlay` 1 or 2" from the TXT record
//! alone, before any protocol code runs.
//!
//! Everything here is therefore restricted to the pure, TXT-derived subset: bit parsing and
//! service-detail classification. The I/O-bound parts of `airplay/utils.py` (the plist helpers, the
//! request/response logging, the dBFS volume mapping) stay in `pyatv-proto-airplay`, where they
//! belong.

mod features;
mod raop_parsers;
mod service_details;

pub use features::{
    AirPlayFlags, AirPlayMajorVersion, AirPlayVersion, InvalidFeatureString, get_protocol_version,
    parse_features,
};
pub use raop_parsers::{EncryptionType, MetadataType, get_encryption_types, get_metadata_types};
pub use service_details::{
    CredentialsKind, LEGACY_PAIRING_BIT, PASSWORD_BIT, PIN_REQUIRED, get_pairing_requirement,
    is_password_required, is_remote_control_supported, update_service_details,
};
