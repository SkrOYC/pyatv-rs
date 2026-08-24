//! One protocol's connection details for a single physical device.
//!
//! Ports `pyatv/interface.py::BaseService` (`pyatv/interface.py:141-243`). pyatv splits the type
//! three ways — the abstract `BaseService`, the scanner-owned `core.MutableService`
//! (`pyatv/core/__init__.py:114-171`) and the user-facing `conf.ManualService`
//! (`pyatv/conf.py:99-143`) — purely so Python can express "these two fields are writable only
//! during set up". Rust's `&mut` already expresses that, so all three collapse into one struct.

use std::collections::HashMap;

use crate::consts::{PairingRequirement, Protocol};

/// One protocol's connection details for a single physical device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseService {
    /// Protocol-specific device identifier, as advertised over mDNS.
    pub identifier: Option<String>,
    /// Which protocol this service speaks.
    pub protocol: Protocol,
    /// TCP or UDP port, read from the mDNS SRV record — never hardcoded.
    pub port: u16,
    /// Whether the user has enabled this service for use.
    pub enabled: bool,
    /// Whether the device demands a password before this service can be used.
    pub requires_password: bool,
    /// Whether the service must be paired before use.
    pub pairing: PairingRequirement,
    /// Raw mDNS TXT record properties.
    ///
    /// **Invariant: every key is ASCII-lowercased.** Upstream stores these in a
    /// `CaseInsensitiveDict` (`pyatv/support/collections.py:53-130`), so pyatv code reads them by
    /// whatever casing the wire uses — `properties["SystemBuildVersion"]` and
    /// `properties["systembuildversion"]` are the same entry there. A plain [`HashMap`] cannot do
    /// that, so the lowercasing happens once, on the way in
    /// (`pyatv_mdns::dns::CaseInsensitiveMap::insert`), and every writer must uphold it.
    ///
    /// Consequence: **do not index this map with a wire-cased key.** `properties.get("Model")`
    /// silently returns `None`. Use [`BaseService::property`], which lowercases first.
    pub properties: HashMap<String, String>,
    /// Credentials previously negotiated for this service, in pyatv's colon-separated hex format.
    pub credentials: Option<String>,
    /// Password for services that require one.
    pub password: Option<String>,
}

impl BaseService {
    /// A minimal service with no credentials and everything else defaulted.
    ///
    /// The defaults are `MutableService.__init__`'s
    /// (`pyatv/core/__init__.py:121-136`): enabled, no password required, and
    /// [`PairingRequirement::Unsupported`] until a protocol's scan handler knows better.
    #[must_use]
    pub fn new(protocol: Protocol, port: u16) -> Self {
        Self {
            identifier: None,
            protocol,
            port,
            enabled: true,
            requires_password: false,
            pairing: PairingRequirement::Unsupported,
            properties: HashMap::new(),
            credentials: None,
            password: None,
        }
    }

    /// Look up a TXT property by any casing of its key.
    ///
    /// The stand-in for indexing pyatv's `CaseInsensitiveDict` (`BaseService.properties`), which
    /// upstream does with the wire spelling: `properties.get("Machine ID")`,
    /// `properties.get("UniqueIdentifier")`. [`BaseService::properties`] stores lowercased keys, so
    /// going through this accessor is what makes those spellings keep working.
    ///
    /// Prefer it over `service.properties.get(key)` in every new call site; the direct form is
    /// correct only when the key literal is already lowercase.
    #[must_use]
    pub fn property(&self, key: &str) -> Option<&str> {
        // Fast path: the caller already spelled the key the way it is stored, which is the common
        // case and avoids allocating for it.
        if let Some(value) = self.properties.get(key) {
            return Some(value.as_str());
        }
        self.properties
            .get(&key.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Fold another discovery result for the same protocol into this one.
    ///
    /// Ports `pyatv/interface.py:203-209` (`BaseService.merge`) exactly. Upstream merges **only**
    /// three fields, and the omissions are deliberate rather than accidental:
    ///
    /// - `credentials`: `self.credentials = other.credentials or self.credentials`, so `other`
    ///   wins only when it actually carries credentials. Python truthiness means an empty string
    ///   counts as absent, which is why `Some(String::new())` is treated like `None` here.
    /// - `password`: the same rule.
    /// - `properties`: `self._properties.update(other.properties)` — a per-key overwrite, so keys
    ///   present only on `self` survive and keys present on both take `other`'s value.
    /// - `identifier`, `protocol`, `port`, `enabled`, `requires_password` and `pairing` are
    ///   **not** merged. `BaseService.merge` never touches them, and
    ///   `pyatv/conf.py:56-65` (`AppleTV.add_service`) only reaches this method when the two
    ///   services already share a protocol, so the existing endpoint is kept as-is. Discovery
    ///   therefore keeps the port from whichever mDNS response arrived first.
    pub fn merge(&mut self, other: &Self) {
        if let Some(credentials) = other.credentials.as_deref().filter(|it| !it.is_empty()) {
            self.credentials = Some(credentials.to_owned());
        }
        if let Some(password) = other.password.as_deref().filter(|it| !it.is_empty()) {
            self.password = Some(password.to_owned());
        }
        for (key, value) in &other.properties {
            self.properties.insert(key.clone(), value.clone());
        }
    }

    /// Apply persisted settings, keeping the current value wherever the setting is unset.
    ///
    /// Ports `pyatv/interface.py:219-226` (`BaseService.apply`): unknown keys are ignored and a
    /// `None` value never clears an existing value.
    pub fn apply(&mut self, credentials: Option<&str>, password: Option<&str>) {
        if let Some(credentials) = credentials.filter(|it| !it.is_empty()) {
            self.credentials = Some(credentials.to_owned());
        }
        if let Some(password) = password.filter(|it| !it.is_empty()) {
            self.password = Some(password.to_owned());
        }
    }
}

impl std::fmt::Display for BaseService {
    /// Reproduces `pyatv/interface.py:228-238` (`BaseService.__str__`), which is what
    /// `atvremote scan` prints under `Services:`. `None` renders as Python's `None` so the output
    /// stays byte-comparable with upstream.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn optional(value: Option<&String>) -> &str {
            value.map_or("None", String::as_str)
        }

        write!(
            f,
            "Protocol: {}, Port: {}, Credentials: {}, Requires Password: {}, Password: {}, Pairing: {:?}",
            self.protocol,
            self.port,
            optional(self.credentials.as_ref()),
            if self.requires_password {
                "True"
            } else {
                "False"
            },
            optional(self.password.as_ref()),
            self.pairing,
        )?;
        if !self.enabled {
            f.write_str(" (Disabled)")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::BaseService;
    use crate::consts::{PairingRequirement, Protocol};

    fn service_with_credentials(credentials: Option<&str>) -> BaseService {
        let mut service = BaseService::new(Protocol::AirPlay, 7000);
        service.credentials = credentials.map(ToOwned::to_owned);
        service
    }

    /// pyatv reads these keys by their wire casing out of a `CaseInsensitiveDict`; the accessor is
    /// what keeps that working over a lowercase-keyed `HashMap`.
    #[test]
    fn property_lookup_ignores_key_case() {
        let mut service = BaseService::new(Protocol::Mrp, 49152);
        service
            .properties
            .insert("systembuildversion".into(), "18M60".into());
        service.properties.insert("model".into(), "J305AP".into());

        for spelling in [
            "SystemBuildVersion",
            "systembuildversion",
            "SYSTEMBUILDVERSION",
        ] {
            assert_eq!(service.property(spelling), Some("18M60"), "{spelling}");
        }
        assert_eq!(service.property("Model"), Some("J305AP"));
        assert_eq!(service.property("Machine ID"), None);
    }

    /// `self.credentials = other.credentials or self.credentials`.
    #[test]
    fn merge_takes_other_credentials_when_present() {
        let mut into = service_with_credentials(Some("old"));
        into.merge(&service_with_credentials(Some("new")));
        assert_eq!(into.credentials.as_deref(), Some("new"));
    }

    #[test]
    fn merge_keeps_own_credentials_when_other_has_none() {
        let mut into = service_with_credentials(Some("old"));
        into.merge(&service_with_credentials(None));
        assert_eq!(into.credentials.as_deref(), Some("old"));
    }

    /// Python treats `""` as falsy, so an empty credential string must not overwrite.
    #[test]
    fn merge_treats_empty_credentials_as_absent() {
        let mut into = service_with_credentials(Some("old"));
        into.merge(&service_with_credentials(Some("")));
        assert_eq!(into.credentials.as_deref(), Some("old"));
    }

    #[test]
    fn merge_applies_the_same_rule_to_password() {
        let mut into = BaseService::new(Protocol::Raop, 7000);
        into.password = Some("old".to_owned());

        let mut other = BaseService::new(Protocol::Raop, 7000);
        other.password = None;
        into.merge(&other);
        assert_eq!(into.password.as_deref(), Some("old"));

        other.password = Some("new".to_owned());
        into.merge(&other);
        assert_eq!(into.password.as_deref(), Some("new"));
    }

    /// `dict.update` semantics: per-key overwrite, no wholesale replacement.
    #[test]
    fn merge_updates_properties_key_by_key() {
        let mut into = BaseService::new(Protocol::AirPlay, 7000);
        into.properties.insert("only_mine".into(), "1".into());
        into.properties.insert("shared".into(), "mine".into());

        let mut other = BaseService::new(Protocol::AirPlay, 7000);
        other.properties.insert("shared".into(), "theirs".into());
        other.properties.insert("only_theirs".into(), "2".into());

        into.merge(&other);

        assert_eq!(
            into.properties.get("only_mine").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            into.properties.get("shared").map(String::as_str),
            Some("theirs")
        );
        assert_eq!(
            into.properties.get("only_theirs").map(String::as_str),
            Some("2")
        );
    }

    /// Upstream `merge` deliberately leaves everything else alone.
    #[test]
    fn merge_leaves_identifier_port_pairing_and_enabled_untouched() {
        let mut into = BaseService::new(Protocol::Mrp, 49152);
        into.identifier = Some("mine".to_owned());
        into.enabled = false;
        into.pairing = PairingRequirement::Mandatory;
        into.requires_password = true;

        let mut other = BaseService::new(Protocol::Mrp, 7000);
        other.identifier = Some("theirs".to_owned());
        other.enabled = true;
        other.pairing = PairingRequirement::NotNeeded;
        other.requires_password = false;

        into.merge(&other);

        assert_eq!(into.identifier.as_deref(), Some("mine"));
        assert_eq!(into.port, 49152);
        assert!(!into.enabled);
        assert_eq!(into.pairing, PairingRequirement::Mandatory);
        assert!(into.requires_password);
    }

    #[test]
    fn apply_never_clears_an_existing_value() {
        let mut service = service_with_credentials(Some("stored"));
        service.apply(None, None);
        assert_eq!(service.credentials.as_deref(), Some("stored"));

        service.apply(Some("fresh"), Some("hunter2"));
        assert_eq!(service.credentials.as_deref(), Some("fresh"));
        assert_eq!(service.password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn display_matches_pyatv_base_service_str() {
        let mut service = BaseService::new(Protocol::Mrp, 49152);
        service.pairing = PairingRequirement::Mandatory;
        assert_eq!(
            service.to_string(),
            "Protocol: MRP, Port: 49152, Credentials: None, Requires Password: False, \
             Password: None, Pairing: Mandatory"
        );
    }

    #[test]
    fn display_appends_disabled_marker() {
        let mut service = BaseService::new(Protocol::Dmap, 3689);
        service.enabled = false;
        assert!(service.to_string().ends_with(" (Disabled)"));
    }
}
