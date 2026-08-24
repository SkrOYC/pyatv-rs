//! [`std::fmt::Display`] for [`BaseConfig`], split out of `mod.rs` for module-size discipline.

use super::BaseConfig;

impl std::fmt::Display for BaseConfig {
    /// Reproduces `pyatv/interface.py:1448-1463` (`BaseConfig.__str__`), which is exactly what
    /// `atvremote scan` prints per device. The column alignment, the ` - ` list prefix and the
    /// Python-style `None`/`True`/`False` renderings are all part of that output.
    ///
    /// [`BaseConfig::properties`] is deliberately absent: upstream's `__str__` never prints the
    /// Zeroconf property map, only the name, device info, address, MAC, deep-sleep flag,
    /// identifiers and services.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Upstream builds both blocks with `"\n".join(...)`, then interpolates them followed by a
        // literal "\n". An empty list therefore still costs one blank line. Reproduced, not tidied.
        let identifiers = self
            .all_identifiers()
            .iter()
            .map(|identifier| format!(" - {identifier}"))
            .collect::<Vec<_>>()
            .join("\n");
        let services = self
            .services
            .iter()
            .map(|service| format!(" - {service}"))
            .collect::<Vec<_>>()
            .join("\n");

        write!(
            f,
            "       Name: {name}\n   Model/SW: {device_info}\n    Address: {address}\n        MAC: {mac}\n Deep Sleep: {deep_sleep}\nIdentifiers:\n{identifiers}\nServices:\n{services}",
            name = self.name,
            device_info = self.device_info,
            address = self.address,
            mac = self.device_info.mac().unwrap_or("None"),
            deep_sleep = if self.deep_sleep { "True" } else { "False" },
        )
    }
}
