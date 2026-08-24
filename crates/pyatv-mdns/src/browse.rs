//! Multicast browse and resolve.
//!
//! `mdns-sd` runs its own background thread and communicates over `flume` channels that expose both
//! blocking and async receive, so it composes with tokio without either crate depending on the
//! other. That is why this module can be async without `mdns-sd` being a tokio crate.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use pyatv_core::{BaseConfig, Protocol, Result};

use crate::service_types::ServiceType;

/// How long to browse for, and what to filter on.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// How long to keep listening for responses.
    pub timeout: Duration,
    /// Stop early once a device with one of these identifiers answers.
    pub identifiers: HashSet<String>,
    /// Only browse the service types backing these protocols. Empty means all of them.
    pub protocols: HashSet<Protocol>,
    /// Scan these hosts directly by unicast instead of browsing the multicast group.
    pub hosts: Vec<IpAddr>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            // pyatv's own default.
            timeout: Duration::from_secs(5),
            identifiers: HashSet::new(),
            protocols: HashSet::new(),
            hosts: Vec::new(),
        }
    }
}

impl ScanOptions {
    /// The service types this scan should browse, honouring the protocol filter.
    ///
    /// The enrichment-only types are always included: they carry model and OS details for devices
    /// found through any other type.
    #[must_use]
    pub fn service_types(&self) -> Vec<ServiceType> {
        ServiceType::ALL
            .into_iter()
            .filter(|service| match service.protocol() {
                None => true,
                Some(protocol) => self.protocols.is_empty() || self.protocols.contains(&protocol),
            })
            .collect()
    }
}

/// Browses the multicast group for every relevant service type.
#[derive(Debug)]
pub struct MulticastScanner {
    options: ScanOptions,
}

impl MulticastScanner {
    /// Build a scanner for the given options.
    #[must_use]
    pub fn new(options: ScanOptions) -> Self {
        Self { options }
    }

    /// Browse until the timeout elapses, or until every requested identifier has answered.
    ///
    /// # Errors
    ///
    /// Returns [`pyatv_core::Error::Io`] if the multicast socket cannot be opened, which on most
    /// systems means no interface has multicast enabled.
    // TODO(step-1): open one `ServiceDaemon`, `browse()` each type from
    // `ScanOptions::service_types`, collect `ServiceEvent::ServiceResolved` until the deadline,
    // then group by IP and merge per-service device-info extractor output into one BaseConfig per
    // device. See docs/research/pyatv-architecture.md §3.
    pub async fn discover(&self) -> Result<Vec<BaseConfig>> {
        let _ = &self.options;
        todo!("MulticastScanner::discover")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use pyatv_core::Protocol;

    use super::ScanOptions;
    use crate::service_types::ServiceType;

    #[test]
    fn no_protocol_filter_browses_everything() {
        assert_eq!(
            ScanOptions::default().service_types().len(),
            ServiceType::ALL.len()
        );
    }

    /// Filtering to one protocol keeps that protocol's types plus the enrichment-only ones.
    #[test]
    fn a_protocol_filter_keeps_the_enrichment_types() {
        let options = ScanOptions {
            protocols: HashSet::from([Protocol::Mrp]),
            ..ScanOptions::default()
        };

        assert_eq!(
            options.service_types(),
            vec![
                ServiceType::MediaRemoteTv,
                ServiceType::DeviceInfo,
                ServiceType::SleepProxy
            ]
        );
    }

    /// DMAP has three service types and all of them must survive the filter.
    #[test]
    fn filtering_to_dmap_keeps_all_three_of_its_types() {
        let options = ScanOptions {
            protocols: HashSet::from([Protocol::Dmap]),
            ..ScanOptions::default()
        };

        let types = options.service_types();
        assert!(types.contains(&ServiceType::AppleTvV2));
        assert!(types.contains(&ServiceType::TouchAble));
        assert!(types.contains(&ServiceType::Hscp));
        assert!(!types.contains(&ServiceType::MediaRemoteTv));
    }
}
