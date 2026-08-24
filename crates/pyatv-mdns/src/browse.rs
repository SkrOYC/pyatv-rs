//! The scanners: what to look for, how to look for it, and the `scan()` entry point.
//!
//! Ports `UnicastMdnsScanner` and `MulticastMdnsScanner` (`pyatv/core/scan.py:252-321`) plus the
//! dispatch in `pyatv/__init__.py:33-95`. All three are thin: they choose a transport, hand it the
//! service types to ask for, and pass whatever comes back to [`crate::scan::build_configs`], which
//! owns every rule that decides what a device actually is.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use pyatv_core::{BaseConfig, Protocol, Result};
use tokio::task::JoinSet;

use crate::knock;
use crate::mdns::{EndCondition, MDNS_PORT, MULTICAST_GROUP};
use crate::scan::{build_configs, unique_identifiers};
use crate::service::Response;
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
            // pyatv's own default (`pyatv/__init__.py:35`).
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
    /// found through any other type. Matches
    /// [`ScanRegistry::service_types`](crate::scan::ScanRegistry::service_types), which is the
    /// list upstream derives this from (`pyatv/core/scan.py:141-145`).
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

    /// The service types as the query names pyatv puts on the wire, i.e. without a trailing dot.
    #[must_use]
    fn query_names(&self) -> Vec<String> {
        self.service_types()
            .into_iter()
            .map(|service| service.as_str().trim_end_matches('.').to_owned())
            .collect()
    }

    /// The early-stop predicate for a multicast browse, or `None` when no identifier was given.
    ///
    /// Ports `_end_if_identifier_found` (`pyatv/core/scan.py:318-321`): the browse ends as soon as
    /// **any one** service on a responding device reports a wanted identifier — it does not wait
    /// for the device's other service types to answer.
    fn end_condition(&self) -> Option<EndCondition> {
        if self.identifiers.is_empty() {
            return None;
        }
        let wanted = self.identifiers.clone();
        Some(Box::new(move |response: &Response| {
            unique_identifiers(response)
                .iter()
                .any(|identifier| wanted.contains(identifier))
        }))
    }
}

/// Browses the multicast group for every relevant service type.
///
/// Ports `MulticastMdnsScanner` (`pyatv/core/scan.py:292-321`).
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

    /// Browse until the timeout elapses, or until a requested identifier has answered.
    ///
    /// # Errors
    ///
    /// Returns [`pyatv_core::Error::Io`] if the multicast socket cannot be opened, which on most
    /// systems means no interface has multicast enabled.
    pub async fn discover(&self) -> Result<Vec<BaseConfig>> {
        let responses = crate::mdns::multicast(
            &self.options.query_names(),
            MULTICAST_GROUP,
            MDNS_PORT,
            self.options.timeout,
            self.options.end_condition(),
        )
        .await?;

        Ok(build_configs(&responses, &self.options))
    }
}

/// Queries specific hosts directly rather than browsing the multicast group.
///
/// Ports `UnicastMdnsScanner` (`pyatv/core/scan.py:252-289`). Needed for `--scan-hosts`, and for
/// networks where multicast is unreliable or blocked outright — Docker bridges, most VLAN setups
/// and a good share of consumer mesh Wi-Fi.
#[derive(Debug)]
pub struct UnicastScanner {
    options: ScanOptions,
}

impl UnicastScanner {
    /// Build a scanner for the hosts named in `options`.
    #[must_use]
    pub fn new(options: ScanOptions) -> Self {
        Self { options }
    }

    /// The hosts this scanner will query.
    #[must_use]
    pub fn hosts(&self) -> &[IpAddr] {
        &self.options.hosts
    }

    /// Knock each host awake, query it, and turn the answers into configs.
    ///
    /// Ports `_get_services` (`pyatv/core/scan.py:272-289`). Two behaviours from there matter:
    ///
    /// - The port-knock (see [`crate::knock`]) is fired **before** the DNS query, because a device
    ///   asleep behind a sleep proxy will not answer until something touches a port it owns.
    /// - A host that does not answer in time degrades to an empty response rather than failing the
    ///   scan, so one unreachable host in `--scan-hosts` never costs you the others.
    ///
    /// # Errors
    ///
    /// Returns [`pyatv_core::Error::Io`] if no socket could be bound at all. Per-host failures are
    /// swallowed by the rule above.
    pub async fn discover(&self) -> Result<Vec<BaseConfig>> {
        let queries = self.options.query_names();
        let timeout = self.options.timeout;

        let mut hosts = JoinSet::new();
        for &host in &self.options.hosts {
            let queries = queries.clone();
            hosts.spawn(async move {
                // Fired first and raced against the query, then cancelled — upstream never awaits
                // the knocker, it just drops it once the DNS call resolves.
                let knocker = knock::knocker(host, knock::KNOCK_PORTS.to_vec(), timeout);
                let response = crate::mdns::unicast(host, &queries, MDNS_PORT, timeout).await;
                knocker.abort();
                (host, response)
            });
        }

        let mut responses = HashMap::new();
        while let Some(joined) = hosts.join_next().await {
            match joined {
                Ok((host, Ok(response))) => {
                    responses.insert(host, response);
                }
                Ok((host, Err(error))) => {
                    tracing::debug!(%host, %error, "unicast scan host did not answer");
                }
                Err(error) => tracing::debug!(%error, "unicast scan task did not finish"),
            }
        }

        Ok(build_configs(&responses, &self.options))
    }
}

/// Discover devices on the local network.
///
/// Ports `pyatv.scan` (`pyatv/__init__.py:33-95`) minus its `aiozc` and `storage` arguments:
/// hosts mean a unicast scan, no hosts mean a multicast browse. The identifier and protocol
/// filters are applied inside [`build_configs`], which is where upstream applies them too — the
/// protocol filter at handler-registration time, the identifier filter to the finished configs.
///
/// # Errors
///
/// Returns [`pyatv_core::Error::Io`] if no socket could be opened for discovery.
pub async fn scan(options: ScanOptions) -> Result<Vec<BaseConfig>> {
    if options.hosts.is_empty() {
        MulticastScanner::new(options).discover().await
    } else {
        UnicastScanner::new(options).discover().await
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

    /// pyatv queries for `_airplay._tcp.local`, with no trailing dot.
    #[test]
    fn query_names_drop_the_trailing_dot() {
        let names = ScanOptions::default().query_names();
        assert!(names.contains(&"_airplay._tcp.local".to_owned()));
        assert!(names.iter().all(|name| !name.ends_with('.')));
    }

    #[test]
    fn no_identifier_filter_means_no_early_stop() {
        assert!(ScanOptions::default().end_condition().is_none());
    }

    /// `_end_if_identifier_found` fires on *any* wanted identifier, not all of them.
    #[test]
    fn the_end_condition_fires_on_any_wanted_identifier() {
        use crate::scan::tests::fixtures;

        let options = ScanOptions {
            identifiers: HashSet::from(["mrp_id_1".to_owned()]),
            ..ScanOptions::default()
        };
        let end_condition = options.end_condition().expect("identifiers were given");

        assert!(end_condition(&fixtures::response(vec![
            fixtures::mrp_service("MRP Service", "MRP ATV", "mrp_id_1", fixtures::IP_1, 49152,)
        ])));
        assert!(!end_condition(&fixtures::response(vec![
            fixtures::airplay_service("AirPlay ATV", "AA:BB:CC:DD:EE:FF", fixtures::IP_1, 7000)
        ])));
    }
}
