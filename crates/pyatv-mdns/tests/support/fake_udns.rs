//! A fake unicast DNS-SD responder, ported from pyatv's `tests/fake_udns.py`.
//!
//! Binds a UDP socket on an ephemeral loopback port and answers pyatv-shaped queries from a
//! declarative service table. The service constructors below carry the **exact** TXT dictionaries
//! `fake_udns.py` uses, because those define the canonical wire shape every pyatv scan test is
//! validated against.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use pyatv_mdns::dns::{DnsMessage, DnsQuestion, QueryType, RecordData};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use super::dns_utils::{answer, properties, resource, srv};

/// Response flags every fake answer carries: `QR` plus `AA` (`tests/fake_udns.py:190`).
pub const RESPONSE_FLAGS: u16 = 0x0840;

/// One service the fake responder knows about (`fake_udns.FakeDnsService`).
#[derive(Debug, Clone)]
pub struct FakeDnsService {
    /// Instance name, e.g. `Kitchen`.
    pub name: String,
    /// Addresses answered as `A` records under `{name}.local`.
    pub addresses: Vec<Ipv4Addr>,
    /// SRV port. Zero means no `SRV` record is emitted at all.
    pub port: u16,
    /// TXT entries, in order.
    pub properties: Vec<(String, Vec<u8>)>,
    /// When set, an extra `_device-info._tcp.local` TXT record carrying `model=` is synthesised.
    pub model: Option<String>,
}

/// A `(service type, service)` pair as the fixture constructors return.
pub type Registration = (String, FakeDnsService);

fn localhost() -> Vec<Ipv4Addr> {
    vec![Ipv4Addr::LOCALHOST]
}

fn props(entries: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).as_bytes().to_vec()))
        .collect()
}

/// `_mediaremotetv._tcp.local` (`fake_udns.py:28-47`). Default port 49152, build version `18M60`.
#[must_use]
pub fn mrp_service(
    service_name: &str,
    atv_name: &str,
    identifier: &str,
    port: u16,
) -> Registration {
    (
        "_mediaremotetv._tcp.local".to_owned(),
        FakeDnsService {
            name: service_name.to_owned(),
            addresses: localhost(),
            port,
            properties: props(&[
                ("Name", atv_name),
                ("UniqueIdentifier", identifier),
                ("SystemBuildVersion", "18M60"),
            ]),
            model: None,
        },
    )
}

/// `_airplay._tcp.local` (`fake_udns.py:50-69`).
///
/// The baseline is `deviceid` plus `features=0x1`. A `model` additionally forces
/// `flags=0x8` (PIN required) — upstream hardcodes that whenever a model is given, so this fixture
/// always produces a pairing-`Mandatory`-shaped service in that case.
#[must_use]
pub fn airplay_service(atv_name: &str, deviceid: &str, model: Option<&str>) -> Registration {
    let mut properties = props(&[("deviceid", deviceid), ("features", "0x1")]);
    if let Some(model) = model {
        properties.push(("model".to_owned(), model.as_bytes().to_vec()));
        properties.push(("flags".to_owned(), b"0x8".to_vec()));
    }

    (
        "_airplay._tcp.local".to_owned(),
        FakeDnsService {
            name: atv_name.to_owned(),
            addresses: localhost(),
            port: 7000,
            properties,
            model: model.map(str::to_owned),
        },
    )
}

/// `_appletv-v2._tcp.local`, DMAP via Home Sharing (`fake_udns.py:72-87`). Always port 3689.
#[must_use]
pub fn homesharing_service(service_name: &str, atv_name: &str, hsgid: &str) -> Registration {
    (
        "_appletv-v2._tcp.local".to_owned(),
        FakeDnsService {
            name: service_name.to_owned(),
            addresses: localhost(),
            port: 3689,
            properties: props(&[("hG", hsgid), ("Name", atv_name)]),
            model: None,
        },
    )
}

/// `_touch-able._tcp.local`, plain DMAP (`fake_udns.py:90-103`). Always port 3689.
#[must_use]
pub fn device_service(service_name: &str, atv_name: &str) -> Registration {
    (
        "_touch-able._tcp.local".to_owned(),
        FakeDnsService {
            name: service_name.to_owned(),
            addresses: localhost(),
            port: 3689,
            properties: props(&[("CtlN", atv_name)]),
            model: None,
        },
    )
}

/// `_companion-link._tcp.local` (`fake_udns.py:106-119`).
///
/// The TXT payload is only `rpHA` — deliberately no `rpfl` and no `rpmrtid`, so this fixture has no
/// usable identifier of its own, which is exactly why a lone Companion service is never discoverable.
#[must_use]
pub fn companion_service(service_name: &str, port: u16) -> Registration {
    (
        "_companion-link._tcp.local".to_owned(),
        FakeDnsService {
            name: service_name.to_owned(),
            addresses: localhost(),
            port,
            properties: props(&[("rpHA", "33efedd528a")]),
            model: None,
        },
    )
}

/// `_raop._tcp.local` (`fake_udns.py:122-136`).
///
/// The instance name is `{identifier}@{name}` and the properties are **empty** — none of RAOP's
/// `am`/`ov`/`et`/`md` keys are exercised by this fixture.
#[must_use]
pub fn raop_service(name: &str, identifier: &str, port: u16) -> Registration {
    (
        "_raop._tcp.local".to_owned(),
        FakeDnsService {
            name: format!("{identifier}@{name}"),
            addresses: localhost(),
            port,
            properties: Vec::new(),
            model: None,
        },
    )
}

/// `_hscp._tcp.local` (`fake_udns.py:139-158`). The instance name is the literal `HSCP Name`.
#[must_use]
pub fn hscp_service(name: &str, identifier: &str, hsgid: &str, port: u16) -> Registration {
    (
        "_hscp._tcp.local".to_owned(),
        FakeDnsService {
            name: "HSCP Name".to_owned(),
            addresses: localhost(),
            port,
            properties: props(&[
                ("Machine Name", name),
                ("Machine ID", identifier),
                ("hG", hsgid),
            ]),
            model: None,
        },
    )
}

/// A bare sleep-proxy registration, as `test_unicast_includes_sleep_proxy_service` uses.
#[must_use]
pub fn sleep_proxy_service(name: &str, port: u16) -> Registration {
    (
        "_sleep-proxy._udp.local".to_owned(),
        FakeDnsService {
            name: name.to_owned(),
            addresses: localhost(),
            port,
            properties: Vec::new(),
            model: None,
        },
    )
}

/// Find the service a question is about (`fake_udns._lookup_service`).
///
/// A question for a bare service type (`_x._tcp.local`) matches by type; anything else is treated
/// as `{instance}.{type}` split at the **first** dot and matched on both halves.
fn lookup_service<'a>(
    question: &DnsQuestion,
    services: &'a HashMap<String, FakeDnsService>,
) -> Option<(&'a FakeDnsService, String)> {
    if question.qname.starts_with('_') {
        let service = services.get(&question.qname)?;
        return Some((service, format!("{}.{}", service.name, question.qname)));
    }

    let (instance, service_type) = question.qname.split_once('.')?;
    services
        .iter()
        .find(|(name, service)| service_type == *name && instance == service.name)
        .map(|(_, service)| (service, question.qname.clone()))
}

/// Synthesise a response for a request (`fake_udns.create_response`).
///
/// `ip_filter` drops services that do not advertise that address, which is how upstream fakes a
/// per-host multicast scan. `sleep_proxy` answers service-type questions with a bare `PTR` and
/// nothing else, which is what a real Bonjour sleep proxy does for a dozing device.
#[must_use]
pub fn create_response(
    request: &[u8],
    services: &HashMap<String, FakeDnsService>,
    ip_filter: Option<Ipv4Addr>,
    sleep_proxy: bool,
) -> DnsMessage {
    let request = DnsMessage::unpack(request).expect("the client sends well-formed queries");

    let mut response = DnsMessage {
        msg_id: 0,
        flags: RESPONSE_FLAGS,
        questions: request.questions,
        ..DnsMessage::default()
    };

    for question in response.questions.clone() {
        let Some((service, full_name)) = lookup_service(&question, services) else {
            continue;
        };
        if ip_filter.is_some_and(|filter| !service.addresses.contains(&filter)) {
            continue;
        }

        response.answers.push(answer(&question.qname, &full_name));
        if sleep_proxy && question.qname.starts_with('_') {
            continue;
        }

        if service.port != 0 {
            response.resources.push(resource(
                &full_name,
                QueryType::SRV,
                srv(service.port, &format!("{}.local", service.name)),
            ));
        }
        for address in &service.addresses {
            response.resources.push(resource(
                &format!("{}.local", service.name),
                QueryType::A,
                RecordData::A(*address),
            ));
        }
        if !service.properties.is_empty() {
            let entries: Vec<(&str, &[u8])> = service
                .properties
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_slice()))
                .collect();
            response
                .resources
                .push(resource(&full_name, QueryType::TXT, properties(&entries)));
        }
        if let Some(model) = &service.model {
            response.resources.push(resource(
                &format!("{}._device-info._tcp.local", service.name),
                QueryType::TXT,
                properties(&[("model", model.as_bytes())]),
            ));
        }
    }

    response
}

/// Mutable knobs the tests turn between scans (`fake_udns.FakeUdns`'s attributes).
#[derive(Debug, Default)]
struct ServerState {
    services: HashMap<String, FakeDnsService>,
    /// Silently drop this many further requests, to exercise the client's resend loop.
    skip_count: usize,
    ip_filter: Option<Ipv4Addr>,
    sleep_proxy: bool,
}

/// A fake responder listening on an ephemeral loopback port.
#[derive(Debug)]
pub struct FakeUdns {
    port: u16,
    state: Arc<Mutex<ServerState>>,
    request_count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl FakeUdns {
    /// Bind and start serving.
    ///
    /// # Errors
    ///
    /// Returns the [`io::Error`] from binding the loopback socket.
    pub async fn start(services: Vec<Registration>) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = socket.local_addr()?.port();

        let state = Arc::new(Mutex::new(ServerState {
            services: services.into_iter().collect(),
            ..ServerState::default()
        }));
        let request_count = Arc::new(AtomicUsize::new(0));

        let task = tokio::spawn(serve(
            socket,
            Arc::clone(&state),
            Arc::clone(&request_count),
        ));

        Ok(Self {
            port,
            state,
            request_count,
            task,
        })
    }

    /// The ephemeral port the responder is listening on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Requests actually answered so far.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::Relaxed)
    }

    /// Replace the whole service table.
    pub fn set_services(&self, services: Vec<Registration>) {
        self.with_state(|state| state.services = services.into_iter().collect());
    }

    /// Drop the next `count` requests without answering.
    pub fn set_skip_count(&self, count: usize) {
        self.with_state(|state| state.skip_count = count);
    }

    /// Only answer for services advertising this address.
    pub fn set_ip_filter(&self, address: Option<Ipv4Addr>) {
        self.with_state(|state| state.ip_filter = address);
    }

    /// Answer service-type questions with a bare `PTR`, as a sleep proxy does.
    pub fn set_sleep_proxy(&self, enabled: bool) {
        self.with_state(|state| state.sleep_proxy = enabled);
    }

    fn with_state(&self, apply: impl FnOnce(&mut ServerState)) {
        let mut state = self.state.lock().expect("the fake responder never panics");
        apply(&mut state);
    }
}

impl Drop for FakeUdns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Receive requests and answer them from the current state.
async fn serve(socket: UdpSocket, state: Arc<Mutex<ServerState>>, request_count: Arc<AtomicUsize>) {
    let mut buffer = vec![0u8; 9_000];
    loop {
        let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
            return;
        };

        // The lock is released before the send; nothing is awaited while it is held.
        let response = {
            let mut state = state.lock().expect("the fake responder never panics");
            if state.skip_count > 0 {
                state.skip_count -= 1;
                continue;
            }
            create_response(
                &buffer[..length],
                &state.services,
                state.ip_filter,
                state.sleep_proxy,
            )
        };

        if socket.send_to(&response.pack(), source).await.is_err() {
            return;
        }
        request_count.fetch_add(1, Ordering::Relaxed);
    }
}
