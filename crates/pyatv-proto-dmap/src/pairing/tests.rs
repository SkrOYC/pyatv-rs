//! The pairing lifecycle, ported from `tests/protocols/dmap/test_dmap_pairing.py`.
//!
//! The device side is driven straight over TCP rather than through real mDNS: upstream's own tests
//! stub zeroconf out and read the port off the "registered" service
//! (`test_dmap_pairing.py:359-364`), and binding port 5353 in a test would be both slow and
//! environment-dependent. [`registration`] is asserted separately, so the advertisement is still
//! covered — just not by making an Apple TV find it.

use std::net::Ipv4Addr;
use std::sync::Arc;

use pyatv_core::interface::PairingHandler;
use pyatv_core::storage::{MemoryStorage, Storage};
use pyatv_core::{BaseService, Protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    DEVICE_TYPE, DmapPairingHandler, DmapPairingOptions, PAIRING_HOST, REMOTE_NAME,
    REMOTE_SERVICE_TYPE, REMOTE_VERSION, TXT_VERSION,
};
use crate::parser::{first_str, first_uint, parse};

const REMOTE_DISPLAY_NAME: &str = "pyatv remote";
const DEVICE_IDENTIFIER: &str = "dmapid";

// `test_dmap_pairing.py:336-354`.
const PIN_CODE: u32 = 1234;
const PAIRING_GUID: &str = "0x0000000000000001";
const PAIRING_CODE: &str = "690E6FF61E0D7C747654A42AED17047D";

const PIN_CODE2: u32 = 5555;
const PAIRING_GUID2: &str = "0x1234ABCDE56789FF";
const PAIRING_CODE2: &str = "58AD1D195B6DAA58AA2EA29DC25B81C3";

const PIN_CODE3: u32 = 1;
const PAIRING_GUID3: &str = "0x7D1324235F535AE7";
const PAIRING_CODE3: &str = "A34C3361C7D57D61CA41F62A8042F069";

/// A handler that publishes nothing, so no test needs port 5353.
fn handler(pairing_guid: Option<&str>) -> (DmapPairingHandler, Arc<MemoryStorage>) {
    let storage = Arc::new(MemoryStorage::new());
    let mut service = BaseService::new(Protocol::Dmap, 0);
    service.identifier = Some(DEVICE_IDENTIFIER.to_owned());

    let handler = DmapPairingHandler::new(
        DmapPairingOptions {
            name: REMOTE_DISPLAY_NAME.to_owned(),
            pairing_guid: pairing_guid.map(ToOwned::to_owned),
            addresses: Some(Vec::new()),
            ..DmapPairingOptions::new(service, DEVICE_IDENTIFIER)
        },
        Arc::clone(&storage) as Arc<dyn Storage>,
    );

    (handler, storage)
}

/// Play the Apple TV's part: `GET /pair?...` against the handler's own port.
///
/// This is `FakeDmapState.perform_pairing` (`tests/fake_device/dmap.py:92-107`), which is a plain
/// HTTP GET and a check of the returned container.
async fn pair_request(port: u16, code: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the pairing server is listening");
    stream
        .write_all(
            format!("GET /pair?pairingcode={code}&servicename=test HTTP/1.1\r\n\r\n").as_bytes(),
        )
        .await
        .expect("writes");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("reads");

    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a complete head")
        + 4;
    let status = String::from_utf8_lossy(&response[..head_end])
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status code");

    (status, response[head_end..].to_vec())
}

/// `test_succesful_pairing` (`test_dmap_pairing.py:435-450`): the full round trip, including that
/// the credential lands in **storage** and not only on the in-memory service.
#[tokio::test]
async fn a_successful_pairing_persists_the_credential() {
    let (handler, storage) = handler(Some(PAIRING_GUID));
    handler.begin().await.expect("begins");
    handler.pin(PIN_CODE).expect("sets the pin");

    let port = handler.port().expect("bound");
    let (status, body) = pair_request(port, PAIRING_CODE).await;
    assert_eq!(status, 200);

    let parsed = parse(&body).expect("a DMAP body");
    assert_eq!(first_uint(&parsed, &["cmpa", "cmpg"]), Some(1));
    assert_eq!(
        first_str(&parsed, &["cmpa", "cmnm"]),
        Some(REMOTE_DISPLAY_NAME)
    );
    assert_eq!(first_str(&parsed, &["cmpa", "cmty"]), Some("iPhone"));

    assert!(handler.has_paired());
    handler.finish().await.expect("finishes");

    assert_eq!(handler.service().credentials.as_deref(), Some(PAIRING_GUID));
    let settings = storage.settings().expect("readable");
    assert_eq!(
        settings[0].protocols.credentials(Protocol::Dmap),
        Some(PAIRING_GUID),
        "the credential must survive into storage, not just the service"
    );

    handler.close().await.expect("closes");
}

/// `test_pair_custom_pairing_guid` (`test_dmap_pairing.py:485-500`).
#[tokio::test]
async fn a_custom_guid_pairs_and_is_persisted_verbatim() {
    let (handler, storage) = handler(Some(PAIRING_GUID2));
    handler.begin().await.expect("begins");
    handler.pin(PIN_CODE2).expect("sets the pin");

    let (status, body) = pair_request(handler.port().expect("bound"), PAIRING_CODE2).await;
    assert_eq!(status, 200);
    assert_eq!(
        first_uint(&parse(&body).expect("a DMAP body"), &["cmpa", "cmpg"]),
        Some(0x1234_ABCD_E567_89FF)
    );

    handler.finish().await.expect("finishes");
    assert_eq!(
        handler.service().credentials.as_deref(),
        Some(PAIRING_GUID2)
    );
    assert_eq!(
        storage.settings().expect("readable")[0]
            .protocols
            .credentials(Protocol::Dmap),
        Some(PAIRING_GUID2)
    );
}

/// `test_succesful_pairing_with_pin_leadering_zeros` (`test_dmap_pairing.py:476-482`).
#[tokio::test]
async fn a_pin_with_leading_zeros_pairs() {
    let (handler, _) = handler(Some(PAIRING_GUID3));
    handler.begin().await.expect("begins");
    handler.pin(PIN_CODE3).expect("sets the pin");

    let (status, _) = pair_request(handler.port().expect("bound"), PAIRING_CODE3).await;
    assert_eq!(status, 200);
}

/// `test_succesful_pairing_with_any_pin` (`test_dmap_pairing.py:467-473`): no PIN set yet means
/// any code is accepted.
#[tokio::test]
async fn any_code_pairs_before_a_pin_is_set() {
    let (handler, _) = handler(Some(PAIRING_GUID));
    handler.begin().await.expect("begins");

    let (status, _) = pair_request(handler.port().expect("bound"), "invalid_pairing_code").await;
    assert_eq!(status, 200);
    assert!(handler.has_paired());
}

/// `test_failed_pairing` (`test_dmap_pairing.py:503-509`): a wrong code is a bodyless 500, and
/// nothing is persisted afterwards.
#[tokio::test]
async fn a_wrong_code_does_not_pair_or_persist() {
    let (handler, storage) = handler(Some(PAIRING_GUID));
    handler.begin().await.expect("begins");
    handler.pin(PIN_CODE).expect("sets the pin");

    let (status, body) = pair_request(handler.port().expect("bound"), "wrong").await;
    assert_eq!(status, 500);
    assert!(body.is_empty(), "there must be no cmpa container");
    assert!(!handler.has_paired());

    assert!(
        handler.finish().await.is_err(),
        "finishing without a pairing must not silently succeed"
    );
    assert!(handler.service().credentials.is_none());
    assert!(storage.settings().expect("readable").is_empty());
}

/// `test_successful_pairing_random_pairing_guid_generated` (`test_dmap_pairing.py:453-464`), minus
/// the monkey-patched RNG: what matters is that a generated GUID round-trips into a credential the
/// login regex accepts, which is the bug `code::pairing_guid_from` fixes.
#[tokio::test]
async fn a_generated_guid_pairs_and_yields_a_usable_credential() {
    let (handler, _) = handler(None);
    handler.begin().await.expect("begins");
    handler.pin(PIN_CODE).expect("sets the pin");

    let code = super::expected_code(handler.pairing_guid(), PIN_CODE);
    let (status, _) = pair_request(handler.port().expect("bound"), &code).await;
    assert_eq!(status, 200);

    handler.finish().await.expect("finishes");
    let credential = handler.service().credentials.expect("set");
    assert_eq!(credential.len(), 18, "0x plus sixteen digits");
    assert!(
        crate::daap::url::classify(&credential).is_ok(),
        "{credential} must be usable on the next login"
    );
}

/// Uniquely among this workspace's protocols, the *user* is given the PIN rather than reading one
/// off the screen (`pairing.py:283-286`).
#[test]
fn the_device_does_not_provide_the_pin() {
    let (handler, _) = handler(Some(PAIRING_GUID));
    assert!(!handler.device_provides_pin());
    assert!(!handler.has_paired());
}

/// `test_zeroconf_service_published` (`test_dmap_pairing.py:412-421`): the TXT record, verbatim and
/// case-sensitively.
#[test]
fn the_published_service_carries_pyatvs_txt_record() {
    let (handler, _) = handler(Some(PAIRING_GUID));
    let registration = handler.registration(Ipv4Addr::new(10, 0, 10, 1), 49_152);

    assert_eq!(registration.service_type, REMOTE_SERVICE_TYPE);
    assert_eq!(registration.host, PAIRING_HOST);
    assert_eq!(registration.port, 49_152);
    assert_eq!(registration.addresses, vec![Ipv4Addr::new(10, 0, 10, 1)]);
    assert_eq!(
        registration.properties,
        vec![
            ("DvNm".to_owned(), REMOTE_DISPLAY_NAME.to_owned()),
            ("RemV".to_owned(), REMOTE_VERSION.to_owned()),
            ("DvTy".to_owned(), DEVICE_TYPE.to_owned()),
            ("RemN".to_owned(), REMOTE_NAME.to_owned()),
            ("txtvers".to_owned(), TXT_VERSION.to_owned()),
            ("Pair".to_owned(), "0000000000000001".to_owned()),
        ]
    );
}

/// `f"{int(address):040d}"` (`pairing.py:302`): the address as a 32-bit integer, zero-padded to
/// forty decimal digits. Not human-meaningful, and reproduced anyway.
#[test]
fn the_instance_name_is_the_address_as_forty_decimal_digits() {
    let (handler, _) = handler(Some(PAIRING_GUID));

    let registration = handler.registration(Ipv4Addr::new(10, 0, 10, 1), 1);
    assert_eq!(registration.instance.len(), 40);
    // **Correction to `docs/research/dmap-port-spec.md` §2.1**, which gives `10.0.10.1` as
    // `167774977`. That is `0x0A000B01`, i.e. `10.0.11.1`; `10.0.10.1` is `0x0A000A01` =
    // `167774721`, which is what `int(IPv4Address("10.0.10.1"))` returns.
    assert_eq!(
        registration.instance,
        "0000000000000000000000000000000167774721"
    );
    assert_eq!(
        registration.instance.parse::<u32>().expect("decimal"),
        u32::from(Ipv4Addr::new(10, 0, 10, 1))
    );

    assert_eq!(
        handler
            .registration(Ipv4Addr::new(1, 2, 3, 4), 1)
            .instance
            .parse::<u32>()
            .expect("decimal"),
        0x0102_0304
    );
}

/// pyatv advertises itself as an iPod and answers as an iPhone. Both are upstream's.
#[test]
fn the_advertised_and_answered_device_types_differ() {
    assert_eq!(DEVICE_TYPE, "iPod");
    assert_eq!(super::RESPONSE_DEVICE_TYPE, "iPhone");
}

/// `test_zeroconf_custom_addresses` (`test_dmap_pairing.py:424-432`): one registration per address.
#[tokio::test]
async fn one_registration_is_published_per_address() {
    let storage = Arc::new(MemoryStorage::new());
    let handler = DmapPairingHandler::new(
        DmapPairingOptions {
            name: REMOTE_DISPLAY_NAME.to_owned(),
            pairing_guid: Some(PAIRING_GUID.to_owned()),
            // Deliberately empty so the test binds no multicast socket; the per-address shape is
            // asserted through `registration` instead.
            addresses: Some(Vec::new()),
            ..DmapPairingOptions::new(BaseService::new(Protocol::Dmap, 0), DEVICE_IDENTIFIER)
        },
        storage as Arc<dyn Storage>,
    );
    handler.begin().await.expect("begins");

    assert!(handler.registrations().is_empty());
    for address in [Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(10, 0, 10, 1)] {
        let registration = handler.registration(address, 1);
        assert_eq!(registration.addresses, vec![address]);
        assert_eq!(registration.service_type, REMOTE_SERVICE_TYPE);
    }
}

/// Closing twice must not panic: `close` is the teardown a caller may reach by more than one path.
#[tokio::test]
async fn closing_is_idempotent() {
    let (handler, _) = handler(Some(PAIRING_GUID));
    handler.begin().await.expect("begins");

    handler.close().await.expect("closes");
    handler.close().await.expect("closes again");
    assert!(handler.port().is_none());
}
