//! End-to-end AirPlay pairing against a hermetic receiver.
//!
//! The counterpart of `tests/protocols/airplay/test_airplay_auth.py` and
//! `tests/protocols/airplay/test_airplay_verify.py`, run over a real loopback TCP socket so that
//! the HTTP framing, the header set and the TLV8 bodies are all exercised together rather than
//! mocked apart.
//!
//! The accessory is [`pyatv_pairing::server::ReferenceAccessory`] with pyatv's fixed key material,
//! so every one of these runs is deterministic in everything except the two ephemeral keypairs.

mod support;

use std::sync::Arc;

use pyatv_core::consts::{PairingRequirement, Protocol};
use pyatv_core::interface::PairingHandler;
use pyatv_core::models::BaseService;
use pyatv_core::storage::{MemoryStorage, Storage};
use pyatv_pairing::server::AIRPLAY_PIN;
use pyatv_pairing::{AuthenticationType, HapCredentials};
use pyatv_proto_airplay::auth::{PairVerifyProcedure, verify_connection};
use pyatv_proto_airplay::{AirPlayPairingHandler, AirPlayPairingOptions, HttpConnection};

use support::fake_airplay::FakeAirPlayDevice;

/// The identifier a paired device is filed under in storage.
const DEVICE_IDENTIFIER: &str = "AA:BB:CC:DD:EE:FF";

/// Build the handler a `pyatv::pair(…, Protocol::AirPlay, …)` call would return.
fn handler(device: &FakeAirPlayDevice, storage: Arc<dyn Storage>) -> AirPlayPairingHandler {
    let mut service = BaseService::new(Protocol::AirPlay, device.address().port());
    service.identifier = Some(DEVICE_IDENTIFIER.to_owned());
    service.pairing = PairingRequirement::Mandatory;

    AirPlayPairingHandler::new(
        AirPlayPairingOptions {
            address: device.address().ip(),
            service,
            // Every modern receiver is AirPlay 2, which is what selects HAP pair-setup.
            airplay_version: pyatv_core::airplay::AirPlayMajorVersion::V2,
            device_identifier: DEVICE_IDENTIFIER.to_owned(),
            device_name: Some("Fake AirPlay ATV".to_owned()),
        },
        storage,
    )
}

/// The full `atvremote pair --protocol airplay` sequence, with the right PIN.
///
/// Proves that `/pair-pin-start`, four `/pair-setup` posts and the TLV8 bodies in between all line
/// up well enough for the accessory to accept the pairing and hand back credentials.
#[tokio::test]
async fn correct_pin_pairs_and_stores_credentials() {
    let device = FakeAirPlayDevice::start(AIRPLAY_PIN).await;
    let storage = Arc::new(MemoryStorage::new());
    let handler = handler(&device, Arc::clone(&storage) as Arc<dyn Storage>);

    handler.begin().await.expect("pairing should begin");
    handler.pin(AIRPLAY_PIN).expect("PIN should be accepted");
    handler.finish().await.expect("pairing should finish");

    assert!(handler.has_paired());

    let credentials = handler
        .service()
        .credentials
        .expect("a successful pairing must leave credentials on the service");
    let parsed = HapCredentials::parse(&credentials).expect("credentials must parse");
    assert_eq!(parsed.authentication_type(), AuthenticationType::Hap);

    // The accessory's own view: it registered exactly one controller, with the public half of the
    // key the client just persisted.
    let accessory = device.accessory();
    let accessory = accessory.lock().await;
    assert_eq!(accessory.pairings().len(), 1);
    assert_eq!(accessory.pairings()[0].client_id, parsed.client_id);
    assert_eq!(parsed.ltpk, accessory.public_key().to_vec());
    assert_eq!(parsed.atv_id, accessory.identifier().to_vec());
    drop(accessory);

    // And storage holds the same string, under this device's identifier and the AirPlay slot.
    let stored = storage
        .get_settings(DEVICE_IDENTIFIER)
        .expect("storage must be readable")
        .expect("a settings record must have been written");
    assert_eq!(stored.name.as_deref(), Some("Fake AirPlay ATV"));
    assert_eq!(
        stored.protocols[&Protocol::AirPlay].credentials.as_deref(),
        Some(credentials.as_str())
    );

    handler.close().await.expect("closing should succeed");
}

/// The credentials a successful pairing produced must then verify on a fresh connection.
///
/// This is the pair that matters in practice: pairing once and connecting later are two separate
/// invocations, and credentials that pair-setup accepts but pair-verify rejects would only show up
/// on the second one.
#[tokio::test]
async fn credentials_from_pairing_then_pass_pair_verify() {
    let device = FakeAirPlayDevice::start(AIRPLAY_PIN).await;
    let storage = Arc::new(MemoryStorage::new());
    let handler = handler(&device, storage);

    handler.begin().await.expect("pairing should begin");
    handler.pin(AIRPLAY_PIN).expect("PIN should be accepted");
    handler.finish().await.expect("pairing should finish");

    let credentials = HapCredentials::parse(
        &handler
            .service()
            .credentials
            .expect("pairing must produce credentials"),
    )
    .expect("credentials must parse");
    handler.close().await.expect("closing should succeed");

    let mut http = HttpConnection::connect(device.address())
        .await
        .expect("a second connection should open");
    assert!(!http.is_encrypted());

    let verifier = verify_connection(&credentials, &mut http)
        .await
        .expect("pair-verify should succeed with the credentials just negotiated");

    // Pair-verify derived control-channel keys and spliced them into the connection.
    assert!(matches!(verifier, PairVerifyProcedure::Hap(_)));
    assert!(http.is_encrypted());
}

/// A wrong PIN must fail at `finish`, leave `has_paired` false and write nothing.
///
/// The check that rejects it is the accessory's, not the controller's: pyatv's client-side SRP
/// proof comparison is a tautology (`docs/research/hap-pairing-port-spec.md` §11 finding 1), so the
/// failure arrives as an `{SeqNo: 4, Error: Authentication}` TLV in M4.
#[tokio::test]
async fn wrong_pin_fails_and_stores_nothing() {
    let device = FakeAirPlayDevice::start(AIRPLAY_PIN).await;
    let storage = Arc::new(MemoryStorage::new());
    let handler = handler(&device, Arc::clone(&storage) as Arc<dyn Storage>);

    handler.begin().await.expect("pairing should begin");
    handler
        .pin(AIRPLAY_PIN + 1)
        .expect("PIN should be accepted");

    let error = handler
        .finish()
        .await
        .expect_err("a wrong PIN must not pair");
    assert!(
        matches!(&error, pyatv_core::Error::Authentication(_)),
        "expected the device's HAP authentication error to surface, got {error:?}"
    );

    assert!(!handler.has_paired());
    assert!(handler.service().credentials.is_none());
    assert!(
        storage
            .get_settings(DEVICE_IDENTIFIER)
            .expect("storage must be readable")
            .is_none(),
        "a failed pairing must not write credentials"
    );

    let accessory = device.accessory();
    assert!(accessory.lock().await.pairings().is_empty());
}

/// Transient pairing needs no PIN and persists nothing, but must still end with usable keys.
///
/// pyatv has no test for this path at all (`hap-pairing-port-spec.md` §11 finding 7), so this is
/// the only check that the fixed PIN `3939`, the `Flags` TLV and the `X-Apple-HKP: 4` header line
/// up with what an accessory expects.
#[tokio::test]
async fn transient_pairing_succeeds_without_a_pin() {
    let device = FakeAirPlayDevice::start(AIRPLAY_PIN).await;

    let mut http = HttpConnection::connect(device.address())
        .await
        .expect("connection should open");

    let verifier = verify_connection(&HapCredentials::transient(), &mut http)
        .await
        .expect("transient pairing should succeed");

    assert!(matches!(verifier, PairVerifyProcedure::Transient(_)));
    assert!(http.is_encrypted());

    // Nothing was registered: transient pairing establishes no long-term identity.
    let accessory = device.accessory();
    assert!(accessory.lock().await.pairings().is_empty());
}

/// Credentials that name a device this accessory is not must be rejected, not silently accepted.
#[tokio::test]
async fn unknown_credentials_fail_pair_verify() {
    let device = FakeAirPlayDevice::start(AIRPLAY_PIN).await;

    let mut http = HttpConnection::connect(device.address())
        .await
        .expect("connection should open");

    let credentials = HapCredentials::parse(&format!(
        "{}:{}:{}:{}",
        "00".repeat(32),
        "11".repeat(32),
        "22".repeat(36),
        "33".repeat(36)
    ))
    .expect("the fixture must parse");

    let error = verify_connection(&credentials, &mut http)
        .await
        .expect_err("an unknown controller must not verify");
    assert!(
        !http.is_encrypted(),
        "a failed verify must not enable encryption, got {error:?}"
    );
}

/// A null credential means "no verification at all", and must not touch the socket or the keys.
#[tokio::test]
async fn null_credentials_skip_verification() {
    let device = FakeAirPlayDevice::start(AIRPLAY_PIN).await;

    let mut http = HttpConnection::connect(device.address())
        .await
        .expect("connection should open");

    let verifier = verify_connection(&HapCredentials::null(), &mut http)
        .await
        .expect("a null verify never fails");

    assert!(matches!(verifier, PairVerifyProcedure::Null));
    assert!(!http.is_encrypted());
}
