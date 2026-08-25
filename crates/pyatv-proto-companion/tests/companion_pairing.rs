//! End-to-end Companion pairing against a hermetic device.
//!
//! The counterpart of `tests/protocols/companion/test_companion_auth.py`, run over a real loopback
//! TCP socket so that the frame header, the OPACK envelope, the TLV8 bodies, the transport keys and
//! the session bring-up are all exercised together rather than mocked apart.
//!
//! The device is [`pyatv_pairing::server::ReferenceAccessory`] behind the Companion framing in
//! `support::fake_companion`, so every run is deterministic in everything but the ephemeral keys.

use pyatv_proto_companion::test_support as support;

use std::sync::Arc;

use pyatv_core::consts::{PairingRequirement, Protocol};
use pyatv_core::interface::PairingHandler;
use pyatv_core::models::BaseService;
use pyatv_core::storage::{MemoryStorage, Storage};
use pyatv_opack::Value;
use pyatv_pairing::server::PIN_CODE;
use pyatv_pairing::{AuthenticationType, HapCredentials};
use pyatv_proto_companion::pairing::{CompanionPairingHandler, CompanionPairingOptions, verify};
use pyatv_proto_companion::session::{SystemInfo, begin_session};

use support::fake_companion::FakeCompanionDevice;
use support::fake_state::REMOTE_SID;

/// The identifier a paired device is filed under in storage.
const DEVICE_IDENTIFIER: &str = "AA:BB:CC:DD:EE:FF";

/// Build the handler a `pyatv::pair(…, Protocol::Companion, …)` call would return.
fn handler(device: &FakeCompanionDevice, storage: Arc<dyn Storage>) -> CompanionPairingHandler {
    let mut service = BaseService::new(Protocol::Companion, device.address().port());
    service.identifier = Some(DEVICE_IDENTIFIER.to_owned());
    // What `rpfl=0x367A2` resolves to (`docs/research/companion-port-spec.md` §4.5).
    service.pairing = PairingRequirement::Mandatory;

    CompanionPairingHandler::new(
        CompanionPairingOptions {
            address: device.address().ip(),
            service,
            device_identifier: DEVICE_IDENTIFIER.to_owned(),
            setup: pyatv_proto_companion::auth::PairSetupOptionsCompanion::default(),
        },
        storage,
    )
}

/// The full `atvremote pair --protocol companion` sequence with the right PIN.
///
/// Proves that `PS_Start`, two `PS_Next` exchanges and the TLV8 inside each `_pd` line up well
/// enough for the device to accept the pairing and hand back credentials — and, because this port
/// diverges from pyatv by proving them, that a pair-verify on a second connection then succeeds
/// before `finish` reports success at all.
#[tokio::test]
async fn correct_pin_pairs_and_stores_credentials() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let storage = Arc::new(MemoryStorage::new());
    let handler = handler(&device, Arc::clone(&storage) as Arc<dyn Storage>);

    handler.begin().await.expect("pairing should begin");
    handler.pin(PIN_CODE).expect("PIN should be accepted");
    handler.finish().await.expect("pairing should finish");

    assert!(handler.has_paired());

    let credentials = handler
        .service()
        .credentials
        .expect("a successful pairing must leave credentials on the service");
    let parsed = HapCredentials::parse(&credentials).expect("credentials must parse");
    assert_eq!(parsed.authentication_type(), AuthenticationType::Hap);

    // The device's own view: it registered exactly one controller, with the public half of the key
    // the client just persisted.
    let accessory = device.accessory();
    let accessory = accessory.lock().await;
    assert_eq!(accessory.pairings().len(), 1);
    assert_eq!(accessory.pairings()[0].client_id, parsed.client_id);
    assert_eq!(parsed.ltpk, accessory.public_key().to_vec());
    assert_eq!(parsed.atv_id, accessory.identifier().to_vec());
    drop(accessory);

    assert!(
        device.state().lock().await.has_paired,
        "the device must agree that pairing completed"
    );

    // And storage holds the same string, under this device's identifier and the Companion slot.
    let stored = storage
        .find_settings(DEVICE_IDENTIFIER)
        .expect("storage must be readable")
        .expect("a settings record must have been written");
    assert_eq!(
        stored.protocols.credentials(Protocol::Companion),
        Some(credentials.as_str())
    );

    handler.close().await.expect("closing should succeed");
}

/// The credentials a successful pairing produced must verify on a fresh connection, encrypt it, and
/// carry the whole `_systemInfo`/`_sessionStart` bring-up chain.
///
/// This is the pair that matters in practice: pairing once and connecting later are two separate
/// invocations, and credentials that pair-setup accepts but pair-verify rejects would only show up
/// on the second one.
#[tokio::test]
async fn credentials_then_verify_encrypt_and_bring_up_a_session() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let storage = Arc::new(MemoryStorage::new());
    let handler = handler(&device, storage);

    handler.begin().await.expect("pairing should begin");
    handler.pin(PIN_CODE).expect("PIN should be accepted");
    handler.finish().await.expect("pairing should finish");

    let credentials = HapCredentials::parse(
        &handler
            .service()
            .credentials
            .expect("pairing must produce credentials"),
    )
    .expect("credentials must parse");
    handler.close().await.expect("closing should succeed");

    let (mut protocol, _events) = verify(device.address(), &credentials)
        .await
        .expect("pair-verify should succeed with the credentials just negotiated");
    assert!(
        protocol.is_encrypted(),
        "a successful pair-verify must install the transport keys"
    );

    let info = SystemInfo::new(credentials.client_id.clone());
    let session = begin_session(&mut protocol, &info)
        .await
        .expect("session bring-up should complete");

    // `_interest` is an Event, so `begin_session` returns without waiting for the device to see it;
    // give it a moment before asserting on the full command list.
    let state = device.state();
    for _ in 0..100u8 {
        if !state.lock().await.interests.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // The composite SID is the device's half in the high 32 bits and the client's in the low ones.
    let state = state.lock().await;
    let local_sid = state.local_sid.expect("_sessionStart must have been seen");
    assert_eq!(session.sid, (REMOTE_SID << 32) | local_sid);

    // The exact bring-up chain, in order (`api.py:135-159`). `_interest` is an Event, so it is
    // recorded but never answered.
    assert_eq!(
        state.commands,
        [
            "_systemInfo",
            "_touchStart",
            "_sessionStart",
            "TVRCSessionStart",
            "_tiStart",
            "_interest",
        ]
    );
    assert_eq!(state.interests, ["_iMC"]);
    assert!(state.saw_encrypted_traffic);

    // The device refuses any OPACK frame before pair-verify, so this arriving intact is itself
    // proof the transport keys and the bare-12-byte-counter nonce layout are right.
    let system_info = state
        .system_info
        .clone()
        .expect("_systemInfo must have arrived");
    assert_eq!(
        system_info.get("_sv").and_then(Value::as_str),
        Some("170.18")
    );
    assert_eq!(
        system_info
            .get("_idsID")
            .and_then(Value::as_bytes)
            .map(|id| id.to_vec()),
        Some(credentials.client_id)
    );
    drop(state);

    protocol.close().await.expect("closing should succeed");
}

/// A wrong PIN must fail at `finish`, leave `has_paired` false and write nothing.
///
/// The check that rejects it is the device's, not the controller's: the failure arrives as a
/// `{SeqNo: 4, Error: Authentication}` TLV inside the M4 `_pd`.
#[tokio::test]
async fn wrong_pin_fails_and_stores_nothing() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let storage = Arc::new(MemoryStorage::new());
    let handler = handler(&device, Arc::clone(&storage) as Arc<dyn Storage>);

    handler.begin().await.expect("pairing should begin");
    handler.pin(PIN_CODE + 1).expect("PIN should be accepted");

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
            .find_settings(DEVICE_IDENTIFIER)
            .expect("storage must be readable")
            .is_none(),
        "a failed pairing must not write credentials"
    );

    assert!(device.accessory().lock().await.pairings().is_empty());
    assert!(!device.state().lock().await.has_paired);

    handler.close().await.expect("closing should succeed");
}

/// `finish` without a PIN fails before a byte reaches the device, matching upstream's fail-fast
/// precondition check (`pairing.py:55-56`).
#[tokio::test]
async fn finishing_without_a_pin_is_refused_locally() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let handler = handler(&device, Arc::new(MemoryStorage::new()));

    handler.begin().await.expect("pairing should begin");

    let error = handler.finish().await.expect_err("no PIN means no pairing");
    assert!(!handler.has_paired(), "got {error:?}");
    assert!(device.accessory().lock().await.pairings().is_empty());

    handler.close().await.expect("closing should succeed");
}

/// Pairing must not be short-circuited by credentials that already exist, and re-pairing must
/// produce a *different* controller identity rather than reusing the old one
/// (`test_companion_auth.py::test_pairing_with_existing_credentials`).
#[tokio::test]
async fn re_pairing_over_existing_credentials_succeeds() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let storage = Arc::new(MemoryStorage::new());

    let mut first = None;
    for _ in 0..2u8 {
        let handler = handler(&device, Arc::clone(&storage) as Arc<dyn Storage>);
        handler.begin().await.expect("pairing should begin");
        handler.pin(PIN_CODE).expect("PIN should be accepted");
        handler.finish().await.expect("pairing should finish");

        let credentials = handler.service().credentials.expect("credentials");
        handler.close().await.expect("closing should succeed");

        match first.take() {
            None => first = Some(credentials),
            Some(previous) => assert_ne!(
                previous, credentials,
                "each pairing must generate a fresh controller keypair"
            ),
        }
    }

    assert_eq!(
        device.accessory().lock().await.pairings().len(),
        2,
        "the device must have registered both controllers"
    );
}

/// Credentials for a device this one is not must be refused, and must leave the connection in the
/// clear rather than half-encrypted.
#[tokio::test]
async fn unknown_credentials_fail_pair_verify() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;

    let credentials = HapCredentials::parse(&format!(
        "{}:{}:{}:{}",
        "00".repeat(32),
        "11".repeat(32),
        "22".repeat(36),
        "33".repeat(36)
    ))
    .expect("the fixture must parse");

    let error = verify(device.address(), &credentials)
        .await
        .expect_err("an unknown controller must not verify");
    assert!(
        matches!(
            pyatv_core::Error::from(error),
            pyatv_core::Error::Authentication(_) | pyatv_core::Error::Pairing(_)
        ),
        "a refused verify must be reported as an identity failure"
    );
}

/// Bring-up is refused locally on an unencrypted connection: every command below it is `E_OPACK`,
/// and a real device drops the connection instead of answering.
#[tokio::test]
async fn session_bring_up_needs_encryption_first() {
    use pyatv_proto_companion::{CompanionConnection, CompanionProtocol};

    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let connection = CompanionConnection::connect(device.address())
        .await
        .expect("connecting should work");
    let (mut protocol, _events) = CompanionProtocol::new(connection);

    let error = begin_session(&mut protocol, &SystemInfo::new(b"whoever".to_vec()))
        .await
        .expect_err("bring-up must refuse an unencrypted connection");
    assert!(
        matches!(error, pyatv_proto_companion::Error::NotReady(_)),
        "got {error:?}"
    );
    assert!(device.state().lock().await.commands.is_empty());
}
