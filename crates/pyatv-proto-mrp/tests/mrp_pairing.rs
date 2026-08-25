//! MRP pair-setup and pair-verify against a hermetic HAP accessory.
//!
//! Counterpart of `tests/protocols/mrp/test_mrp_auth.py`. Both halves run over a real socket with
//! real SRP and real Ed25519, so the credential string produced here is the same one a device would
//! have produced — which is what makes reusing it for pair-verify a meaningful test rather than a
//! round trip through this crate's own encoder.

use pyatv_proto_mrp::test_support as support;

use std::sync::Arc;

use pyatv_core::interface::PairingHandler;
use pyatv_core::storage::{InfoSettings, Storage};
use pyatv_core::{BaseService, Protocol};
use pyatv_pairing::server::PIN_CODE;
use pyatv_proto_mrp::auth::{MrpPairSetupProcedure, verify_credentials};
use pyatv_proto_mrp::{MrpPairingHandler, MrpPairingOptions};

use support::fake_mrp::FakeMrpDevice;
use support::harness::open;

#[tokio::test]
async fn pair_setup_produces_usable_credentials() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let protocol = open(&device).await;

    let procedure = MrpPairSetupProcedure::start(&protocol)
        .await
        .expect("pair-setup M1 must be answered");
    assert!(
        !procedure.client_id().is_empty(),
        "the controller must present a pairing identifier"
    );

    let credentials = procedure
        .finish(&protocol, PIN_CODE)
        .await
        .expect("pair-setup must complete");
    protocol.close().await.expect("closing must succeed");

    assert_eq!(
        device
            .accessory()
            .lock()
            .await
            .pairings()
            .first()
            .map(|pairing| pairing.client_id.clone()),
        Some(credentials.client_id.clone()),
        "the accessory must have stored the controller this port announced"
    );

    // The same credentials must now pair-verify on a fresh connection.
    let protocol = open(&device).await;
    protocol
        .exchange_device_info()
        .await
        .expect("DEVICE_INFO must be answered");
    let keys = verify_credentials(&protocol, credentials)
        .await
        .expect("pair-verify must succeed");
    assert_ne!(
        keys.output_key, keys.input_key,
        "the two directions must not share a key"
    );
    protocol.close().await.expect("closing must succeed");
}

#[tokio::test]
async fn a_wrong_pin_is_rejected() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let protocol = open(&device).await;

    let procedure = MrpPairSetupProcedure::start(&protocol)
        .await
        .expect("pair-setup M1 must be answered");
    let outcome = procedure.finish(&protocol, PIN_CODE + 1).await;

    assert!(
        outcome.is_err(),
        "a wrong PIN must fail rather than yield credentials"
    );
    assert!(
        device.accessory().lock().await.pairings().is_empty(),
        "nothing may be stored for a failed pairing"
    );
    protocol.close().await.expect("closing must succeed");
}

/// pyatv never checks the pair-setup M6 signature (`pyatv/auth/hap_srp.py:229`); this port does.
#[tokio::test]
async fn a_forged_accessory_signature_is_rejected() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.accessory().lock().await.corrupt_signatures(true);

    let protocol = open(&device).await;
    let procedure = MrpPairSetupProcedure::start(&protocol)
        .await
        .expect("pair-setup M1 must be answered");

    assert!(
        procedure.finish(&protocol, PIN_CODE).await.is_err(),
        "an accessory that signs with the wrong key must be refused"
    );
    protocol.close().await.expect("closing must succeed");
}

/// The whole [`PairingHandler`] lifecycle, including the persistence the facade relies on.
#[tokio::test]
async fn the_pairing_handler_persists_credentials() {
    let storage: Arc<dyn Storage> = Arc::new(pyatv_core::storage::MemoryStorage::default());
    let device = FakeMrpDevice::start(PIN_CODE).await;

    let handler = MrpPairingHandler::new(
        MrpPairingOptions {
            address: device.address().ip(),
            service: BaseService::new(Protocol::Mrp, device.address().port()),
            device_identifier: "AA:BB:CC:DD:EE:FF".to_owned(),
            info: InfoSettings::default(),
        },
        Arc::clone(&storage),
    );

    assert!(
        handler.device_provides_pin(),
        "MRP shows the PIN on the device"
    );
    assert!(!handler.has_paired(), "nothing is paired yet");

    handler.begin().await.expect("begin must succeed");
    handler.pin(PIN_CODE).expect("the PIN must be accepted");
    handler.finish().await.expect("finish must succeed");

    assert!(handler.has_paired(), "the handler must report success");
    assert!(
        handler
            .service()
            .credentials
            .as_deref()
            .is_some_and(|it| !it.is_empty()),
        "the service must carry the new credentials"
    );

    let settings = storage
        .find_settings("AA:BB:CC:DD:EE:FF")
        .expect("reading the store must succeed")
        .expect("a record must have been created");
    assert!(
        settings
            .protocols
            .mrp
            .credentials
            .as_deref()
            .is_some_and(|it| !it.is_empty()),
        "the credentials must be persisted under the MRP protocol"
    );

    handler.close().await.expect("closing must succeed");
}
