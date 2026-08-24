//! `~/.pyatv.conf` compatibility, against a file pyatv actually wrote.
//!
//! `tests/fixtures/pyatv-0.16.conf` is a verbatim copy of the settings file pyatv produced after
//! pairing Companion with an Apple TV — it holds nothing but that device's pairing credentials.
//! Every assertion here is about interoperability rather than about this crate's own round trip:
//! a user who has already paired with pyatv must keep working, and a file this crate writes must
//! be one pyatv's pydantic models accept unchanged.
//!
//! The Python side of the contract lives in `pyatv/settings.py`,
//! `pyatv/storage/__init__.py:36-40,168-175` and `pyatv/storage/file_storage.py:38-62`.

use std::net::{IpAddr, Ipv4Addr};

use pyatv_core::consts::Protocol;
use pyatv_core::models::{BaseConfig, BaseService};
use pyatv_core::storage::{FileStorage, MemoryStorage, Settings, Storage, StorageModel};

/// The file pyatv wrote, including its trailing newline.
const PYATV_CONF: &str = include_str!("fixtures/pyatv-0.16.conf");

/// The device the fixture describes, as a scan would report it.
const AIRPLAY_ID: &str = "DE:AD:BE:EF:00:01";
const COMPANION_ID: &str = "DEADBEEF-0001-4000-8000-000000000001";
const RAOP_ID: &str = "DEADBEEF0001";
const COMPANION_CREDENTIALS: &str = "0000000000000000000000000000000000000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000";

/// A scratch file that removes itself.
struct TempFile(std::path::PathBuf);

impl TempFile {
    fn with(name: &str, contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pyatv-rs-compat-{name}-{}.conf",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("the scratch file must be writable");
        Self(path)
    }

    /// A path in the scratch directory that does not exist yet.
    fn missing(name: &str) -> Self {
        let file = Self::with(name, "");
        std::fs::remove_file(&file.0).expect("the scratch file must be removable");
        file
    }

    fn read(&self) -> String {
        std::fs::read_to_string(&self.0).expect("the scratch file must be readable")
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        drop(std::fs::remove_file(&self.0));
    }
}

/// The device the fixture was written for, as `scan` would hand it over.
fn scanned_device() -> BaseConfig {
    let mut config = BaseConfig::new("Living Room", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6)));
    for (protocol, port, identifier) in [
        (Protocol::AirPlay, 7000, AIRPLAY_ID),
        (Protocol::Companion, 49153, COMPANION_ID),
        (Protocol::Raop, 7000, RAOP_ID),
    ] {
        let mut service = BaseService::new(protocol, port);
        service.identifier = Some(identifier.to_owned());
        config.add_service(service);
    }
    config
}

/// A file pyatv wrote loads, and the credentials come back out under the right protocol.
#[test]
fn a_file_pyatv_wrote_loads() {
    let file = TempFile::with("load", PYATV_CONF);
    let storage = FileStorage::new(&file.0);
    storage.load().expect("pyatv's own file must load");

    let settings = storage.settings().expect("readable");
    assert_eq!(settings.len(), 1);

    let device = &settings[0];
    assert_eq!(device.info.rp_id, "cafef00dfeed");
    assert_eq!(
        device.protocols.identifier(Protocol::AirPlay),
        Some(AIRPLAY_ID)
    );
    assert_eq!(
        device.protocols.identifier(Protocol::Companion),
        Some(COMPANION_ID)
    );
    assert_eq!(device.protocols.identifier(Protocol::Raop), Some(RAOP_ID));
    assert_eq!(
        device.protocols.credentials(Protocol::Companion),
        Some(COMPANION_CREDENTIALS)
    );
    assert_eq!(device.protocols.credentials(Protocol::AirPlay), None);

    // Nothing was stored for DMAP or MRP, and the untouched defaults come back untouched.
    assert_eq!(
        device.protocols.dmap,
        pyatv_core::storage::DmapSettings::default()
    );
    assert_eq!(
        device.protocols.mrp,
        pyatv_core::storage::MrpSettings::default()
    );
}

/// The device is found by any of its three identifiers, not just the main one.
#[test]
fn the_device_is_found_through_every_protocols_identifier() {
    let file = TempFile::with("lookup", PYATV_CONF);
    let storage = FileStorage::new(&file.0);
    storage.load().expect("load must succeed");

    for identifier in [AIRPLAY_ID, COMPANION_ID, RAOP_ID] {
        let found = storage
            .find_settings(identifier)
            .expect("readable")
            .unwrap_or_else(|| panic!("{identifier} must resolve to the stored device"));
        assert_eq!(
            found.protocols.credentials(Protocol::Companion),
            Some(COMPANION_CREDENTIALS)
        );
    }

    // And a config carrying only one of them resolves to the same record rather than a new one.
    let mut partial = BaseConfig::new("Living Room", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6)));
    let mut service = BaseService::new(Protocol::Companion, 49153);
    service.identifier = Some(COMPANION_ID.to_owned());
    partial.add_service(service);

    storage.get_settings(&partial).expect("lookup must succeed");
    assert_eq!(storage.settings().expect("readable").len(), 1);
}

/// Loading and saving pyatv's file reproduces it byte for byte.
///
/// This is the strongest form of the compatibility claim: not "equivalent JSON" but the same
/// bytes, separators (`", "` / `": "`) and trailing newline that
/// `json.dumps(dumped) + "\n"` produces.
#[test]
fn a_load_then_save_reproduces_the_file_byte_for_byte() {
    let source = TempFile::with("roundtrip-in", PYATV_CONF);
    let storage = FileStorage::new(&source.0);
    storage.load().expect("load must succeed");

    // Negatively: a save straight after the load writes nothing, because the document this crate
    // would emit is already exactly what the file holds. Deleting the file first makes that
    // observable — a save of so much as a differing byte would put it back.
    std::fs::remove_file(&source.0).expect("removable");
    storage.save().expect("save must succeed");
    assert!(
        !source.0.exists(),
        "a file already in pyatv's format must be recognised as unchanged"
    );

    // Positively: the same records written into an empty store produce the same bytes.
    let target = TempFile::missing("roundtrip-out");
    let fresh = FileStorage::new(&target.0);
    for settings in storage.settings().expect("readable") {
        fresh.set_settings(settings).expect("write must succeed");
    }
    fresh.save().expect("save must succeed");

    assert_eq!(target.read(), PYATV_CONF);
}

/// Parsed-JSON equality and an exact key-set comparison, independent of the byte check above.
#[test]
fn the_emitted_document_has_pyatvs_exact_key_set() {
    let file = TempFile::with("keys", PYATV_CONF);
    let storage = FileStorage::new(&file.0);
    storage.load().expect("load must succeed");

    let model = StorageModel {
        version: 1,
        devices: storage.settings().expect("readable"),
    };
    let ours: serde_json::Value = serde_json::to_value(&model).expect("serialising must succeed");
    let theirs: serde_json::Value =
        serde_json::from_str(PYATV_CONF).expect("the fixture must be valid JSON");

    assert_eq!(ours, theirs, "the parsed documents must be identical");

    // Spelled out, so a stray key added to any model shows up here rather than in a user's file.
    let device = &ours["devices"][0];
    assert_eq!(keys(&ours), ["devices", "version"]);
    assert_eq!(keys(device), ["info", "protocols"]);
    assert_eq!(keys(&device["info"]), ["rp_id"]);
    assert_eq!(
        keys(&device["protocols"]),
        ["airplay", "companion", "raop"],
        "a protocol with nothing but defaults must not be written"
    );
    assert_eq!(keys(&device["protocols"]["airplay"]), ["identifier"]);
    assert_eq!(
        keys(&device["protocols"]["companion"]),
        ["credentials", "identifier"]
    );
}

/// Pairing here produces a document shaped exactly like pyatv's.
#[test]
fn a_pairing_written_here_matches_pyatvs_shape() {
    let file = TempFile::missing("pairing");

    let storage = FileStorage::new(&file.0);
    storage.load().expect("a missing file must load as empty");

    // What `scan` does: file the device, identifiers and all.
    let config = scanned_device();
    storage
        .update_settings(&config)
        .expect("update must succeed");
    // What a Companion pairing handler does on success.
    storage
        .store_credentials(COMPANION_ID, Protocol::Companion, COMPANION_CREDENTIALS)
        .expect("storing credentials must succeed");
    storage.save().expect("save must succeed");

    let ours: serde_json::Value =
        serde_json::from_str(&file.read()).expect("what we wrote must be valid JSON");
    let theirs: serde_json::Value =
        serde_json::from_str(PYATV_CONF).expect("the fixture must be valid JSON");

    // Only `rp_id` may differ: it is freshly random for a device this store had not seen.
    assert_ne!(ours["devices"][0]["info"]["rp_id"], serde_json::Value::Null);
    let mut normalised = ours.clone();
    normalised["devices"][0]["info"]["rp_id"] = theirs["devices"][0]["info"]["rp_id"].clone();

    assert_eq!(normalised, theirs);
}

/// Keys pyatv's models do not have are dropped rather than rejected (`extra="ignore"`).
#[test]
fn unknown_keys_are_ignored_and_not_written_back() {
    let augmented = PYATV_CONF.replace(
        r#""info": {"rp_id": "cafef00dfeed"}"#,
        r#""info": {"rp_id": "cafef00dfeed", "future_field": 42}, "unknown_device_key": true"#,
    );
    assert_ne!(augmented, PYATV_CONF, "the fixture must have been patched");

    let file = TempFile::with("extra", &augmented);
    let storage = FileStorage::new(&file.0);
    storage.load().expect("unknown keys must not fail the load");

    storage.save().expect("save must succeed");
    assert_eq!(
        file.read(),
        PYATV_CONF,
        "the parse dropped the unknown keys, so saving must write the file back without them"
    );
}

/// A document from a future pyatv is refused rather than silently misread.
#[test]
fn a_version_mismatch_is_an_error() {
    let file = TempFile::with(
        "version",
        &PYATV_CONF.replace(r#""version": 1"#, r#""version": 2"#),
    );
    let storage = FileStorage::new(&file.0);

    let error = storage.load().expect_err("a foreign version must not load");
    assert!(
        error.to_string().contains("unsupported version: 2"),
        "unexpected error: {error}"
    );
}

/// Loading pyatv's credentials and applying them puts each on the right service.
#[test]
fn applying_the_stored_settings_credentials_the_scanned_services() {
    let file = TempFile::with("apply", PYATV_CONF);
    let storage = FileStorage::new(&file.0);
    storage.load().expect("load must succeed");

    let mut config = scanned_device();
    let settings = storage.get_settings(&config).expect("lookup must succeed");
    config.apply(&settings);

    assert_eq!(
        config
            .get_service(Protocol::Companion)
            .and_then(|it| it.credentials.as_deref()),
        Some(COMPANION_CREDENTIALS)
    );
    assert_eq!(
        config
            .get_service(Protocol::AirPlay)
            .and_then(|it| it.credentials.as_deref()),
        None
    );
    // And the scan did not create a second record for a device the file already knew.
    assert_eq!(storage.settings().expect("readable").len(), 1);
}

/// The in-memory backend answers the same questions, so tests never need a file.
#[test]
fn memory_storage_behaves_like_the_file_backend() {
    let storage = MemoryStorage::new();
    storage.load().expect("load must succeed");

    let config = scanned_device();
    let settings = storage.get_settings(&config).expect("lookup must succeed");
    assert_eq!(
        settings.protocols.identifier(Protocol::Companion),
        Some(COMPANION_ID)
    );

    storage
        .store_credentials(AIRPLAY_ID, Protocol::AirPlay, "creds")
        .expect("storing credentials must succeed");
    storage.save().expect("save must succeed");

    let stored = storage.get_settings(&config).expect("lookup must succeed");
    assert_eq!(
        stored.protocols.credentials(Protocol::AirPlay),
        Some("creds")
    );

    assert!(
        storage
            .remove_settings(&stored)
            .expect("removal must succeed")
    );
    assert!(storage.settings().expect("readable").is_empty());
}

/// A record whose only content is defaults still carries its `rp_id`, exactly as pydantic's
/// `exclude_defaults` dump does (`pyatv/storage/__init__.py:168-175`).
#[test]
fn a_default_record_is_never_empty() {
    let dumped = serde_json::to_value(Settings::default()).expect("serialising must succeed");
    assert_eq!(keys(&dumped), ["info"]);
    assert_eq!(keys(&dumped["info"]), ["rp_id"]);
}

/// The keys of a JSON object, sorted, for order-independent comparison.
fn keys(value: &serde_json::Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    keys
}
