//! What one protocol hands the facade when it has finished connecting.
//!
//! `SetupData` is the return of every protocol crate's `setup()` and the argument to
//! [`crate::facade::FacadeAppleTV::add_protocol`] — the one type the umbrella crate uses to join a
//! protocol implementation to the facade without either side naming the other. Split out of
//! `facade.rs` for module-size discipline; see `docs/research/pyatv-architecture.md` §3 for the
//! upstream contract it reproduces.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::consts::Protocol;
use crate::features::FeatureName;
use crate::interface::{
    Apps, Audio, Features, Keyboard, Metadata, Power, ProtocolHandle, PushUpdater, RemoteControl,
    Stream, TouchGestures, UserAccounts,
};
use crate::models::DeviceInfo;

/// What one protocol contributes to the facade once it has connected.
///
/// Every capability handle is optional: DMAP has no [`Apps`], RAOP has no [`RemoteControl`], and so
/// on. `features` is the set the protocol declares it *could* serve; live availability is resolved
/// by asking `features_impl` at call time, and the same set decides which trait methods this
/// registration is eligible to answer.
#[derive(Debug, Default)]
pub struct SetupData {
    /// Which protocol produced this data.
    pub protocol: Option<Protocol>,
    /// Features this protocol declares support for.
    pub features: BTreeSet<FeatureName>,
    /// The protocol's own live feature reporting, consulted for anything in `features`.
    pub features_impl: Option<Arc<dyn Features>>,
    /// Teardown hook, awaited by [`crate::interface::AppleTV::close`].
    pub handle: Option<Arc<dyn ProtocolHandle>>,
    /// Navigation and transport control, if implemented.
    pub remote_control: Option<Arc<dyn RemoteControl>>,
    /// Now-playing metadata, if implemented.
    pub metadata: Option<Arc<dyn Metadata>>,
    /// Push updates, if implemented.
    pub push_updater: Option<Arc<dyn PushUpdater>>,
    /// Media streaming, if implemented.
    pub stream: Option<Arc<dyn Stream>>,
    /// Power control, if implemented.
    pub power: Option<Arc<dyn Power>>,
    /// App management, if implemented.
    pub apps: Option<Arc<dyn Apps>>,
    /// Volume control, if implemented.
    pub audio: Option<Arc<dyn Audio>>,
    /// Keyboard entry, if implemented.
    pub keyboard: Option<Arc<dyn Keyboard>>,
    /// Trackpad gestures, if implemented.
    pub touch_gestures: Option<Arc<dyn TouchGestures>>,
    /// Account switching, if implemented.
    pub user_accounts: Option<Arc<dyn UserAccounts>>,
    /// Device facts this protocol was able to determine.
    pub device_info: DeviceInfo,
}
