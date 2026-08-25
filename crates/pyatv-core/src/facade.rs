//! The facade that presents many protocol connections as one device.
//!
//! Equivalent to `pyatv/core/facade.py`. Each protocol crate's `setup()` produces a [`SetupData`]
//! describing which capability traits it can serve and which features it declares support for;
//! [`FacadeAppleTV::add_protocol`] files each handle into the matching
//! [`crate::relayer::Relayer`], and the assembled facade is what `pyatv::connect` hands back.
//!
//! See `docs/research/pyatv-architecture.md` §3 for the upstream `SetupData` contract and §6 for
//! the per-capability priority ordering reproduced in [`FacadeAppleTV::new`].
//!
//! # What a relayer selects on
//!
//! The declared feature set travels with each registration into the relayer, because it is what
//! decides *per method* which protocol answers — see [`crate::relayer`]. Without it a device
//! offering both `AirPlay` and RAOP would route `stream_file` to `AirPlay`, which does not
//! implement it, and the call would be unreachable.

pub mod audio;
pub mod device;
pub mod features;
pub mod input;
pub mod listeners;
pub mod metadata;
pub mod playback;
pub mod remote;
pub mod setup;
pub mod stream;
pub mod takeover;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::Result;
use crate::consts::Protocol;
use crate::interface::{
    AppleTV, Apps, Audio, AudioListener, BoxFuture, DeviceListener, Features, Keyboard,
    KeyboardListener, Metadata, Power, PowerListener, ProtocolHandle, PushUpdater, RemoteControl,
    Stream, TouchGestures, UserAccounts,
};
use crate::models::{BaseService, DeviceInfo};
use crate::relayer::Relayer;

pub use audio::FacadeAudio;
pub use device::{FacadeApps, FacadePower, FacadeUserAccounts};
pub use features::FacadeFeatures;
pub use input::{FacadeKeyboard, FacadeTouchGestures};
pub use listeners::{ListenerHub, StateDispatcher};
pub use metadata::FacadeMetadata;
pub use playback::FacadePushUpdater;
pub use remote::FacadeRemoteControl;
pub use setup::SetupData;
pub use stream::FacadeStream;
pub use takeover::{FacadeTakeover, Interface, TakeoverGuard, TakeoverRegistry};

/// The order every capability but [`Power`] resolves in.
///
/// `DEFAULT_PRIORITIES` verbatim (`pyatv/core/facade.py:37-43`). Upstream uses this one list for
/// remote control, metadata, push updates, streaming, apps, audio, keyboard, gestures and
/// accounts alike; only [`FacadeAppleTV`]'s power relayer overrides it.
pub const DEFAULT_PRIORITIES: [Protocol; 5] = [
    Protocol::Mrp,
    Protocol::Dmap,
    Protocol::Companion,
    Protocol::AirPlay,
    Protocol::Raop,
];

/// Power resolution order, preferring Companion.
///
/// `FacadePower.OVERRIDE_PRIORITIES` (`pyatv/core/facade.py:311-318`), whose own comment reads
/// "Generally favor Companion as it implements power better than MRP".
pub const POWER_PRIORITIES: [Protocol; 5] = [
    Protocol::Companion,
    Protocol::Mrp,
    Protocol::Dmap,
    Protocol::AirPlay,
    Protocol::Raop,
];

/// Unified view of one device across every connected protocol.
#[derive(Debug)]
pub struct FacadeAppleTV {
    remote_control: Arc<Relayer<dyn RemoteControl>>,
    metadata: Arc<Relayer<dyn Metadata>>,
    push_updater: Arc<Relayer<dyn PushUpdater>>,
    stream: Arc<Relayer<dyn Stream>>,
    power: Arc<Relayer<dyn Power>>,
    apps: Arc<Relayer<dyn Apps>>,
    audio: Arc<Relayer<dyn Audio>>,
    keyboard: Arc<Relayer<dyn Keyboard>>,
    touch_gestures: Arc<Relayer<dyn TouchGestures>>,
    user_accounts: Arc<Relayer<dyn UserAccounts>>,
    features: Arc<FacadeFeatures>,
    /// The long-lived relaying wrappers handed out by the [`AppleTV`] accessors.
    ///
    /// They are built once and shared rather than created per call because a caller keeps one
    /// across a takeover — that is the behaviour `test_takeover_and_release`
    /// (`tests/core/test_facade.py:544-566`) pins — and because [`FacadePushUpdater`] owns the
    /// listener shims it registered with each protocol.
    facades: Facades,
    takeover: Arc<TakeoverRegistry>,
    handles: Vec<(Protocol, Arc<dyn ProtocolHandle>)>,
    listeners: Arc<ListenerHub>,
    device_info: DeviceInfo,
    service: BaseService,
}

/// The per-interface relaying objects a caller receives.
///
/// There is one per capability trait, because upstream relays *every* method of *every* interface
/// (`facade.py:47-679`): resolving the protocol once per call is what makes a takeover visible to a
/// handle taken before it, and what stops a higher-priority protocol answering a method it never
/// declared.
#[derive(Debug)]
struct Facades {
    remote_control: Arc<FacadeRemoteControl>,
    metadata: Arc<FacadeMetadata>,
    audio: Arc<FacadeAudio>,
    stream: Arc<FacadeStream>,
    push_updater: Arc<FacadePushUpdater>,
    power: Arc<FacadePower>,
    apps: Arc<FacadeApps>,
    keyboard: Arc<FacadeKeyboard>,
    touch_gestures: Arc<FacadeTouchGestures>,
    user_accounts: Arc<FacadeUserAccounts>,
}

impl FacadeAppleTV {
    /// Build an empty facade for `service`, with pyatv's per-capability priority ordering.
    #[must_use]
    pub fn new(service: BaseService) -> Self {
        fn default<T: ?Sized>() -> Arc<Relayer<T>> {
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()))
        }

        let remote_control = default::<dyn RemoteControl>();
        let metadata = default::<dyn Metadata>();
        let push_updater = default::<dyn PushUpdater>();
        let stream = default::<dyn Stream>();
        let power: Arc<Relayer<dyn Power>> = Arc::new(Relayer::new(POWER_PRIORITIES.to_vec()));
        let apps = default::<dyn Apps>();
        let audio = default::<dyn Audio>();
        let keyboard = default::<dyn Keyboard>();
        let touch_gestures = default::<dyn TouchGestures>();
        let user_accounts = default::<dyn UserAccounts>();
        let features = Arc::new(FacadeFeatures::default());

        let mut takeover = TakeoverRegistry::default();
        takeover.insert(Interface::RemoteControl, &remote_control);
        takeover.insert(Interface::Metadata, &metadata);
        takeover.insert(Interface::PushUpdater, &push_updater);
        takeover.insert(Interface::Stream, &stream);
        takeover.insert(Interface::Power, &power);
        takeover.insert(Interface::Apps, &apps);
        takeover.insert(Interface::Audio, &audio);
        takeover.insert(Interface::Keyboard, &keyboard);
        takeover.insert(Interface::TouchGestures, &touch_gestures);
        takeover.insert(Interface::UserAccounts, &user_accounts);

        let facades = Facades {
            remote_control: Arc::new(FacadeRemoteControl::new(Arc::clone(&remote_control))),
            metadata: Arc::new(FacadeMetadata::new(Arc::clone(&metadata))),
            audio: Arc::new(FacadeAudio::new(Arc::clone(&audio))),
            stream: Arc::new(FacadeStream::new(
                Arc::clone(&stream),
                Arc::clone(&features) as Arc<dyn Features>,
            )),
            push_updater: FacadePushUpdater::new(Arc::clone(&push_updater)),
            power: Arc::new(FacadePower::new(Arc::clone(&power))),
            apps: Arc::new(FacadeApps::new(Arc::clone(&apps))),
            keyboard: Arc::new(FacadeKeyboard::new(Arc::clone(&keyboard))),
            touch_gestures: Arc::new(FacadeTouchGestures::new(Arc::clone(&touch_gestures))),
            user_accounts: Arc::new(FacadeUserAccounts::new(Arc::clone(&user_accounts))),
        };

        Self {
            remote_control,
            metadata,
            push_updater,
            stream,
            power,
            apps,
            audio,
            keyboard,
            touch_gestures,
            user_accounts,
            features,
            facades,
            takeover: Arc::new(takeover),
            handles: Vec::new(),
            listeners: Arc::new(ListenerHub::default()),
            device_info: DeviceInfo::default(),
            service,
        }
    }

    /// File one connected protocol's capability handles into the relayers.
    ///
    /// Called once per protocol by `pyatv::connect` after that protocol's own `connect()` reported
    /// success, mirroring the body of `FacadeAppleTV.connect`'s setup loop
    /// (`pyatv/core/facade.py:753-774`). Protocols with nothing to contribute are skipped.
    pub fn add_protocol(&mut self, data: SetupData) {
        let Some(protocol) = data.protocol else {
            return;
        };

        // A registration can only be refused when `protocol` is missing from the relayer's
        // priority list, which neither `DEFAULT_PRIORITIES` nor `POWER_PRIORITIES` allows — both
        // name every `Protocol`. It is logged rather than propagated because it would mean this
        // module contradicted itself, not that anything about the device went wrong.
        macro_rules! register {
            ($field:ident) => {
                if let Some(instance) = data.$field {
                    if let Err(error) = self.$field.register(protocol, instance, data.features.clone())
                    {
                        tracing::error!(
                            ?protocol,
                            interface = stringify!($field),
                            %error,
                            "a capability could not be registered"
                        );
                    }
                }
            };
        }

        let has_push_updater = data.push_updater.is_some();

        register!(remote_control);
        register!(metadata);
        register!(push_updater);
        register!(stream);
        register!(power);
        register!(apps);
        register!(audio);
        register!(keyboard);
        register!(touch_gestures);
        register!(user_accounts);

        if let Some(features) = data.features_impl {
            // `add_mapping` (`facade.py:274-284`): a feature is owned by the highest-priority
            // protocol that declared it, and later registrations only win if they outrank the
            // incumbent.
            self.features
                .add_mapping(protocol, &data.features, &features);
        }
        if has_push_updater {
            self.features.set_push_updates(true);
        }

        // `FacadeKeyboard`'s dispatcher filter is on the keyboard relayer's main protocol
        // (`facade.py:554-558`), which only the facade can know.
        self.listeners
            .set_keyboard_protocol(self.keyboard.main_protocol());

        if let Some(handle) = data.handle {
            self.handles.push((protocol, handle));
        }

        // `dict_merge(devinfo, setup_data.device_info())` (`facade.py:772`): a key already set by
        // a higher-priority protocol is never overwritten, since protocols are added in priority
        // order by `pyatv::connect`.
        self.device_info.merge_from(&data.device_info);
    }

    /// The registry to hand a protocol's `setup()` so its connection reports here.
    ///
    /// Taken before any protocol is set up — see [`ListenerHub`] for why it has to be a separate
    /// object — and handed to each of them, so a protocol that drops its socket reaches every
    /// listener the caller registers later.
    #[must_use]
    pub fn listener_hub(&self) -> Arc<ListenerHub> {
        Arc::clone(&self.listeners)
    }

    /// A takeover handle bound to `protocol`, for that protocol's `setup()`.
    ///
    /// `partial(atv.takeover, proto)` (`pyatv/__init__.py:138`). Taken before setup for the same
    /// reason [`FacadeAppleTV::listener_hub`] is.
    #[must_use]
    pub fn takeover_handle(&self, protocol: Protocol) -> FacadeTakeover {
        FacadeTakeover::new(Arc::clone(&self.takeover), protocol)
    }

    /// Claim one or more interfaces for `protocol` until the returned guard is dropped.
    ///
    /// `FacadeAppleTV.takeover` (`pyatv/core/facade.py:804-830`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidState`] if any named interface is already claimed; nothing
    /// remains claimed in that case.
    pub fn takeover(
        &self,
        protocol: Protocol,
        interfaces: &[Interface],
    ) -> Result<takeover::TakeoverGuard> {
        self.takeover.claim(protocol, interfaces)
    }

    /// Every protocol that contributed at least one capability.
    #[must_use]
    pub fn connected_protocols(&self) -> BTreeSet<Protocol> {
        let mut protocols = BTreeSet::new();
        protocols.extend(self.remote_control.protocols());
        protocols.extend(self.metadata.protocols());
        protocols.extend(self.push_updater.protocols());
        protocols.extend(self.stream.protocols());
        protocols.extend(self.power.protocols());
        protocols.extend(self.apps.protocols());
        protocols.extend(self.audio.protocols());
        protocols.extend(self.keyboard.protocols());
        protocols.extend(self.touch_gestures.protocols());
        protocols.extend(self.user_accounts.protocols());
        protocols.extend(self.handles.iter().map(|(protocol, _)| *protocol));
        protocols
    }

    /// Whether any protocol registered anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty() && self.connected_protocols().is_empty()
    }

    /// Replace the merged device facts, for callers that know more than the protocols did.
    pub fn set_device_info(&mut self, device_info: DeviceInfo) {
        self.device_info = device_info;
    }
}

impl DeviceListener for FacadeAppleTV {
    /// Fan a protocol's connection loss out to every registered listener.
    fn connection_lost(&self, reason: &str) {
        self.listeners.connection_lost(reason);
    }

    fn connection_closed(&self) {
        self.listeners.connection_closed();
    }
}

impl AppleTV for FacadeAppleTV {
    fn remote_control(&self) -> Option<Arc<dyn RemoteControl>> {
        (!self.remote_control.is_empty())
            .then(|| Arc::clone(&self.facades.remote_control) as Arc<dyn RemoteControl>)
    }

    fn metadata(&self) -> Option<Arc<dyn Metadata>> {
        (!self.metadata.is_empty()).then(|| Arc::clone(&self.facades.metadata) as Arc<dyn Metadata>)
    }

    fn push_updater(&self) -> Option<Arc<dyn PushUpdater>> {
        (!self.push_updater.is_empty())
            .then(|| Arc::clone(&self.facades.push_updater) as Arc<dyn PushUpdater>)
    }

    fn stream(&self) -> Option<Arc<dyn Stream>> {
        (!self.stream.is_empty()).then(|| Arc::clone(&self.facades.stream) as Arc<dyn Stream>)
    }

    fn power(&self) -> Option<Arc<dyn Power>> {
        (!self.power.is_empty()).then(|| Arc::clone(&self.facades.power) as Arc<dyn Power>)
    }

    fn apps(&self) -> Option<Arc<dyn Apps>> {
        (!self.apps.is_empty()).then(|| Arc::clone(&self.facades.apps) as Arc<dyn Apps>)
    }

    fn audio(&self) -> Option<Arc<dyn Audio>> {
        (!self.audio.is_empty()).then(|| Arc::clone(&self.facades.audio) as Arc<dyn Audio>)
    }

    fn keyboard(&self) -> Option<Arc<dyn Keyboard>> {
        (!self.keyboard.is_empty()).then(|| Arc::clone(&self.facades.keyboard) as Arc<dyn Keyboard>)
    }

    fn touch_gestures(&self) -> Option<Arc<dyn TouchGestures>> {
        (!self.touch_gestures.is_empty())
            .then(|| Arc::clone(&self.facades.touch_gestures) as Arc<dyn TouchGestures>)
    }

    fn user_accounts(&self) -> Option<Arc<dyn UserAccounts>> {
        (!self.user_accounts.is_empty())
            .then(|| Arc::clone(&self.facades.user_accounts) as Arc<dyn UserAccounts>)
    }

    fn features(&self) -> Arc<dyn Features> {
        Arc::clone(&self.features) as Arc<dyn Features>
    }

    fn device_info(&self) -> &DeviceInfo {
        &self.device_info
    }

    fn service(&self) -> &BaseService {
        &self.service
    }

    fn add_listener(&self, listener: &Arc<dyn DeviceListener>) {
        self.listeners.add_listener(listener);
    }

    fn add_power_listener(&self, listener: &Arc<dyn PowerListener>) {
        self.listeners.add_power_listener(listener);
    }

    fn add_audio_listener(&self, listener: &Arc<dyn AudioListener>) {
        self.listeners.add_audio_listener(listener);
    }

    fn add_keyboard_listener(&self, listener: &Arc<dyn KeyboardListener>) {
        self.listeners.add_keyboard_listener(listener);
    }

    /// Close every protocol in turn.
    ///
    /// Upstream collects a task per protocol and lets the caller await them all
    /// (`facade.py:785-802`). Here they are awaited sequentially and a failure is logged rather
    /// than returned, because one protocol refusing to shut down cleanly must not leave the others
    /// connected. The first error is still reported so a caller can notice.
    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            // `self.push_updater.stop()` (`facade.py:791-792`), which upstream reaches through the
            // facade so *every* protocol's updater stops, not only the main one.
            self.facades.push_updater.stop();

            let mut first_error = None;
            for (protocol, handle) in &self.handles {
                if let Err(error) = handle.close().await {
                    tracing::debug!(?protocol, %error, "a protocol did not close cleanly");
                    first_error.get_or_insert(error);
                }
            }

            self.connection_closed();
            first_error.map_or(Ok(()), Err)
        })
    }
}
