//! The public capability traits every protocol implements a subset of.
//!
//! These correspond one-for-one to the abstract base classes in `pyatv/interface.py`
//! (`docs/research/pyatv-architecture.md` §4). A protocol crate implements only the traits it can
//! actually serve; [`crate::facade::FacadeAppleTV`] unions them behind [`AppleTV`] using a
//! [`crate::relayer::Relayer`] per trait.
//!
//! ## Why boxed futures rather than `async fn` in traits
//!
//! Native `async fn` in traits is stable, but a trait containing one is not dyn-compatible, and the
//! whole facade design depends on storing `Arc<dyn RemoteControl>` and friends in a relayer. Every
//! async method therefore returns [`BoxFuture`], which costs one allocation per call — negligible
//! against a network round trip — and keeps the traits object-safe with no proc-macro dependency.

pub mod control;
pub mod device;
pub mod playback;

use std::pin::Pin;
use std::sync::Arc;

pub use control::{Keyboard, RemoteControl, TouchGestures};
pub use device::{Apps, Audio, Features, Power, UserAccounts};
pub use playback::{Metadata, PlaybackListener, PushUpdater, Stream};

use crate::consts::PowerState;
use crate::models::{BaseService, DeviceInfo};
use crate::{Error, Result};

/// A heap-allocated, `Send` future returned from the object-safe capability traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The root object a caller receives from `pyatv::connect`.
///
/// Each accessor returns `None` when no connected protocol implements that capability at all. This
/// is a deliberate deviation from pyatv, which always hands back a facade object and raises
/// `NotSupportedError` on first use: Rust can express "this capability is absent" in the type
/// system, so absence is reported at lookup time and [`Error::NotSupported`] is reserved for the
/// finer-grained case where a capability exists but one of its methods is unavailable on the
/// connected protocol.
pub trait AppleTV: Send + Sync + std::fmt::Debug {
    /// Navigation and transport control.
    fn remote_control(&self) -> Option<Arc<dyn RemoteControl>>;
    /// Now-playing metadata and artwork.
    fn metadata(&self) -> Option<Arc<dyn Metadata>>;
    /// Push-based now-playing updates.
    fn push_updater(&self) -> Option<Arc<dyn PushUpdater>>;
    /// Video and audio streaming.
    fn stream(&self) -> Option<Arc<dyn Stream>>;
    /// Power control.
    fn power(&self) -> Option<Arc<dyn Power>>;
    /// Installed application management.
    fn apps(&self) -> Option<Arc<dyn Apps>>;
    /// Volume and output device control.
    fn audio(&self) -> Option<Arc<dyn Audio>>;
    /// On-screen keyboard text entry.
    fn keyboard(&self) -> Option<Arc<dyn Keyboard>>;
    /// Trackpad-style gestures.
    fn touch_gestures(&self) -> Option<Arc<dyn TouchGestures>>;
    /// User account switching.
    fn user_accounts(&self) -> Option<Arc<dyn UserAccounts>>;
    /// Per-feature availability reporting.
    fn features(&self) -> Arc<dyn Features>;

    /// Hardware and firmware facts about the connected device.
    fn device_info(&self) -> &DeviceInfo;
    /// The service that drives the primary connection.
    fn service(&self) -> &BaseService;

    /// Register a listener notified when a connection drops or is closed.
    ///
    /// Upstream reaches this through `StateProducer`, which `interface.AppleTV` inherits, so a
    /// caller writes `atv.listener = mine`. There it is a single slot; here it is a list, because a
    /// weakly held list costs nothing and "the last registration silently replaced yours" is not a
    /// behaviour worth porting.
    ///
    /// The listener is held weakly: dropping your `Arc` unregisters it.
    fn add_listener(&self, listener: &Arc<dyn DeviceListener>);

    /// Register a listener notified when the device's power state changes.
    ///
    /// Upstream hangs this off the power interface instead (`atv.power.listener = mine`,
    /// `pyatv/core/facade.py:305-333`). It is on the root object here because the facade is what
    /// owns the listener list, and because a caller that wants power updates should not have to
    /// discover that `power()` may be `None`.
    ///
    /// Held weakly, as [`AppleTV::add_listener`].
    fn add_power_listener(&self, listener: &Arc<dyn PowerListener>);

    /// Tear down every protocol connection.
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

/// Drives one protocol's pairing exchange from start to finish.
///
/// The caller loop is: [`PairingHandler::begin`], then — if
/// [`PairingHandler::device_provides_pin`] — read the PIN off the device's screen and pass it to
/// [`PairingHandler::pin`], then [`PairingHandler::finish`]. On success the resulting credentials
/// are written into the [`crate::storage::Storage`] the handler was constructed with, so callers
/// never thread credential strings by hand.
pub trait PairingHandler: Send + Sync + std::fmt::Debug {
    /// Whether the device displays a PIN the user must type in, as opposed to the client
    /// generating one for the user to enter on the device.
    fn device_provides_pin(&self) -> bool;

    /// Whether a successful exchange has produced credentials.
    fn has_paired(&self) -> bool;

    /// The service being paired.
    ///
    /// Ports `PairingHandler.service` (`pyatv/interface.py:257-260`), which upstream's `atvremote`
    /// reads straight after `finish()` to print the new credentials
    /// (`pyatv/scripts/atvremote.py:238`). Returned by value rather than by reference because
    /// [`PairingHandler::finish`] writes the credentials into it behind a lock, and a lock guard
    /// cannot outlive the call.
    fn service(&self) -> BaseService;

    /// Supply the PIN shown on the device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pairing`] if called at the wrong point in the exchange.
    fn pin(&self, pin: u32) -> Result<()>;

    /// Start the exchange.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if the device is unreachable, or [`Error::Pairing`] if
    /// the device refuses to begin pairing.
    fn begin(&self) -> BoxFuture<'_, Result<()>>;

    /// Complete the exchange and persist the resulting credentials.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Authentication`] if the device rejects the proof, or [`Error::Pairing`] for
    /// any other protocol-level failure.
    fn finish(&self) -> BoxFuture<'_, Result<()>>;

    /// Release the pairing connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the underlying socket could not be shut down cleanly.
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

/// One protocol connection's teardown hook, filed into the facade at setup time.
///
/// Ports the `close` callable in upstream's `SetupData` (`pyatv/core/__init__.py`), which
/// `FacadeAppleTV.close()` collects from every connected protocol and awaits
/// (`pyatv/core/facade.py:785-802`). A separate trait rather than a boxed closure so the handle
/// stays `Debug`, which `missing_debug_implementations` requires of everything public here.
pub trait ProtocolHandle: Send + Sync + std::fmt::Debug {
    /// Tear this protocol's connection down. Must be safe to call more than once.
    ///
    /// # Errors
    ///
    /// Returns whatever the protocol's own teardown reports; the facade logs and continues rather
    /// than letting one protocol's failure abort the rest.
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

/// Notified when a connection the caller did not close goes away.
///
/// Ports `pyatv.interface.DeviceListener` (`pyatv/interface.py:302-318`). Upstream holds listeners
/// weakly through `StateProducer`; here the caller owns the `Arc` and the facade holds a
/// [`std::sync::Weak`], so forgetting to unregister cannot keep a listener alive forever.
pub trait DeviceListener: Send + Sync + std::fmt::Debug {
    /// The connection dropped without the caller asking for it.
    fn connection_lost(&self, reason: &str);
    /// The connection was closed on request.
    fn connection_closed(&self);
}

/// Notified when a connected device reports a new power state.
///
/// Ports `pyatv.interface.PowerListener` (`pyatv/interface.py:918-926`), whose one method is
/// `powerstate_update(old_state, new_state)`. Both states are passed because upstream does and
/// because "it changed" is rarely enough on its own — a listener usually wants to know whether the
/// device just woke or just slept.
///
/// Registered through [`AppleTV::add_power_listener`] and held weakly.
pub trait PowerListener: Send + Sync + std::fmt::Debug {
    /// The device moved from `old_state` to `new_state`.
    fn power_state_changed(&self, old_state: PowerState, new_state: PowerState);
}

/// Helper for protocol crates: the error every unimplemented capability should return.
#[must_use]
pub fn not_supported(what: &str) -> Error {
    Error::NotSupported(what.to_owned())
}
