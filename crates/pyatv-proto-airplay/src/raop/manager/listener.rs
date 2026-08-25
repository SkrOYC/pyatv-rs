//! The bridge from stream-client callbacks into the manager's shared state.
//!
//! `RaopStateListener` (`pyatv/protocols/raop/__init__.py:524-543`), which upstream declares as a
//! local class inside `setup()` for the same reason this is its own type: it needs both the
//! manager and the push updater, and neither exists until `setup` runs.

use std::sync::Arc;

use super::RaopPlaybackManager;
use crate::raop::stream::{PlaybackInfo, RaopListener};

/// Bridges [`RaopListener`] callbacks into the manager's shared state.
///
/// `RaopStateListener` (`__init__.py:524-543`), which is a local class inside upstream's `setup()`
/// for the same reason this is a separate type: it needs the manager and the push updater, and
/// neither exists before `setup` runs.
pub struct ManagerListener {
    manager: std::sync::Weak<RaopPlaybackManager>,
    on_change: Box<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for ManagerListener {
    /// Hand-written because a boxed closure has no `Debug`, and the workspace denies
    /// `missing_debug_implementations`.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagerListener")
            .field("manager", &self.manager.upgrade().is_some())
            .finish_non_exhaustive()
    }
}

impl ManagerListener {
    /// Report into `manager`, calling `on_change` after each transition.
    ///
    /// The manager is held weakly so the listener cannot keep it alive; upstream's own listener is
    /// held weakly from the other direction, for the same "do not create a cycle" reason.
    #[must_use]
    pub fn new(
        manager: &Arc<RaopPlaybackManager>,
        on_change: Box<dyn Fn() + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(Self {
            manager: Arc::downgrade(manager),
            on_change,
        })
    }
}

impl RaopListener for ManagerListener {
    fn playing(&self, info: &PlaybackInfo) {
        if let Some(manager) = self.manager.upgrade() {
            manager.set_playback_info(Some(info.clone()));
        }
        (self.on_change)();
    }

    fn stopped(&self) {
        if let Some(manager) = self.manager.upgrade() {
            manager.set_playback_info(None);
        }
        (self.on_change)();
    }
}
