//! Tokio-driven background engine bridging pyatv and the GPUI frontend.

mod worker;

use tokio::sync::mpsc::UnboundedSender;

pub(crate) use worker::BackendWorker;

use crate::remote::RemoteCommand;
use crate::state::{DiscoveredDevice, NowPlaying};

/// Actions sent from the GPUI frontend to the Tokio background worker.
#[derive(Debug)]
pub enum UiAction {
    /// Initiate a discovery scan for Apple TV devices on LAN.
    Scan,
    /// Connect to a device identified by its unique identifier.
    Connect(String),
    /// Disconnect from the currently active device.
    #[allow(dead_code)]
    Disconnect,
    /// Execute a remote control button press.
    SendCommand(RemoteCommand),
    /// Refresh current now-playing metadata.
    #[allow(dead_code)]
    RefreshMetadata,
    /// Initiate pairing with an Apple TV.
    StartPairing(String),
    /// Submit 4-digit PIN for ongoing pairing.
    SubmitPin(u32),
    /// Cancel active pairing attempt.
    CancelPairing,
}

/// Events emitted by the Tokio background worker to update GPUI.
#[derive(Debug, Clone)]
pub enum BackendEvent {
    /// Network discovery started.
    ScanStarted,
    /// List of discovered or stored devices updated.
    DevicesDiscovered(Vec<DiscoveredDevice>),
    /// Attempting connection to specified device.
    Connecting(String),
    /// Successfully connected to Apple TV.
    Connected {
        /// Device name.
        name: String,
        /// Device identifier.
        id: String,
        /// Whether remote navigation commands (D-pad/Home) are available.
        can_navigate: bool,
    },
    /// Disconnected from active Apple TV.
    Disconnected,
    /// Metadata for the active track/app updated.
    NowPlayingUpdated(Option<NowPlaying>),
    /// Power state updated.
    PowerStateUpdated(bool),
    /// Brief toast notification or feedback message.
    Toast(String),
    /// Command execution failure (does not disconnect session).
    CommandFailed(String),
    /// Pairing started, device is displaying PIN on TV screen.
    PairingStarted {
        /// Device name.
        name: String,
        /// Device identifier.
        identifier: String,
    },
    /// Pairing exchange finished successfully.
    PairingSucceeded,
    /// Pairing exchange failed.
    PairingFailed(String),
    /// Connection or discovery error encountered.
    Error(String),
}

/// Start the backend loop, returning the command sender.
#[must_use]
pub fn start_backend(event_tx: UnboundedSender<BackendEvent>) -> UnboundedSender<UiAction> {
    let (action_tx, action_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("pyatv-backend".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to create Tokio runtime for pyatv backend");
            rt.block_on(async move {
                let mut worker = BackendWorker::new(event_tx);
                worker.run(action_rx).await;
            });
        })
        .expect("failed to spawn pyatv backend thread");
    action_tx
}
