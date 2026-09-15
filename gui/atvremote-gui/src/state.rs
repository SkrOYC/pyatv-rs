//! Reactive application state for the Apple TV remote GUI.

/// Playback state of the active media on the Apple TV.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlaybackState {
    /// No media is currently active.
    #[default]
    Idle,
    /// Media is currently playing.
    Playing,
    /// Media playback is paused.
    Paused,
    /// Media playback is stopped.
    Stopped,
}

impl PlaybackState {
    /// Human-readable label for the playback state.
    #[must_use]
    #[allow(dead_code)]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Playing => "Playing",
            Self::Paused => "Paused",
            Self::Stopped => "Stopped",
        }
    }
}

/// Metadata for currently playing media.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NowPlaying {
    /// Track or media title.
    pub title: String,
    /// Artist or content provider.
    pub artist: Option<String>,
    /// Album or series name.
    pub album: Option<String>,
    /// Current playback status.
    pub state: PlaybackState,
}

/// Representation of an Apple TV or AirPlay device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    /// User-visible name of the device.
    pub name: String,
    /// Unique identifier for pairing / connection.
    pub identifier: String,
    /// Host or IP address, if known.
    pub address: Option<String>,
    /// Whether the device has credentials paired for remote navigation.
    pub is_paired: bool,
}

/// Connection lifecycle status of the remote.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// Not connected to any device.
    #[default]
    Disconnected,
    /// Currently scanning local network for devices.
    Scanning,
    /// In the process of connecting to a device.
    Connecting(String),
    /// Successfully connected and authenticated.
    Connected {
        /// Device name.
        name: String,
        /// Device identifier.
        id: String,
    },
    /// Connection or discovery error encountered.
    Error(String),
}

/// Primary application state model managed by GPUI.
#[derive(Debug, Clone, Default)]
pub struct AppState {
    /// Current connection status.
    pub connection: ConnectionState,
    /// List of available/discovered devices.
    pub devices: Vec<DiscoveredDevice>,
    /// Metadata for the currently playing media.
    pub now_playing: Option<NowPlaying>,
    /// Power state of the connected device.
    pub power_on: bool,
    /// Whether the device selector dropdown/modal is visible.
    pub show_device_picker: bool,
    /// Status or notification banner message.
    pub toast_message: Option<String>,
    /// Whether the connected device supports D-pad and navigation commands.
    pub can_navigate: bool,
    /// Target device (name, identifier) currently undergoing pairing.
    pub pairing_device: Option<(String, String)>,
    /// PIN digits entered by user.
    pub pairing_pin: String,
    /// Error message during pairing exchange.
    pub pairing_error: Option<String>,
}

impl AppState {
    /// Create a new empty application state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if pairing flow is actively in progress.
    #[must_use]
    pub const fn is_pairing(&self) -> bool {
        self.pairing_device.is_some()
    }

    /// Check if currently connected to a device.
    #[must_use]
    #[allow(dead_code)]
    pub const fn is_connected(&self) -> bool {
        matches!(self.connection, ConnectionState::Connected { .. })
    }

    /// Retrieve the connected device's name if connected.
    #[must_use]
    #[allow(dead_code)]
    pub fn connected_device_name(&self) -> Option<&str> {
        match &self.connection {
            ConnectionState::Connected { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playback_state_strings() {
        assert_eq!(PlaybackState::Idle.as_str(), "Idle");
        assert_eq!(PlaybackState::Playing.as_str(), "Playing");
        assert_eq!(PlaybackState::Paused.as_str(), "Paused");
        assert_eq!(PlaybackState::Stopped.as_str(), "Stopped");
    }

    #[test]
    fn test_app_state_defaults_and_helpers() {
        let mut state = AppState::new();
        assert!(!state.is_connected());
        assert_eq!(state.connected_device_name(), None);

        state.connection = ConnectionState::Connected {
            name: "Living Room Apple TV".to_string(),
            id: "ID-1234".to_string(),
        };
        assert!(state.is_connected());
        assert_eq!(state.connected_device_name(), Some("Living Room Apple TV"));
    }
}
