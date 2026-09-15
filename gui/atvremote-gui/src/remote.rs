//! Remote control button definitions and execution mapping.

use pyatv::AppleTV;
use pyatv::InputAction;
use std::sync::Arc;

/// Represents all remote commands supported by the Apple TV GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RemoteCommand {
    /// Navigate up on the D-Pad.
    Up,
    /// Navigate down on the D-Pad.
    Down,
    /// Navigate left on the D-Pad.
    Left,
    /// Navigate right on the D-Pad.
    Right,
    /// Select / Click the focused item.
    Select,
    /// Go back one level / Menu button.
    Menu,
    /// Return to the home screen / TV button.
    Home,
    /// Top menu button.
    TopMenu,
    /// Activate the aerial screensaver.
    Screensaver,
    /// Toggle media play / pause.
    PlayPause,
    /// Start media playback.
    Play,
    /// Pause media playback.
    Pause,
    /// Skip to the next track or episode.
    Next,
    /// Skip to previous track or beginning.
    Previous,
    /// Skip forward 15 seconds.
    SkipForward,
    /// Skip backward 15 seconds.
    SkipBackward,
    /// Increment audio volume.
    VolumeUp,
    /// Decrement audio volume.
    VolumeDown,
    /// Wake up / turn on device.
    TurnOn,
    /// Put device to sleep.
    TurnOff,
    /// Toggle device power.
    TogglePower,
}

impl RemoteCommand {
    /// Human-readable label for debugging and toast notifications.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Up => "Up",
            Self::Down => "Down",
            Self::Left => "Left",
            Self::Right => "Right",
            Self::Select => "Select",
            Self::Menu => "Back / Menu",
            Self::Home => "Home / TV",
            Self::TopMenu => "Top Menu",
            Self::Screensaver => "Screensaver",
            Self::PlayPause => "Play / Pause",
            Self::Play => "Play",
            Self::Pause => "Pause",
            Self::Next => "Next Track",
            Self::Previous => "Previous Track",
            Self::SkipForward => "Skip Forward",
            Self::SkipBackward => "Skip Backward",
            Self::VolumeUp => "Volume Up",
            Self::VolumeDown => "Volume Down",
            Self::TurnOn => "Power On",
            Self::TurnOff => "Power Off",
            Self::TogglePower => "Toggle Power",
        }
    }

    /// Dispatch this command to the connected Apple TV facade.
    ///
    /// # Errors
    ///
    /// Returns [`pyatv::Error`] if the connected protocols fail to handle the command or capability is missing.
    pub async fn execute(self, atv: &Arc<dyn AppleTV>) -> pyatv::Result<()> {
        match self {
            Self::Up
            | Self::Down
            | Self::Left
            | Self::Right
            | Self::Select
            | Self::Menu
            | Self::Home
            | Self::TopMenu
            | Self::Screensaver
            | Self::PlayPause
            | Self::Play
            | Self::Pause
            | Self::Next
            | Self::Previous
            | Self::SkipForward
            | Self::SkipBackward => {
                let Some(rc) = atv.remote_control() else {
                    return Err(pyatv::Error::NotSupported("remote_control".into()));
                };
                let res = match self {
                    Self::Up => rc.up(InputAction::SingleTap).await,
                    Self::Down => rc.down(InputAction::SingleTap).await,
                    Self::Left => rc.left(InputAction::SingleTap).await,
                    Self::Right => rc.right(InputAction::SingleTap).await,
                    Self::Select => rc.select(InputAction::SingleTap).await,
                    Self::Menu => rc.menu(InputAction::SingleTap).await,
                    Self::Home => rc.home(InputAction::SingleTap).await,
                    Self::TopMenu => rc.top_menu().await,
                    Self::Screensaver => rc.screensaver().await,
                    Self::PlayPause => rc.play_pause().await,
                    Self::Play => rc.play().await,
                    Self::Pause => rc.pause().await,
                    Self::Next => rc.next().await,
                    Self::Previous => rc.previous().await,
                    Self::SkipForward => rc.skip_forward(15.0).await,
                    Self::SkipBackward => rc.skip_backward(15.0).await,
                    _ => unreachable!(),
                };
                if let Err(pyatv::Error::NotSupported(_)) = &res {
                    let is_nav = matches!(
                        self,
                        Self::Up
                            | Self::Down
                            | Self::Left
                            | Self::Right
                            | Self::Select
                            | Self::Menu
                            | Self::Home
                            | Self::TopMenu
                            | Self::Screensaver
                    );
                    if is_nav {
                        return Err(pyatv::Error::NotSupported(
                            "pairing required for remote buttons (run: atvremote --protocol companion pair)".into(),
                        ));
                    }
                }
                res
            }
            Self::VolumeUp => {
                let Some(audio) = atv.audio() else {
                    return Err(pyatv::Error::NotSupported("audio".into()));
                };
                audio.volume_up().await
            }
            Self::VolumeDown => {
                let Some(audio) = atv.audio() else {
                    return Err(pyatv::Error::NotSupported("audio".into()));
                };
                audio.volume_down().await
            }
            Self::TurnOn => {
                let Some(power) = atv.power() else {
                    return Err(pyatv::Error::NotSupported("power".into()));
                };
                power.turn_on(false).await
            }
            Self::TurnOff => {
                let Some(power) = atv.power() else {
                    return Err(pyatv::Error::NotSupported("power".into()));
                };
                power.turn_off(false).await
            }
            Self::TogglePower => {
                let Some(power) = atv.power() else {
                    return Err(pyatv::Error::NotSupported("power".into()));
                };
                if power.power_state() == pyatv::PowerState::On {
                    power.turn_off(false).await
                } else {
                    power.turn_on(false).await
                }
            }
        }
    }
}
