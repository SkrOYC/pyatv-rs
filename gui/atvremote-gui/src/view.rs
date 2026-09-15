use gpui::{
    Context, FocusHandle, InteractiveElement, IntoElement, KeyDownEvent, ParentElement, Render,
    Styled, Window, div,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::backend::{BackendEvent, UiAction};
use crate::components::controls::{
    render_footer, render_nav_cluster, render_transport_cluster, render_volume_cluster,
};
use crate::components::device_picker::render_device_header;
use crate::components::dpad::render_dpad;
use crate::components::now_playing::render_now_playing;
use crate::components::pairing_dialog::render_pairing_dialog;
use crate::remote::RemoteCommand;
use crate::state::{AppState, ConnectionState};
use crate::theme;

/// The primary GPUI view presenting the minimalist Apple TV remote interface.
pub struct RemoteView {
    state: AppState,
    backend_tx: UnboundedSender<UiAction>,
    focus_handle: FocusHandle,
}

impl RemoteView {
    /// Create a new `RemoteView` with backend action channel.
    #[must_use]
    pub fn new(backend_tx: UnboundedSender<UiAction>, cx: &mut Context<Self>) -> Self {
        Self {
            state: AppState::new(),
            backend_tx,
            focus_handle: cx.focus_handle(),
        }
    }

    /// Access the view's primary focus handle.
    #[must_use]
    pub fn focus_handle(&self) -> &FocusHandle {
        &self.focus_handle
    }

    /// Process a background event from the Tokio worker and trigger re-render.
    pub fn handle_backend_event(&mut self, event: BackendEvent, cx: &mut Context<Self>) {
        match event {
            BackendEvent::ScanStarted => {
                self.state.connection = ConnectionState::Scanning;
                self.state.toast_message = Some("Scanning for Apple TVs...".into());
            }
            BackendEvent::DevicesDiscovered(devices) => {
                self.state.devices = devices;
                if self.state.connection == ConnectionState::Scanning {
                    self.state.connection = ConnectionState::Disconnected;
                }
                self.state.toast_message =
                    Some(format!("Found {} device(s)", self.state.devices.len()));
            }
            BackendEvent::Connecting(name) => {
                self.state.connection = ConnectionState::Connecting(name.clone());
                self.state.show_device_picker = false;
                self.state.toast_message = Some(format!("Connecting to {name}..."));
            }
            BackendEvent::Connected {
                name,
                id,
                can_navigate,
            } => {
                self.state.connection = ConnectionState::Connected {
                    name: name.clone(),
                    id,
                };
                self.state.can_navigate = can_navigate;
                self.state.show_device_picker = false;
                if can_navigate {
                    self.state.toast_message = Some(format!("Connected to {name}"));
                } else {
                    self.state.toast_message = Some(format!(
                        "Connected to {name} (Pairing needed for D-pad & Home buttons)"
                    ));
                }
            }
            BackendEvent::Disconnected => {
                self.state.connection = ConnectionState::Disconnected;
                self.state.now_playing = None;
                self.state.can_navigate = false;
                self.state.toast_message = Some("Disconnected".into());
            }
            BackendEvent::NowPlayingUpdated(now_playing) => {
                self.state.now_playing = now_playing;
            }
            BackendEvent::PowerStateUpdated(power_on) => {
                self.state.power_on = power_on;
            }
            BackendEvent::Toast(msg) => {
                self.state.toast_message = Some(msg);
            }
            BackendEvent::CommandFailed(err) => {
                self.state.toast_message = Some(format!("Error: {err}"));
            }
            BackendEvent::PairingStarted { name, identifier } => {
                self.state.pairing_device = Some((name, identifier));
                self.state.pairing_pin.clear();
                self.state.pairing_error = None;
                self.state.show_device_picker = false;
            }
            BackendEvent::PairingSucceeded => {
                self.state.pairing_device = None;
                self.state.pairing_pin.clear();
                self.state.pairing_error = None;
                self.state.toast_message = Some("Pairing succeeded!".into());
            }
            BackendEvent::PairingFailed(err) => {
                self.state.pairing_error = Some(err);
                self.state.pairing_pin.clear();
            }
            BackendEvent::Error(err) => {
                if !matches!(self.state.connection, ConnectionState::Connected { .. }) {
                    self.state.connection = ConnectionState::Error(err.clone());
                }
                self.state.toast_message = Some(format!("Error: {err}"));
            }
        }
        cx.notify();
    }

    /// Append a single digit to the entered PIN during pairing.
    pub fn append_pairing_digit(&mut self, ch: char, cx: &mut Context<Self>) {
        if self.state.pairing_pin.len() < 4 {
            self.state.pairing_pin.push(ch);
            if self.state.pairing_pin.len() == 4
                && let Ok(pin) = self.state.pairing_pin.parse::<u32>()
            {
                let _ = self.backend_tx.send(UiAction::SubmitPin(pin));
            }
            cx.notify();
        }
    }

    /// Delete the last digit from the pairing PIN.
    pub fn backspace_pairing_digit(&mut self, cx: &mut Context<Self>) {
        self.state.pairing_pin.pop();
        cx.notify();
    }

    /// Cancel active pairing attempt and return to main remote.
    pub fn cancel_pairing(&mut self, cx: &mut Context<Self>) {
        self.state.pairing_device = None;
        self.state.pairing_pin.clear();
        self.state.pairing_error = None;
        let _ = self.backend_tx.send(UiAction::CancelPairing);
        cx.notify();
    }

    /// Handle keyboard input when the remote view has focus.
    pub fn handle_key_down(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        // Ignore key combinations with Ctrl, Alt or Super/Cmd modifiers
        if event.keystroke.modifiers.control
            || event.keystroke.modifiers.alt
            || event.keystroke.modifiers.platform
        {
            return;
        }

        let key = event.keystroke.key.as_str();
        tracing::debug!(%key, "remote key press received");

        // 1. If currently in pairing mode, handle numeric entry, backspace and escape
        if self.state.is_pairing() {
            match key {
                "escape" => {
                    self.cancel_pairing(cx);
                    return;
                }
                "backspace" => {
                    self.backspace_pairing_digit(cx);
                    return;
                }
                digit
                    if digit.len() == 1
                        && digit.chars().next().is_some_and(|c| c.is_ascii_digit()) =>
                {
                    if let Some(ch) = digit.chars().next() {
                        self.append_pairing_digit(ch, cx);
                    }
                    return;
                }
                _ => return,
            }
        }

        // 2. If device dropdown is open, Escape closes it
        if key == "escape" && self.state.show_device_picker {
            self.state.show_device_picker = false;
            cx.notify();
            return;
        }

        // 3. Remote navigation and control commands
        if let Some(command) = map_key_to_command(key) {
            self.send_command(command);
        }
    }

    pub(crate) fn send_command(&self, cmd: RemoteCommand) {
        let _ = self.backend_tx.send(UiAction::SendCommand(cmd));
    }
}

impl Render for RemoteView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let state = self.state.clone();

        let backend_tx = self.backend_tx.clone();
        let pair_tx = self.backend_tx.clone();

        let header = render_device_header(
            &state,
            cx.listener(|this, _, _, cx| {
                this.state.show_device_picker = !this.state.show_device_picker;
                cx.notify();
            }),
            cx.listener(|this, _, _, cx| {
                this.state.show_device_picker = true;
                let _ = this.backend_tx.send(UiAction::Scan);
                cx.notify();
            }),
            move |id| {
                let _ = backend_tx.send(UiAction::Connect(id));
            },
            move |id| {
                let _ = pair_tx.send(UiAction::StartPairing(id));
            },
            cx.listener(|this, _, _, _| {
                this.send_command(RemoteCommand::TogglePower);
            }),
        );

        let body = if state.is_pairing() {
            div()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .w_full()
                .child(render_pairing_dialog(&state, cx))
                .into_any_element()
        } else {
            let now_playing = render_now_playing(state.now_playing.as_ref());
            let dpad = render_dpad({
                let backend_tx = self.backend_tx.clone();
                move |cmd| {
                    let _ = backend_tx.send(UiAction::SendCommand(cmd));
                }
            });

            div()
                .flex()
                .flex_col()
                .items_center()
                .justify_between()
                .size_full()
                .gap_3()
                .child(now_playing)
                .child(dpad)
                .child(render_nav_cluster(cx))
                .child(render_transport_cluster(cx))
                .child(render_volume_cluster(cx))
                .into_any_element()
        };

        div()
            .id("remote-root")
            .key_context("RemoteView")
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(|this, event: &KeyDownEvent, _window, cx| {
                this.handle_key_down(event, cx);
            }))
            .flex()
            .flex_col()
            .items_center()
            .justify_between()
            .size_full()
            .bg(theme::BACKGROUND)
            .p_4()
            .gap_3()
            .child(header)
            .child(body)
            .child(render_footer(state.toast_message.as_deref()))
    }
}

/// Map a keyboard key name to its corresponding Apple TV remote command.
#[must_use]
pub fn map_key_to_command(key: &str) -> Option<RemoteCommand> {
    match key {
        "escape" | "backspace" => Some(RemoteCommand::Menu),
        "enter" | "return" => Some(RemoteCommand::Select),
        "up" => Some(RemoteCommand::Up),
        "down" => Some(RemoteCommand::Down),
        "left" => Some(RemoteCommand::Left),
        "right" => Some(RemoteCommand::Right),
        "space" => Some(RemoteCommand::PlayPause),
        "home" => Some(RemoteCommand::Home),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyboard_navigation_mappings() {
        // Esc and Backspace map to Menu (Back)
        assert_eq!(map_key_to_command("escape"), Some(RemoteCommand::Menu));
        assert_eq!(map_key_to_command("backspace"), Some(RemoteCommand::Menu));

        // Enter and Return map to Select (OK)
        assert_eq!(map_key_to_command("enter"), Some(RemoteCommand::Select));
        assert_eq!(map_key_to_command("return"), Some(RemoteCommand::Select));

        // Arrow keys map to directional navigation
        assert_eq!(map_key_to_command("up"), Some(RemoteCommand::Up));
        assert_eq!(map_key_to_command("down"), Some(RemoteCommand::Down));
        assert_eq!(map_key_to_command("left"), Some(RemoteCommand::Left));
        assert_eq!(map_key_to_command("right"), Some(RemoteCommand::Right));

        // Media and home shortcuts
        assert_eq!(map_key_to_command("space"), Some(RemoteCommand::PlayPause));
        assert_eq!(map_key_to_command("home"), Some(RemoteCommand::Home));

        // Unbound keys return None
        assert_eq!(map_key_to_command("tab"), None);
        assert_eq!(map_key_to_command("a"), None);
    }
}
