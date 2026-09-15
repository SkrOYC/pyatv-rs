//! Control button clusters for navigation, playback transport and volume.

use gpui::{Context, IntoElement, ParentElement, Styled, div, px};

use crate::components::button::round_button;
use crate::remote::RemoteCommand;
use crate::theme;
use crate::view::RemoteView;

/// Render navigation cluster buttons: Menu (Back), TV (Home), Screensaver.
pub fn render_nav_cluster(cx: &mut Context<RemoteView>) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_around()
        .w_full()
        .px_2()
        .child(round_button(
            "btn-menu",
            "MENU",
            Some("Back"),
            cx.listener(|this, _, _, _| {
                this.send_command(RemoteCommand::Menu);
            }),
        ))
        .child(round_button(
            "btn-home",
            "⌂",
            Some("TV"),
            cx.listener(|this, _, _, _| {
                this.send_command(RemoteCommand::Home);
            }),
        ))
        .child(round_button(
            "btn-screen",
            "⏾",
            Some("Screen"),
            cx.listener(|this, _, _, _| {
                this.send_command(RemoteCommand::Screensaver);
            }),
        ))
}

/// Render transport cluster buttons: Skip Backward, Play/Pause, Skip Forward.
pub fn render_transport_cluster(cx: &mut Context<RemoteView>) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_around()
        .w_full()
        .px_2()
        .child(round_button(
            "btn-skip-back",
            "⏮",
            Some("15s"),
            cx.listener(|this, _, _, _| {
                this.send_command(RemoteCommand::SkipBackward);
            }),
        ))
        .child(round_button(
            "btn-play-pause",
            "▶⏸",
            Some("Play"),
            cx.listener(|this, _, _, _| {
                this.send_command(RemoteCommand::PlayPause);
            }),
        ))
        .child(round_button(
            "btn-skip-fwd",
            "⏭",
            Some("15s"),
            cx.listener(|this, _, _, _| {
                this.send_command(RemoteCommand::SkipForward);
            }),
        ))
}

/// Render volume cluster buttons: Volume Down, Volume Up.
pub fn render_volume_cluster(cx: &mut Context<RemoteView>) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_center()
        .gap_6()
        .w_full()
        .child(round_button(
            "btn-vol-down",
            "－",
            Some("Vol"),
            cx.listener(|this, _, _, _| {
                this.send_command(RemoteCommand::VolumeDown);
            }),
        ))
        .child(round_button(
            "btn-vol-up",
            "＋",
            Some("Vol"),
            cx.listener(|this, _, _, _| {
                this.send_command(RemoteCommand::VolumeUp);
            }),
        ))
}

/// Render bottom status / toast message bar.
pub fn render_footer(toast_message: Option<&str>) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .justify_center()
        .h(px(24.0))
        .w_full()
        .child(
            div()
                .text_xs()
                .text_color(theme::TEXT_MUTED)
                .child(toast_message.unwrap_or("Ready").to_string()),
        )
}
