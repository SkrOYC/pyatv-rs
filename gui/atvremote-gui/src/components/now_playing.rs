//! Now Playing metadata display component.

use gpui::{IntoElement, ParentElement, Styled, div};

use crate::state::{NowPlaying, PlaybackState};
use crate::theme;

/// Render the Now Playing metadata strip.
pub fn render_now_playing(now_playing: Option<&NowPlaying>) -> impl IntoElement {
    let content = match now_playing {
        Some(info) => {
            let (badge_text, badge_color) = match info.state {
                PlaybackState::Playing => ("PLAYING", theme::STATUS_CONNECTED),
                PlaybackState::Paused => ("PAUSED", theme::STATUS_CONNECTING),
                PlaybackState::Stopped => ("STOPPED", theme::STATUS_IDLE),
                PlaybackState::Idle => ("IDLE", theme::STATUS_IDLE),
            };

            let artist_or_album = match (&info.artist, &info.album) {
                (Some(art), Some(alb)) => format!("{art} • {alb}"),
                (Some(art), None) => art.clone(),
                (None, Some(alb)) => alb.clone(),
                (None, None) => "Apple TV Media".to_string(),
            };

            div()
                .flex()
                .flex_col()
                .gap_1()
                .w_full()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .w_full()
                        .child(
                            div()
                                .text_sm()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .text_color(theme::TEXT_PRIMARY)
                                .child(info.title.clone()),
                        )
                        .child(
                            div()
                                .px_2()
                                .py_0p5()
                                .rounded_sm()
                                .bg(badge_color)
                                .text_color(theme::BACKGROUND)
                                .text_xs()
                                .font_weight(gpui::FontWeight::BOLD)
                                .child(badge_text),
                        ),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme::TEXT_MUTED)
                        .child(artist_or_album),
                )
        }
        None => div().flex().items_center().justify_center().py_1().child(
            div()
                .text_xs()
                .text_color(theme::TEXT_MUTED)
                .child("No Media Playing"),
        ),
    };

    div()
        .flex()
        .flex_col()
        .w_full()
        .p_3()
        .rounded_xl()
        .bg(theme::SURFACE)
        .border_1()
        .border_color(theme::BORDER)
        .child(content)
}
