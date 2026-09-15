//! Pairing PIN entry dialog component.

use gpui::{
    AnyElement, Context, InteractiveElement, IntoElement, ParentElement,
    StatefulInteractiveElement, Styled, div, px,
};

use crate::state::AppState;
use crate::theme;
use crate::view::RemoteView;

/// Render the pairing modal with numeric PIN pad.
pub fn render_pairing_dialog(state: &AppState, cx: &mut Context<RemoteView>) -> impl IntoElement {
    let target_device = state
        .pairing_device
        .as_ref()
        .map_or("Apple TV", |(n, _)| n.as_str());
    let error = state.pairing_error.as_deref();

    let error_view = error.map(|e| {
        div()
            .text_xs()
            .text_color(theme::STATUS_ERROR)
            .child(e.to_string())
    });

    div()
        .flex()
        .flex_col()
        .items_center()
        .gap_4()
        .p_4()
        .w_full()
        .rounded_lg()
        .bg(theme::BACKGROUND)
        .border_1()
        .border_color(theme::BORDER)
        .shadow_lg()
        .child(
            div()
                .text_sm()
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(theme::TEXT_PRIMARY)
                .child(format!("Pair with {target_device}")),
        )
        .child(
            div()
                .text_xs()
                .text_color(theme::TEXT_MUTED)
                .child("Enter the 4-digit code shown on your TV"),
        )
        .child(render_pin_slots(&state.pairing_pin))
        .children(error_view)
        .child(render_keypad(cx))
}

fn render_pin_slots(pin: &str) -> impl IntoElement {
    let mut slots: Vec<AnyElement> = Vec::new();
    for i in 0..4 {
        let ch = pin.chars().nth(i).map_or("·", |_| "●");
        let is_filled = pin.chars().nth(i).is_some();
        let slot = div()
            .flex()
            .items_center()
            .justify_center()
            .size(px(40.0))
            .rounded_md()
            .bg(theme::SURFACE)
            .border_1()
            .border_color(if is_filled {
                theme::ACCENT
            } else {
                theme::BORDER
            })
            .text_lg()
            .font_weight(gpui::FontWeight::BOLD)
            .text_color(if is_filled {
                theme::TEXT_PRIMARY
            } else {
                theme::TEXT_MUTED
            })
            .child(ch);
        slots.push(slot.into_any_element());
    }

    div()
        .flex()
        .items_center()
        .justify_center()
        .gap_3()
        .children(slots)
}

fn render_keypad(cx: &mut Context<RemoteView>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(
            div()
                .flex()
                .gap_3()
                .justify_center()
                .child(make_pin_key("1", '1', cx))
                .child(make_pin_key("2", '2', cx))
                .child(make_pin_key("3", '3', cx)),
        )
        .child(
            div()
                .flex()
                .gap_3()
                .justify_center()
                .child(make_pin_key("4", '4', cx))
                .child(make_pin_key("5", '5', cx))
                .child(make_pin_key("6", '6', cx)),
        )
        .child(
            div()
                .flex()
                .gap_3()
                .justify_center()
                .child(make_pin_key("7", '7', cx))
                .child(make_pin_key("8", '8', cx))
                .child(make_pin_key("9", '9', cx)),
        )
        .child(
            div()
                .flex()
                .gap_3()
                .justify_center()
                .child(
                    div()
                        .id("pin-cancel-btn")
                        .flex()
                        .items_center()
                        .justify_center()
                        .size(px(48.0))
                        .rounded_full()
                        .bg(theme::SURFACE)
                        .hover(|s| s.bg(theme::SURFACE_HOVER))
                        .border_1()
                        .border_color(theme::BORDER)
                        .cursor_pointer()
                        .text_xs()
                        .text_color(theme::TEXT_MUTED)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.cancel_pairing(cx);
                        }))
                        .child("Cancel"),
                )
                .child(make_pin_key("0", '0', cx))
                .child(
                    div()
                        .id("pin-backspace-btn")
                        .flex()
                        .items_center()
                        .justify_center()
                        .size(px(48.0))
                        .rounded_full()
                        .bg(theme::SURFACE)
                        .hover(|s| s.bg(theme::SURFACE_HOVER))
                        .border_1()
                        .border_color(theme::BORDER)
                        .cursor_pointer()
                        .text_base()
                        .text_color(theme::TEXT_MUTED)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.backspace_pairing_digit(cx);
                        }))
                        .child("⌫"),
                ),
        )
}

fn make_pin_key(
    label: &'static str,
    digit: char,
    cx: &mut Context<RemoteView>,
) -> impl IntoElement {
    div()
        .id(format!("pin-key-{digit}"))
        .flex()
        .items_center()
        .justify_center()
        .size(px(48.0))
        .rounded_full()
        .bg(theme::SURFACE)
        .hover(|s| s.bg(theme::SURFACE_HOVER))
        .border_1()
        .border_color(theme::BORDER)
        .cursor_pointer()
        .text_base()
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .text_color(theme::TEXT_PRIMARY)
        .on_click(cx.listener(move |this, _, _, cx| {
            this.append_pairing_digit(digit, cx);
        }))
        .child(label)
}
