//! Circular D-Pad element for directional navigation and item selection.

use gpui::{
    InteractiveElement, IntoElement, ParentElement, StatefulInteractiveElement, Styled, div, px,
};
use std::rc::Rc;

use crate::remote::RemoteCommand;
use crate::theme;

/// Render the circular Apple TV D-Pad.
pub fn render_dpad(on_command: impl Fn(RemoteCommand) + 'static) -> impl IntoElement {
    let on_cmd = Rc::new(on_command);

    let make_nav = |id: &'static str,
                    label: &'static str,
                    cmd: RemoteCommand,
                    on_cmd: Rc<dyn Fn(RemoteCommand)>| {
        div()
            .id(id)
            .flex()
            .items_center()
            .justify_center()
            .cursor_pointer()
            .text_color(theme::TEXT_PRIMARY)
            .hover(|s| s.text_color(theme::ACCENT))
            .active(|s| s.bg(theme::DPAD_BTN_HOVER))
            .on_click(move |_, _, _| on_cmd(cmd))
            .child(label)
    };

    let up = make_nav("dpad-up", "▲", RemoteCommand::Up, on_cmd.clone())
        .w_full()
        .h(px(46.0));

    let down = make_nav("dpad-down", "▼", RemoteCommand::Down, on_cmd.clone())
        .w_full()
        .h(px(46.0));

    let left = make_nav("dpad-left", "◀", RemoteCommand::Left, on_cmd.clone())
        .h_full()
        .w(px(46.0));

    let right = make_nav("dpad-right", "▶", RemoteCommand::Right, on_cmd.clone())
        .h_full()
        .w(px(46.0));

    let on_center = on_cmd.clone();
    let center = div()
        .id("dpad-center")
        .flex()
        .items_center()
        .justify_center()
        .size(px(72.0))
        .rounded_full()
        .bg(theme::DPAD_CENTER_BG)
        .hover(|s| s.bg(theme::DPAD_BTN_HOVER))
        .active(|s| s.bg(theme::SURFACE_ACTIVE))
        .border_1()
        .border_color(theme::BORDER)
        .cursor_pointer()
        .text_color(theme::TEXT_PRIMARY)
        .font_weight(gpui::FontWeight::BOLD)
        .on_click(move |_, _, _| on_center(RemoteCommand::Select))
        .child("OK");

    div()
        .flex()
        .items_center()
        .justify_center()
        .w_full()
        .py_3()
        .child(
            div()
                .flex()
                .flex_col()
                .items_center()
                .justify_between()
                .size(px(180.0))
                .rounded_full()
                .bg(theme::DPAD_BG)
                .border_2()
                .border_color(theme::BORDER)
                .shadow_md()
                .child(up)
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .w_full()
                        .px_1()
                        .child(left)
                        .child(center)
                        .child(right),
                )
                .child(down),
        )
}
