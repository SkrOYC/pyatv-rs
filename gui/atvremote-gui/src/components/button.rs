//! Reusable button elements for the Apple TV Remote GUI.

use gpui::{
    App, ClickEvent, ElementId, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled, Window, div, px,
};

use crate::theme;

/// A circular remote action button (e.g. Menu, Home, Play/Pause).
pub fn round_button(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    sublabel: Option<&'static str>,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let sub = sublabel.map(|s| div().text_xs().text_color(theme::TEXT_MUTED).child(s));

    div()
        .id(id)
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .size(px(54.0))
        .rounded_full()
        .bg(theme::SURFACE)
        .hover(|s| s.bg(theme::SURFACE_HOVER))
        .active(|s| s.bg(theme::SURFACE_ACTIVE))
        .border_1()
        .border_color(theme::BORDER)
        .cursor_pointer()
        .text_color(theme::TEXT_PRIMARY)
        .on_click(on_click)
        .child(
            div()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(label.into()),
        )
        .children(sub)
}

/// A compact pill button for utility actions (e.g. Scan, Power).
pub fn pill_button(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    accent: bool,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let bg = if accent {
        theme::ACCENT
    } else {
        theme::SURFACE
    };
    let bg_hover = if accent {
        theme::ACCENT
    } else {
        theme::SURFACE_HOVER
    };

    div()
        .id(id)
        .flex()
        .items_center()
        .justify_center()
        .px_3()
        .py_1()
        .rounded_md()
        .bg(bg)
        .hover(|s| s.bg(bg_hover))
        .active(|s| s.bg(theme::SURFACE_ACTIVE))
        .border_1()
        .border_color(theme::BORDER)
        .cursor_pointer()
        .text_xs()
        .font_weight(gpui::FontWeight::MEDIUM)
        .text_color(theme::TEXT_PRIMARY)
        .on_click(on_click)
        .child(label.into())
}
