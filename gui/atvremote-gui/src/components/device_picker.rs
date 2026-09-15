//! Device selection and connection status header component.

use gpui::{
    AnyElement, App, ClickEvent, InteractiveElement, IntoElement, ParentElement,
    StatefulInteractiveElement, Styled, Window, div, px,
};
use std::rc::Rc;

use crate::components::button::pill_button;
use crate::state::{AppState, ConnectionState, DiscoveredDevice};
use crate::theme;

/// Render the device header and optional device selector dropdown.
pub fn render_device_header(
    state: &AppState,
    on_toggle_picker: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    on_scan: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    on_select_device: impl Fn(String) + 'static,
    on_pair_device: impl Fn(String) + 'static,
    on_toggle_power: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let header_bar = render_header_bar(state, on_toggle_picker, on_scan, on_toggle_power);
    let is_scanning = state.connection == ConnectionState::Scanning;
    let dropdown = state.show_device_picker.then(|| {
        render_dropdown(
            &state.devices,
            is_scanning,
            on_select_device,
            on_pair_device,
        )
    });

    div()
        .flex()
        .flex_col()
        .gap_2()
        .w_full()
        .child(header_bar)
        .children(dropdown)
}

fn render_header_bar(
    state: &AppState,
    on_toggle_picker: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    on_scan: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    on_toggle_power: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let (dot_color, status_text) = match &state.connection {
        ConnectionState::Connected { name, .. } => {
            if state.can_navigate {
                (theme::STATUS_CONNECTED, name.clone())
            } else {
                (theme::STATUS_CONNECTING, format!("{name} (Unpaired)"))
            }
        }
        ConnectionState::Connecting(name) => (theme::STATUS_CONNECTING, name.clone()),
        ConnectionState::Scanning => (theme::STATUS_CONNECTING, "Scanning LAN...".to_string()),
        ConnectionState::Disconnected => (theme::STATUS_IDLE, "No Device Connected".to_string()),
        ConnectionState::Error(err) => (theme::STATUS_ERROR, err.clone()),
    };

    let power_icon = if state.power_on { "⏻ ON" } else { "⏻ OFF" };
    let picker_toggle_icon = if state.show_device_picker {
        "▲"
    } else {
        "▼"
    };

    div()
        .flex()
        .items_center()
        .justify_between()
        .w_full()
        .py_1()
        .child(
            div()
                .id("device-select-trigger")
                .flex()
                .items_center()
                .gap_2()
                .cursor_pointer()
                .on_click(on_toggle_picker)
                .child(div().size(px(10.0)).rounded_full().bg(dot_color))
                .child(
                    div()
                        .text_sm()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(theme::TEXT_PRIMARY)
                        .child(status_text),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme::TEXT_MUTED)
                        .child(picker_toggle_icon),
                ),
        )
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(pill_button("scan-btn", "↻ Scan", false, on_scan))
                .child(pill_button(
                    "power-btn",
                    power_icon,
                    state.power_on,
                    on_toggle_power,
                )),
        )
}

fn render_dropdown(
    devices: &[DiscoveredDevice],
    is_scanning: bool,
    on_select_device: impl Fn(String) + 'static,
    on_pair_device: impl Fn(String) + 'static,
) -> impl IntoElement {
    let on_select: Rc<dyn Fn(String)> = Rc::new(on_select_device);
    let on_pair: Rc<dyn Fn(String)> = Rc::new(on_pair_device);
    let mut device_items: Vec<AnyElement> = Vec::new();

    if devices.is_empty() {
        let msg = if is_scanning {
            "Scanning local network for Apple TVs..."
        } else {
            "No devices discovered. Click Scan to search."
        };
        device_items.push(
            div()
                .text_xs()
                .text_color(theme::TEXT_MUTED)
                .p_2()
                .child(msg)
                .into_any_element(),
        );
    } else {
        for dev in devices {
            device_items.push(render_device_row(dev, on_select.clone(), on_pair.clone()));
        }
    }

    div()
        .flex()
        .flex_col()
        .gap_1()
        .w_full()
        .p_2()
        .rounded_lg()
        .bg(theme::SURFACE)
        .border_1()
        .border_color(theme::BORDER)
        .shadow_lg()
        .children(device_items)
}

fn render_device_row(
    dev: &DiscoveredDevice,
    on_select: Rc<dyn Fn(String)>,
    on_pair: Rc<dyn Fn(String)>,
) -> AnyElement {
    let id = dev.identifier.clone();
    let name = dev.name.clone();
    let addr = dev.address.clone().unwrap_or_default();
    let is_paired = dev.is_paired;
    let status_badge = if is_paired { "Paired" } else { "Unpaired" };
    let pair_id = id.clone();

    let action = if is_paired {
        div()
            .text_xs()
            .font_weight(gpui::FontWeight::SEMIBOLD)
            .text_color(theme::ACCENT)
            .child("Connect")
            .into_any_element()
    } else {
        div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                div()
                    .id(format!("pair-btn-{}", dev.identifier))
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .bg(theme::ACCENT)
                    .hover(|s| s.bg(theme::SURFACE_HOVER))
                    .cursor_pointer()
                    .text_xs()
                    .font_weight(gpui::FontWeight::BOLD)
                    .text_color(theme::TEXT_PRIMARY)
                    .on_click(move |_, _, _| on_pair(pair_id.clone()))
                    .child("Pair"),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(theme::TEXT_MUTED)
                    .child("Connect"),
            )
            .into_any_element()
    };

    div()
        .id(format!("dev-{}", dev.identifier))
        .flex()
        .items_center()
        .justify_between()
        .p_2()
        .rounded_md()
        .hover(|s| s.bg(theme::SURFACE_HOVER))
        .cursor_pointer()
        .on_click(move |_, _, _| on_select(id.clone()))
        .child(
            div()
                .flex()
                .flex_col()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(div().text_sm().text_color(theme::TEXT_PRIMARY).child(name))
                        .child(
                            div()
                                .text_xs()
                                .text_color(if is_paired {
                                    theme::STATUS_CONNECTED
                                } else {
                                    theme::STATUS_CONNECTING
                                })
                                .child(format!("({status_badge})")),
                        ),
                )
                .child(div().text_xs().text_color(theme::TEXT_MUTED).child(addr)),
        )
        .child(action)
        .into_any_element()
}
