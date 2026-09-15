//! Minimalist Apple TV Remote GUI using GPUI.

mod backend;
mod components;
mod discovery;
mod remote;
mod state;
mod theme;
mod view;

use gpui::{
    App, AppContext, Bounds, Context, TitlebarOptions, WindowBounds, WindowOptions, px, size,
};
use gpui_platform::application;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

use crate::backend::BackendEvent;
use crate::view::RemoteView;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    application().run(|cx: &mut App| {
        gpui_tokio::init(cx);

        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<BackendEvent>();
        let action_tx = backend::start_backend(event_tx);

        let bounds = Bounds::centered(None, size(px(360.0), px(720.0)), cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            titlebar: Some(TitlebarOptions {
                title: Some("Apple TV Remote".into()),
                appears_transparent: false,
                traffic_light_position: None,
            }),
            is_resizable: false,
            ..Default::default()
        };

        cx.open_window(options, |window, cx| {
            let view = cx.new(|cx: &mut Context<RemoteView>| {
                cx.spawn(async move |this, cx| {
                    while let Some(event) = event_rx.recv().await {
                        if this
                            .update(cx, |view, cx| {
                                view.handle_backend_event(event, cx);
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                })
                .detach();

                RemoteView::new(action_tx, cx)
            });

            let focus_handle = view.read(cx).focus_handle().clone();
            window.focus(&focus_handle, cx);
            view
        })
        .expect("failed to open Apple TV Remote window");

        cx.activate(true);
    });
}
