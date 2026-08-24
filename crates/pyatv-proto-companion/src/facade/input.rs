//! [`Keyboard`] and [`TouchGestures`] over Companion.
//!
//! Ports `CompanionKeyboard` (`__init__.py:490-533`) and `CompanionTouchGestures` (`:536-574`).
//! Both are Companion-only capabilities: no other pyatv protocol implements either.

use std::sync::Arc;

use pyatv_core::interface::{BoxFuture, Keyboard, TouchGestures};
use pyatv_core::{InputAction, KeyboardFocusState, Result, TouchAction};

use crate::api::CompanionApi;

/// On-screen keyboard entry.
///
/// All four operations funnel through the one `_tiStop` → `_tiStart` → optional `_tiC` exchange in
/// [`CompanionApi::text_input_command`]; only the two boolean-ish arguments differ:
///
/// | Method | `text` | `clear_previous_input` |
/// |---|---|---|
/// | `text_get` | `""` | `false` |
/// | `text_clear` | `""` | `true` |
/// | `text_append` | the text | `false` |
/// | `text_set` | the text | `true` |
#[derive(Debug)]
pub struct CompanionKeyboard {
    api: Arc<CompanionApi>,
}

impl CompanionKeyboard {
    /// Wrap a connected session.
    #[must_use]
    pub const fn new(api: Arc<CompanionApi>) -> Self {
        Self { api }
    }

    fn edit(&self, text: String, clear: bool) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.api
                .text_input_command(&text, clear)
                .await
                .map(|_| ())
                .map_err(Into::into)
        })
    }
}

impl Keyboard for CompanionKeyboard {
    /// Focus as of the last `_tiStart` response or `_tiStarted`/`_tiStopped` push.
    fn text_focus_state(&self) -> KeyboardFocusState {
        self.api.observed().focus
    }

    fn text_get(&self) -> BoxFuture<'_, Result<Option<String>>> {
        Box::pin(async move {
            self.api
                .text_input_command("", false)
                .await
                .map_err(Into::into)
        })
    }

    fn text_set(&self, text: &str) -> BoxFuture<'_, Result<()>> {
        self.edit(text.to_owned(), true)
    }

    fn text_append(&self, text: &str) -> BoxFuture<'_, Result<()>> {
        self.edit(text.to_owned(), false)
    }

    fn text_clear(&self) -> BoxFuture<'_, Result<()>> {
        self.edit(String::new(), true)
    }
}

/// Trackpad gestures on the virtual touch surface.
#[derive(Debug)]
pub struct CompanionTouchGestures {
    api: Arc<CompanionApi>,
}

impl CompanionTouchGestures {
    /// Wrap a connected session.
    #[must_use]
    pub const fn new(api: Arc<CompanionApi>) -> Self {
        Self { api }
    }
}

impl TouchGestures for CompanionTouchGestures {
    fn action(&self, x: i32, y: i32, action: TouchAction) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { self.api.hid_event(x, y, action).await.map_err(Into::into) })
    }

    fn swipe(
        &self,
        start_x: i32,
        start_y: i32,
        end_x: i32,
        end_y: i32,
        duration_ms: u32,
    ) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.api
                .swipe(start_x, start_y, end_x, end_y, duration_ms)
                .await
                .map_err(Into::into)
        })
    }

    /// A select click. `TouchAction` is not the right vocabulary here — upstream's `click` takes an
    /// [`InputAction`] — so the phase is mapped onto one: [`TouchAction::Click`] is a single tap,
    /// [`TouchAction::Hold`] is a hold, and the two remaining phases have no click meaning.
    fn click(&self, action: TouchAction) -> BoxFuture<'_, Result<()>> {
        let action = match action {
            TouchAction::Hold => InputAction::Hold,
            TouchAction::Press | TouchAction::Release | TouchAction::Click => {
                InputAction::SingleTap
            }
        };

        Box::pin(async move { self.api.click(action).await.map_err(Into::into) })
    }
}
