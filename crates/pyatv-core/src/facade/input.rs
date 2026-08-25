//! Per-method relaying for the input interfaces: on-screen keyboard and trackpad gestures.
//!
//! Ports the relaying halves of `FacadeKeyboard` (`pyatv/core/facade.py:546-594`) and
//! `FacadeTouchGestures` (`facade.py:647-679`). As with [`crate::facade::FacadeRemoteControl`],
//! every member is `self.relay("name")(...)` upstream and resolves here through
//! [`crate::relayer::Relayer::instance_for`] on that method's [`FeatureName`].
//!
//! `FacadeKeyboard`'s listening half — remembering the focus state and reporting only genuine
//! changes, filtered to the keyboard relayer's main protocol — is in
//! [`crate::facade::ListenerHub`], which is why nothing here touches focus state beyond relaying
//! the query.

use std::sync::Arc;

use crate::consts::{InputAction, KeyboardFocusState, TouchAction};
use crate::features::FeatureName;
use crate::interface::{BoxFuture, Keyboard, TouchGestures};
use crate::relayer::Relayer;
use crate::{Error, Result};

/// The instance that declared `feature`, or the error upstream's `_find_instance` raises.
fn target<T: ?Sized>(relayer: &Relayer<T>, feature: FeatureName) -> Result<Arc<T>> {
    relayer
        .instance_for(feature)
        .ok_or_else(|| Error::NotSupported(format!("{feature} is not supported")))
}

/// Relays each keyboard call to whichever protocol declared it.
#[derive(Debug)]
pub struct FacadeKeyboard {
    relayer: Arc<Relayer<dyn Keyboard>>,
}

impl FacadeKeyboard {
    /// Relay through `relayer`.
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn Keyboard>>) -> Self {
        Self { relayer }
    }
}

impl Keyboard for FacadeKeyboard {
    /// The declared protocol's focus state, or [`KeyboardFocusState::Unknown`] when nobody declared
    /// one — the same "no error channel in the signature" case [`crate::facade::FacadePower`] has.
    fn text_focus_state(&self) -> KeyboardFocusState {
        target(&self.relayer, FeatureName::TextFocusState)
            .map_or(KeyboardFocusState::Unknown, |target| {
                target.text_focus_state()
            })
    }

    fn text_get(&self) -> BoxFuture<'_, Result<Option<String>>> {
        match target(&self.relayer, FeatureName::TextGet) {
            Ok(target) => Box::pin(async move { target.text_get().await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn text_set(&self, text: &str) -> BoxFuture<'_, Result<()>> {
        let text = text.to_owned();
        match target(&self.relayer, FeatureName::TextSet) {
            Ok(target) => Box::pin(async move { target.text_set(&text).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn text_append(&self, text: &str) -> BoxFuture<'_, Result<()>> {
        let text = text.to_owned();
        match target(&self.relayer, FeatureName::TextAppend) {
            Ok(target) => Box::pin(async move { target.text_append(&text).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn text_clear(&self) -> BoxFuture<'_, Result<()>> {
        match target(&self.relayer, FeatureName::TextClear) {
            Ok(target) => Box::pin(async move { target.text_clear().await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }
}

/// Relays each gesture to whichever protocol declared it.
#[derive(Debug)]
pub struct FacadeTouchGestures {
    relayer: Arc<Relayer<dyn TouchGestures>>,
}

impl FacadeTouchGestures {
    /// Relay through `relayer`.
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn TouchGestures>>) -> Self {
        Self { relayer }
    }
}

impl TouchGestures for FacadeTouchGestures {
    fn action(&self, x: i32, y: i32, action: TouchAction) -> BoxFuture<'_, Result<()>> {
        match target(&self.relayer, FeatureName::TouchAction) {
            Ok(target) => Box::pin(async move { target.action(x, y, action).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn swipe(
        &self,
        start_x: i32,
        start_y: i32,
        end_x: i32,
        end_y: i32,
        duration_ms: u32,
    ) -> BoxFuture<'_, Result<()>> {
        match target(&self.relayer, FeatureName::Swipe) {
            Ok(target) => Box::pin(async move {
                target
                    .swipe(start_x, start_y, end_x, end_y, duration_ms)
                    .await
            }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn click(&self, action: InputAction) -> BoxFuture<'_, Result<()>> {
        match target(&self.relayer, FeatureName::Click) {
            Ok(target) => Box::pin(async move { target.click(action).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use super::{FacadeKeyboard, FacadeTouchGestures};
    use crate::consts::{InputAction, KeyboardFocusState, Protocol, TouchAction};
    use crate::facade::DEFAULT_PRIORITIES;
    use crate::features::FeatureName;
    use crate::interface::{BoxFuture, Keyboard, TouchGestures};
    use crate::relayer::Relayer;
    use crate::{Error, Result};

    /// Records which of its methods were called, so a test can see where a call landed.
    #[derive(Debug)]
    struct Recorder {
        name: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl Recorder {
        fn record(&self, method: &str) {
            self.calls
                .lock()
                .expect("uncontended")
                .push(format!("{}:{method}", self.name));
        }
    }

    impl Keyboard for Recorder {
        fn text_focus_state(&self) -> KeyboardFocusState {
            self.record("text_focus_state");
            KeyboardFocusState::Focused
        }

        fn text_get(&self) -> BoxFuture<'_, Result<Option<String>>> {
            self.record("text_get");
            Box::pin(async move { Ok(Some(self.name.to_owned())) })
        }

        fn text_set(&self, _text: &str) -> BoxFuture<'_, Result<()>> {
            self.record("text_set");
            Box::pin(async { Ok(()) })
        }

        fn text_append(&self, _text: &str) -> BoxFuture<'_, Result<()>> {
            self.record("text_append");
            Box::pin(async { Ok(()) })
        }

        fn text_clear(&self) -> BoxFuture<'_, Result<()>> {
            self.record("text_clear");
            Box::pin(async { Ok(()) })
        }
    }

    impl TouchGestures for Recorder {
        fn action(&self, _x: i32, _y: i32, _action: TouchAction) -> BoxFuture<'_, Result<()>> {
            self.record("action");
            Box::pin(async { Ok(()) })
        }

        fn swipe(
            &self,
            _start_x: i32,
            _start_y: i32,
            _end_x: i32,
            _end_y: i32,
            _duration_ms: u32,
        ) -> BoxFuture<'_, Result<()>> {
            self.record("swipe");
            Box::pin(async { Ok(()) })
        }

        fn click(&self, _action: InputAction) -> BoxFuture<'_, Result<()>> {
            self.record("click");
            Box::pin(async { Ok(()) })
        }
    }

    fn recorder(name: &'static str, calls: &Arc<Mutex<Vec<String>>>) -> Arc<Recorder> {
        Arc::new(Recorder {
            name,
            calls: Arc::clone(calls),
        })
    }

    fn declaring(features: &[FeatureName]) -> BTreeSet<FeatureName> {
        features.iter().copied().collect()
    }

    /// MRP outranks Companion but declares no keyboard feature at all, so every keyboard call has
    /// to fall past it.
    #[tokio::test]
    async fn keyboard_calls_reach_the_protocol_that_declared_them() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let relayer: Arc<Relayer<dyn Keyboard>> =
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        relayer
            .register(Protocol::Mrp, recorder("mrp", &calls), BTreeSet::new())
            .expect("the protocol is in the priority list");
        relayer
            .register(
                Protocol::Companion,
                recorder("companion", &calls),
                declaring(&[FeatureName::TextFocusState, FeatureName::TextGet]),
            )
            .expect("the protocol is in the priority list");

        let keyboard = FacadeKeyboard::new(relayer);
        assert_eq!(keyboard.text_focus_state(), KeyboardFocusState::Focused);
        assert_eq!(
            keyboard.text_get().await.expect("Companion declared it"),
            Some("companion".to_owned())
        );
        let error = keyboard
            .text_clear()
            .await
            .expect_err("nobody declared TextClear");
        assert!(matches!(error, Error::NotSupported(_)), "{error}");

        assert_eq!(
            *calls.lock().expect("uncontended"),
            vec!["companion:text_focus_state", "companion:text_get"]
        );
    }

    /// With nothing registered the focus state is unknown, not a guess.
    #[test]
    fn an_empty_keyboard_relayer_reports_unknown_focus() {
        let relayer: Arc<Relayer<dyn Keyboard>> =
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        assert_eq!(
            FacadeKeyboard::new(relayer).text_focus_state(),
            KeyboardFocusState::Unknown
        );
    }

    #[tokio::test]
    async fn gestures_reach_the_protocol_that_declared_them() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let relayer: Arc<Relayer<dyn TouchGestures>> =
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        relayer
            .register(Protocol::Mrp, recorder("mrp", &calls), BTreeSet::new())
            .expect("the protocol is in the priority list");
        relayer
            .register(
                Protocol::Companion,
                recorder("companion", &calls),
                declaring(&[
                    FeatureName::Swipe,
                    FeatureName::Click,
                    FeatureName::TouchAction,
                ]),
            )
            .expect("the protocol is in the priority list");

        let gestures = FacadeTouchGestures::new(relayer);
        gestures.swipe(0, 0, 10, 10, 100).await.expect("declared");
        gestures
            .action(1, 2, TouchAction::Click)
            .await
            .expect("declared");
        gestures
            .click(InputAction::SingleTap)
            .await
            .expect("declared");

        assert_eq!(
            *calls.lock().expect("uncontended"),
            vec!["companion:swipe", "companion:action", "companion:click"]
        );
    }
}
