//! `FacadeRemoteControl`: one remote control over every connected protocol.
//!
//! Port of `FacadeRemoteControl` (`pyatv/core/facade.py:47-210`). Every method is
//! `self.relay("name")(...)` upstream, and every method here is the same thing: look up the
//! protocol that declared the matching [`FeatureName`], call it, or report
//! [`crate::Error::NotSupported`] when nobody did.
//!
//! This has to be a live object rather than a snapshot of the highest-priority instance, because a
//! caller holds it across a takeover. `test_takeover_and_release`
//! (`tests/core/test_facade.py:544-566`) reads `facade_dummy.audio` *before* the takeover and
//! expects the value to change under it; the same is true of the remote control AirPlay claims for
//! the duration of a `play_url`.

use std::sync::Arc;

use crate::consts::{InputAction, RepeatState, ShuffleState};
use crate::features::FeatureName;
use crate::interface::{BoxFuture, RemoteControl};
use crate::relayer::Relayer;
use crate::{Error, Result};

/// Relays each button to whichever protocol declared it.
#[derive(Debug)]
pub struct FacadeRemoteControl {
    relayer: Arc<Relayer<dyn RemoteControl>>,
}

impl FacadeRemoteControl {
    /// Relay through `relayer`.
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn RemoteControl>>) -> Self {
        Self { relayer }
    }

    /// The instance that declared `feature`, or the error upstream's `_find_instance` raises.
    fn target(&self, feature: FeatureName) -> Result<Arc<dyn RemoteControl>> {
        self.relayer
            .instance_for(feature)
            .ok_or_else(|| Error::NotSupported(format!("{feature} is not supported")))
    }
}

/// Generate one delegating method per button.
///
/// The bodies are all `relay(feature)(args...)`; writing twenty-five of them out by hand would be
/// twenty-five chances to pair a method with the wrong [`FeatureName`].
macro_rules! relay_buttons {
    ($($method:ident => $feature:ident $(, $argument:ident : $type:ty)*);* $(;)?) => {
        $(
            fn $method(&self $(, $argument: $type)*) -> BoxFuture<'_, Result<()>> {
                match self.target(FeatureName::$feature) {
                    Ok(target) => Box::pin(async move { target.$method($($argument),*).await }),
                    Err(error) => Box::pin(async move { Err(error) }),
                }
            }
        )*
    };
}

impl RemoteControl for FacadeRemoteControl {
    relay_buttons! {
        up => Up, action: InputAction;
        down => Down, action: InputAction;
        left => Left, action: InputAction;
        right => Right, action: InputAction;
        select => Select, action: InputAction;
        menu => Menu, action: InputAction;
        home => Home, action: InputAction;
        home_hold => HomeHold;
        top_menu => TopMenu;
        guide => Guide;
        control_center => ControlCenter;
        screensaver => Screensaver;
        play => Play;
        play_pause => PlayPause;
        pause => Pause;
        stop => Stop;
        next => Next;
        previous => Previous;
        skip_forward => SkipForward, interval: f32;
        skip_backward => SkipBackward, interval: f32;
        set_position => SetPosition, position: f32;
        set_shuffle => SetShuffle, state: ShuffleState;
        set_repeat => SetRepeat, state: RepeatState;
        channel_up => ChannelUp;
        channel_down => ChannelDown;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use super::FacadeRemoteControl;
    use crate::consts::{InputAction, Protocol, RepeatState, ShuffleState};
    use crate::facade::DEFAULT_PRIORITIES;
    use crate::features::FeatureName;
    use crate::interface::{BoxFuture, RemoteControl};
    use crate::relayer::Relayer;
    use crate::{Error, Result};

    /// Records which of its methods were called, so a test can see where a button landed.
    #[derive(Debug)]
    struct Recorder {
        name: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    macro_rules! record {
        ($($method:ident($($argument:ident : $type:ty),*)),* $(,)?) => {
            $(
                fn $method(&self $(, $argument: $type)*) -> BoxFuture<'_, Result<()>> {
                    $(let _ = $argument;)*
                    self.calls
                        .lock()
                        .expect("uncontended")
                        .push(format!("{}:{}", self.name, stringify!($method)));
                    Box::pin(async { Ok(()) })
                }
            )*
        };
    }

    impl RemoteControl for Recorder {
        record!(
            up(action: InputAction),
            down(action: InputAction),
            left(action: InputAction),
            right(action: InputAction),
            select(action: InputAction),
            menu(action: InputAction),
            home(action: InputAction),
            home_hold(),
            top_menu(),
            guide(),
            control_center(),
            screensaver(),
            play(),
            play_pause(),
            pause(),
            stop(),
            next(),
            previous(),
            skip_forward(interval: f32),
            skip_backward(interval: f32),
            set_position(position: f32),
            set_shuffle(state: ShuffleState),
            set_repeat(state: RepeatState),
            channel_up(),
            channel_down(),
        );
    }

    /// A facade over one MRP and one AirPlay recorder, plus the pieces a test pokes at.
    struct Fixture {
        remote: FacadeRemoteControl,
        relayer: Arc<Relayer<dyn RemoteControl>>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    fn setup() -> Fixture {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let relayer: Arc<Relayer<dyn RemoteControl>> =
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));

        relayer.register(
            Protocol::Mrp,
            Arc::new(Recorder {
                name: "mrp",
                calls: Arc::clone(&calls),
            }),
            [FeatureName::Up, FeatureName::Stop]
                .into_iter()
                .collect::<BTreeSet<_>>(),
        );
        relayer.register(
            Protocol::AirPlay,
            Arc::new(Recorder {
                name: "airplay",
                calls: Arc::clone(&calls),
            }),
            [FeatureName::Stop].into_iter().collect::<BTreeSet<_>>(),
        );

        Fixture {
            remote: FacadeRemoteControl::new(Arc::clone(&relayer)),
            relayer,
            calls,
        }
    }

    /// Priority decides between two protocols that both declared the button.
    #[tokio::test]
    async fn a_button_goes_to_the_highest_priority_protocol_that_declared_it() {
        let Fixture { remote, calls, .. } = setup();

        remote.stop().await.expect("MRP declared Stop");
        assert_eq!(*calls.lock().expect("uncontended"), vec!["mrp:stop"]);
    }

    /// A button nobody declared is `NotSupportedError` upstream (`relayer.py:114-115`).
    #[tokio::test]
    async fn an_undeclared_button_is_not_supported() {
        let Fixture { remote, .. } = setup();

        let error = remote.play().await.expect_err("nobody declared Play");
        assert!(matches!(error, Error::NotSupported(_)), "{error}");
    }

    /// The whole point: a handle taken before the takeover follows it.
    #[tokio::test]
    async fn a_takeover_redirects_a_handle_taken_earlier() {
        let Fixture {
            remote,
            relayer,
            calls,
        } = setup();

        relayer.takeover(Protocol::AirPlay).expect("free relayer");
        remote.stop().await.expect("AirPlay declared Stop");
        assert_eq!(*calls.lock().expect("uncontended"), vec!["airplay:stop"]);

        // ...but only for buttons AirPlay actually declared.
        remote.up(InputAction::SingleTap).await.expect("MRP has Up");
        assert_eq!(
            *calls.lock().expect("uncontended"),
            vec!["airplay:stop", "mrp:up"]
        );

        relayer.release();
        remote.stop().await.expect("back to MRP");
        assert_eq!(
            *calls.lock().expect("uncontended"),
            vec!["airplay:stop", "mrp:up", "mrp:stop"]
        );
    }
}
