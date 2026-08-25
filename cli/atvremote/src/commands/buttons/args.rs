//! Parsing the arguments a button takes.
//!
//! `_extract_command_with_args` (`pyatv/scripts/atvremote.py:810-859`): arguments are positional,
//! and which enum an integer means depends on which command it was given to. Upstream's mapping is
//! a chain of `if cmd == ...` returning a coerced list; here each coercion is its own function so
//! it can be tested without a device.
//!
//! Every enum accepts pyatv's integer *and* a readable name. Upstream only takes the integer,
//! because it constructs the Python enum by value; `set_repeat all` is strictly easier to type than
//! `set_repeat 2` and cannot be ambiguous, since no enum here has a numeric member name.

use anyhow::{Context, Result, bail};
use pyatv::{InputAction, RepeatState, ShuffleState, TouchAction};

/// The positional arguments a button was given, with the button's name for error messages.
#[derive(Debug)]
pub struct Args<'a> {
    /// The button these arguments belong to, quoted back in any failure.
    pub button: &'a str,
    /// The arguments themselves, in the order they were typed.
    pub values: &'a [String],
}

impl Args<'_> {
    /// The argument at `index`, or a message naming what is missing.
    ///
    /// # Errors
    ///
    /// Fails when fewer than `index + 1` arguments were supplied.
    pub fn required(&self, index: usize) -> Result<&str> {
        self.values
            .get(index)
            .map(String::as_str)
            .with_context(|| format!("{} needs {} argument(s)", self.button, index + 1))
    }

    /// The argument at `index`, parsed.
    ///
    /// # Errors
    ///
    /// Fails when the argument is missing or does not parse as `T`.
    pub fn parse<T: std::str::FromStr>(&self, index: usize) -> Result<T>
    where
        T::Err: std::fmt::Display,
    {
        let raw = self.required(index)?;
        raw.parse()
            .map_err(|error| anyhow::anyhow!("{}: {raw:?} is not valid ({error})", self.button))
    }

    /// The argument at `index`, parsed, or `fallback` when it was not supplied.
    ///
    /// # Errors
    ///
    /// Fails when an argument *was* supplied but does not parse as `T`.
    pub fn parse_or<T: std::str::FromStr>(&self, index: usize, fallback: T) -> Result<T>
    where
        T::Err: std::fmt::Display,
    {
        if self.values.len() > index {
            self.parse(index)
        } else {
            Ok(fallback)
        }
    }

    /// An [`InputAction`], defaulting to a single tap.
    ///
    /// `return [InputAction(args[0])]` (`atvremote.py:836-846`) — upstream requires the argument
    /// because the command only reaches that branch when there was an `=`; here it is optional, so
    /// a bare `remote up` still works.
    ///
    /// # Errors
    ///
    /// Fails when the argument is neither `0`, `1`, `2` nor one of their names.
    pub fn input_action(&self) -> Result<InputAction> {
        let Some(raw) = self.values.first() else {
            return Ok(InputAction::SingleTap);
        };

        match raw.to_ascii_lowercase().as_str() {
            "0" | "singletap" | "single_tap" | "tap" => Ok(InputAction::SingleTap),
            "1" | "doubletap" | "double_tap" => Ok(InputAction::DoubleTap),
            "2" | "hold" => Ok(InputAction::Hold),
            other => bail!(
                "{}: {other:?} is not an input action (0, 1 or 2)",
                self.button
            ),
        }
    }

    /// The third argument of `action`, as a [`TouchAction`].
    ///
    /// `return [args[0], args[1], TouchAction(args[2])]` (`atvremote.py:849-850`). The
    /// discriminants are pyatv's and **skip 2**, so `2` is refused rather than silently accepted.
    ///
    /// # Errors
    ///
    /// Fails when the argument is missing or is not one of the four valid phases.
    pub fn touch_action(&self) -> Result<TouchAction> {
        match self.required(2)?.to_ascii_lowercase().as_str() {
            "1" | "press" => Ok(TouchAction::Press),
            "3" | "hold" => Ok(TouchAction::Hold),
            "4" | "release" => Ok(TouchAction::Release),
            "5" | "click" => Ok(TouchAction::Click),
            other => bail!("action: {other:?} is not a touch action (1, 3, 4 or 5)"),
        }
    }

    /// `return [ShuffleState(args[0])]` (`atvremote.py:832-833`).
    ///
    /// # Errors
    ///
    /// Fails when the argument is missing or is not one of the three states.
    pub fn shuffle_state(&self) -> Result<ShuffleState> {
        match self.required(0)?.to_ascii_lowercase().as_str() {
            "0" | "off" => Ok(ShuffleState::Off),
            "1" | "albums" => Ok(ShuffleState::Albums),
            "2" | "songs" => Ok(ShuffleState::Songs),
            other => bail!("set_shuffle: {other:?} is not a shuffle state (0, 1 or 2)"),
        }
    }

    /// `return [RepeatState(args[0])]` (`atvremote.py:834-835`).
    ///
    /// # Errors
    ///
    /// Fails when the argument is missing or is not one of the three states.
    pub fn repeat_state(&self) -> Result<RepeatState> {
        match self.required(0)?.to_ascii_lowercase().as_str() {
            "0" | "off" => Ok(RepeatState::Off),
            "1" | "track" => Ok(RepeatState::Track),
            "2" | "all" => Ok(RepeatState::All),
            other => bail!("set_repeat: {other:?} is not a repeat state (0, 1 or 2)"),
        }
    }
}

/// Split upstream's `name=arg1,arg2` spelling, falling back to the separately supplied arguments.
///
/// `equal_sign = cmd.find("=")` (`atvremote.py:853-859`), so `remote up=1` and `remote up 1` mean
/// the same thing.
#[must_use]
pub fn split(button: &str, args: &[String]) -> (String, Vec<String>) {
    match button.split_once('=') {
        Some((name, rest)) => (
            name.to_owned(),
            rest.split(',').map(ToOwned::to_owned).collect(),
        ),
        None => (button.to_owned(), args.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::{Args, split};
    use pyatv::{InputAction, RepeatState, ShuffleState, TouchAction};

    fn args<'a>(button: &'a str, values: &'a [String]) -> Args<'a> {
        Args { button, values }
    }

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|it| (*it).to_owned()).collect()
    }

    /// `remote up=1` and `remote up 1` must mean the same thing.
    #[test]
    fn upstreams_equals_form_splits_into_arguments() {
        assert_eq!(split("up=1", &[]), ("up".to_owned(), owned(&["1"])));
        assert_eq!(
            split("action=10,20,1", &[]),
            ("action".to_owned(), owned(&["10", "20", "1"]))
        );
        assert_eq!(split("menu", &[]), ("menu".to_owned(), Vec::new()));
    }

    #[test]
    fn separate_arguments_survive_when_there_is_no_equals_sign() {
        let supplied = owned(&["10", "20"]);
        assert_eq!(
            split("action", &supplied),
            ("action".to_owned(), supplied.clone())
        );
    }

    #[test]
    fn input_actions_accept_pyatvs_integers_and_readable_names() {
        for (raw, expected) in [
            ("0", InputAction::SingleTap),
            ("1", InputAction::DoubleTap),
            ("2", InputAction::Hold),
            ("hold", InputAction::Hold),
            ("double_tap", InputAction::DoubleTap),
        ] {
            let values = owned(&[raw]);
            assert_eq!(
                args("up", &values).input_action().expect("a valid action"),
                expected,
                "for {raw:?}"
            );
        }
    }

    #[test]
    fn a_button_with_no_argument_is_a_single_tap() {
        assert_eq!(
            args("up", &[]).input_action().expect("the default applies"),
            InputAction::SingleTap
        );
    }

    #[test]
    fn an_unparseable_action_is_rejected() {
        let values = owned(&["sideways"]);
        assert!(args("up", &values).input_action().is_err());
    }

    #[test]
    fn shuffle_and_repeat_states_match_pyatvs_discriminants() {
        for (raw, expected) in [
            ("0", ShuffleState::Off),
            ("1", ShuffleState::Albums),
            ("2", ShuffleState::Songs),
            ("songs", ShuffleState::Songs),
        ] {
            let values = owned(&[raw]);
            assert_eq!(
                args("set_shuffle", &values)
                    .shuffle_state()
                    .expect("a valid state"),
                expected
            );
        }

        for (raw, expected) in [
            ("0", RepeatState::Off),
            ("1", RepeatState::Track),
            ("2", RepeatState::All),
            ("all", RepeatState::All),
        ] {
            let values = owned(&[raw]);
            assert_eq!(
                args("set_repeat", &values)
                    .repeat_state()
                    .expect("a valid state"),
                expected
            );
        }
    }

    /// `TouchAction` skips 2 upstream, so `2` must be rejected rather than silently accepted.
    #[test]
    fn touch_actions_keep_pyatvs_gap_at_two() {
        for (raw, expected) in [
            ("1", TouchAction::Press),
            ("3", TouchAction::Hold),
            ("4", TouchAction::Release),
            ("5", TouchAction::Click),
            ("release", TouchAction::Release),
        ] {
            let values = owned(&["0", "0", raw]);
            assert_eq!(
                args("action", &values)
                    .touch_action()
                    .expect("a valid action"),
                expected
            );
        }

        let values = owned(&["0", "0", "2"]);
        assert!(args("action", &values).touch_action().is_err());
    }

    #[test]
    fn a_missing_argument_names_the_button() {
        let error = args("set_position", &[])
            .parse::<f32>(0)
            .expect_err("a missing argument must fail");

        assert!(error.to_string().contains("set_position"), "{error}");
    }

    #[test]
    fn optional_arguments_fall_back_to_the_default() {
        let parsed = args("skip_forward", &[])
            .parse_or(0, 0.0_f32)
            .expect("the default must apply");
        assert!((parsed - 0.0).abs() < f32::EPSILON);

        let values = owned(&["30"]);
        let parsed = args("skip_forward", &values)
            .parse_or(0, 0.0_f32)
            .expect("a supplied value must win");
        assert!((parsed - 30.0).abs() < f32::EPSILON);
    }
}
