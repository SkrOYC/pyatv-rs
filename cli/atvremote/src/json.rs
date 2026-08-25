//! pyatv's `atvscript` JSON schema.
//!
//! `--json` makes this binary emit what upstream's separate `atvscript` entry point emits, rather
//! than shipping a second binary: the two tools differ only in how they render, and pyatv's own
//! docs describe `atvscript` as "a subset of what `atvremote` supports"
//! (`docs/documentation/atvscript.md:16-18`). Every key here is upstream's.
//!
//! # The envelope
//!
//! `output(success, error, exception, values)` (`pyatv/scripts/atvscript.py:192-207`) builds a
//! dictionary with `result` (`"success"` or `"failure"`) and `datetime` always present, then
//! `error` and `exception` when there was one, then the command's own keys merged in at the top
//! level. One object per line, `flush=True` after each (`atvscript.py:56-59`).
//!
//! # Where this necessarily diverges
//!
//! | Key | Upstream | Here |
//! | --- | --- | --- |
//! | `datetime` | local time with the local UTC offset (`atvscript.py:194`) | UTC, i.e. always `+00:00`. Reading the local offset needs a tz database and is unsound to do from a threaded process in the crates that offer it; the instant is identical, only the rendering differs. |
//! | `stacktrace` | `traceback.format_exception(...)` | the `anyhow` error chain, since Rust errors carry no traceback. Omitted when the chain has a single link. |
//! | `hash` | falls back to `sha256(title+artist+album+total_time)` when unset (`pyatv/interface.py:601-612`) | `null` when unset; the fallback is not implemented in `pyatv-core` (see `models/playing.rs`). |
//!
//! Commands `atvscript` does not have — `features`, `device_info`, `app_list` and the rest — get a
//! key named after the command holding its result, inside the same envelope. Those keys are this
//! tool's own; everything documented in `atvscript.md` is reproduced exactly.

mod convert;
mod time;

pub use convert::{
    device_info_value, device_value, focus_state_name, output_device_value, playing_values,
    power_state_name,
};

use serde_json::{Map, Value};

/// One line of JSON output, before it is rendered.
///
/// Built rather than assembled inline so that the key order matches upstream's: `result` and
/// `datetime` first, then `error`, then `exception` and `stacktrace`, then the command's own
/// values. `serde_json`'s default `Map` is insertion-ordered only with the `preserve_order`
/// feature, which is off — so key order in the *rendered* text is alphabetical either way, and
/// this ordering is for readers of the code rather than of the output.
#[derive(Debug)]
pub struct Envelope {
    fields: Map<String, Value>,
}

impl Envelope {
    /// A successful result with no values yet.
    #[must_use]
    pub fn success() -> Self {
        Self::new(true)
    }

    /// A failed result with no values yet.
    #[must_use]
    pub fn failure() -> Self {
        Self::new(false)
    }

    fn new(success: bool) -> Self {
        let mut fields = Map::new();
        fields.insert(
            "result".to_owned(),
            Value::String(if success { "success" } else { "failure" }.to_owned()),
        );
        fields.insert("datetime".to_owned(), Value::String(time::now_iso8601()));
        Self { fields }
    }

    /// Attach upstream's well-defined `error` string.
    ///
    /// The vocabulary is closed: `device_not_found` and `unsupported_command`
    /// (`docs/documentation/atvscript.md:31`, produced at `atvscript.py:289,336`).
    #[must_use]
    pub fn error(mut self, error: &str) -> Self {
        self.fields
            .insert("error".to_owned(), Value::String(error.to_owned()));
        self
    }

    /// Attach an unexpected failure as `exception`, plus `stacktrace` when there is a cause chain.
    #[must_use]
    pub fn exception(mut self, error: &anyhow::Error) -> Self {
        self.fields
            .insert("exception".to_owned(), Value::String(error.to_string()));

        let chain: Vec<String> = error.chain().skip(1).map(ToString::to_string).collect();
        if !chain.is_empty() {
            self.fields
                .insert("stacktrace".to_owned(), Value::String(chain.join("\n")));
        }
        self
    }

    /// Merge one key into the envelope, as `result.update(**values)` does.
    #[must_use]
    pub fn value(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.fields.insert(key.to_owned(), value.into());
        self
    }

    /// Merge a whole map of keys, as the `playing` response does.
    #[must_use]
    pub fn values(mut self, values: Map<String, Value>) -> Self {
        self.fields.extend(values);
        self
    }

    /// The rendered line, without its newline.
    ///
    /// Serialisation of a `Map` of already-valid `Value`s cannot fail, but `to_string` returns a
    /// `Result` all the same; the fallback is a hand-written envelope rather than a panic, because
    /// a `--json` caller parsing our output should never be handed a non-JSON line.
    #[must_use]
    pub fn render(self) -> String {
        serde_json::to_string(&Value::Object(self.fields)).unwrap_or_else(|_| {
            r#"{"result": "failure", "error": "could not serialise the response"}"#.to_owned()
        })
    }
}

/// Print one envelope, flushed, the way every `print(..., flush=True)` upstream does.
pub fn emit(envelope: Envelope) {
    use std::io::Write as _;

    let mut stdout = std::io::stdout().lock();
    // A write failure here means stdout is gone (a closed pipe, typically). There is nowhere left
    // to report it, and the process is about to exit anyway.
    let _ = writeln!(stdout, "{}", envelope.render());
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::Envelope;
    use serde_json::Value;

    fn parse(envelope: Envelope) -> Value {
        serde_json::from_str(&envelope.render()).expect("the envelope must be valid JSON")
    }

    #[test]
    fn every_envelope_carries_result_and_datetime() {
        let value = parse(Envelope::success());
        assert_eq!(value["result"], "success");
        assert!(
            value["datetime"]
                .as_str()
                .is_some_and(|it| it.contains('T')),
            "datetime must be ISO-8601: {value}"
        );

        assert_eq!(parse(Envelope::failure())["result"], "failure");
    }

    #[test]
    fn error_and_exception_only_appear_on_failure_paths() {
        let value = parse(Envelope::success());
        assert!(value.get("error").is_none());
        assert!(value.get("exception").is_none());
        assert!(value.get("stacktrace").is_none());

        let value = parse(Envelope::failure().error("device_not_found"));
        assert_eq!(value["error"], "device_not_found");
    }

    #[test]
    fn an_exception_chain_becomes_a_stacktrace() {
        let bare = anyhow::anyhow!("it broke");
        let value = parse(Envelope::failure().exception(&bare));
        assert_eq!(value["exception"], "it broke");
        assert!(
            value.get("stacktrace").is_none(),
            "a single-link chain has no trace to show"
        );

        let chained = bare.context("while connecting");
        let value = parse(Envelope::failure().exception(&chained));
        assert_eq!(value["exception"], "while connecting");
        assert_eq!(value["stacktrace"], "it broke");
    }

    #[test]
    fn values_merge_at_the_top_level() {
        let value = parse(Envelope::success().value("command", "menu"));
        assert_eq!(value["command"], "menu");
        assert_eq!(value["result"], "success");
    }

    /// The line `atvscript menu` prints, verbatim from `docs/documentation/atvscript.md:225`.
    #[test]
    fn a_button_press_matches_the_documented_shape() {
        let value = parse(Envelope::success().value("command", "menu"));
        let object = value.as_object().expect("an object");

        assert_eq!(
            object.len(),
            3,
            "result, datetime and command only: {value}"
        );
    }
}
