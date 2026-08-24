//! A `json.dumps`-compatible JSON writer.
//!
//! `~/.pyatv.conf` is written by `json.dumps(dumped) + "\n"` (`pyatv/storage/file_storage.py:48`)
//! with `CPython`'s defaults, which differ from `serde_json`'s compact output in two ways:
//!
//! - separators are `", "` and `": "`, not `","` and `":"`;
//! - `ensure_ascii=True`, so every non-ASCII character is escaped as `\uXXXX` (a surrogate pair
//!   above the BMP) instead of being written as UTF-8.
//!
//! Reproducing both makes the file this crate writes byte-identical to the one pyatv writes, which
//! is what lets [`crate::storage::Storage::save`] use a plain string comparison for change
//! detection and what keeps a diff of a user's settings file empty when they switch tools.

use std::io;

use serde::Serialize;
use serde_json::ser::Formatter;

/// `CPython`'s `json.dumps` formatting.
#[derive(Debug, Default, Clone, Copy)]
pub struct PythonFormatter;

impl Formatter for PythonFormatter {
    fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        writer.write_all(b": ")
    }

    /// `ensure_ascii=True`: escape everything above U+007F.
    ///
    /// `serde_json` hands this method the runs of text between the escapes it already knows about
    /// (quotes, backslashes, control characters), so only the non-ASCII case is left to handle.
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut ascii_from = 0;
        for (index, character) in fragment.char_indices() {
            if character.is_ascii() {
                continue;
            }

            writer.write_all(&fragment.as_bytes()[ascii_from..index])?;
            ascii_from = index + character.len_utf8();

            let mut units = [0u16; 2];
            for unit in character.encode_utf16(&mut units) {
                writer.write_all(format!("\\u{unit:04x}").as_bytes())?;
            }
        }

        writer.write_all(&fragment.as_bytes()[ascii_from..])
    }
}

/// Serialise `value` exactly as `CPython`'s `json.dumps` would.
///
/// # Errors
///
/// Returns [`serde_json::Error`] if `value`'s `Serialize` implementation fails, which for the
/// settings models cannot happen.
pub fn to_python_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, PythonFormatter);
    value.serialize(&mut serializer)?;

    // `Serializer` only ever writes the UTF-8 `serde_json` produced, and the escaping above
    // replaces non-ASCII with ASCII, so the buffer is always valid UTF-8.
    String::from_utf8(out).map_err(serde::ser::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::to_python_json;

    #[test]
    fn separators_match_json_dumps() {
        let value = serde_json::json!({"version": 1, "devices": [{"a": 1}, {"b": [1, 2]}]});
        assert_eq!(
            to_python_json(&value).expect("serialising must succeed"),
            r#"{"devices": [{"a": 1}, {"b": [1, 2]}], "version": 1}"#
        );
    }

    #[test]
    fn empty_containers_are_unchanged() {
        let value = serde_json::json!({"a": {}, "b": []});
        assert_eq!(
            to_python_json(&value).expect("serialising must succeed"),
            r#"{"a": {}, "b": []}"#
        );
    }

    /// `json.dumps("Vardagsrum – Salång")` escapes both, and so must this.
    #[test]
    fn non_ascii_is_escaped_like_ensure_ascii() {
        let value = serde_json::json!({"name": "Sal\u{e5}ng \u{2013} \u{1f4fa}"});
        assert_eq!(
            to_python_json(&value).expect("serialising must succeed"),
            "{\"name\": \"Sal\\u00e5ng \\u2013 \\ud83d\\udcfa\"}"
        );
    }

    #[test]
    fn ascii_escapes_are_left_to_serde_json() {
        let value = serde_json::json!({"a": "quote\" tab\t"});
        assert_eq!(
            to_python_json(&value).expect("serialising must succeed"),
            r#"{"a": "quote\" tab\t"}"#
        );
    }
}
