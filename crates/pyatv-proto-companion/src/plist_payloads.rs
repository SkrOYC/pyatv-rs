//! The two hand-encoded `NSKeyedArchiver` payloads the RTI text-input service accepts.
//!
//! Port of `pyatv/protocols/companion/plist_payloads/rti_text_operations.py`, reproduced verbatim
//! in `docs/research/companion-port-spec.md` §6. pyatv never wrote a general `NSKeyedArchiver`
//! encoder: it emits exactly two fixed object graphs with one or two substitution points each, and
//! this port does the same rather than deriving a shared builder. The object numbering genuinely
//! differs between the two shapes — "clear" has a `textToAssert` slot that "insert" does not, and
//! "insert" has an `insertionText` slot that "clear" does not — so one parameterised encoder would
//! have to reproduce that difference anyway.
//!
//! Two details are load-bearing and easy to lose:
//!
//! - `$archiver` is `"RTIKeyedArchiver"`, **not** the generic `"NSKeyedArchiver"` a real
//!   Foundation archiver would write. It is an RTI-service-specific class name and a strict device
//!   may reject anything else.
//! - Key order inside each dictionary is upstream's (`sort_keys=False`), preserved here by
//!   [`plist::Dictionary`]'s insertion-ordered backing map.

use plist::{Dictionary, Uid, Value};

/// `$version`, from `plistlib.dumps({... "$version": 100000 ...})`.
const ARCHIVE_VERSION: i64 = 100_000;

/// `$archiver`. See the module docs: this is deliberately not `NSKeyedArchiver`.
const ARCHIVER: &str = "RTIKeyedArchiver";

/// Build an `NSKeyedArchiver` payload that clears the focused text field.
///
/// `get_rti_clear_text_payload` (`rti_text_operations.py:14-76`).
#[must_use]
pub fn rti_clear_text_payload(session_uuid: &[u8]) -> Vec<u8> {
    let objects = vec![
        Value::String("$null".to_owned()),
        dictionary([
            ("$class", Value::Uid(Uid::new(7))),
            ("targetSessionUUID", Value::Uid(Uid::new(5))),
            ("keyboardOutput", Value::Uid(Uid::new(2))),
            ("textToAssert", Value::Uid(Uid::new(4))),
        ]),
        dictionary([("$class", Value::Uid(Uid::new(3)))]),
        class("TIKeyboardOutput"),
        Value::String(String::new()),
        dictionary([
            ("NS.uuidbytes", Value::Data(session_uuid.to_vec())),
            ("$class", Value::Uid(Uid::new(6))),
        ]),
        class("NSUUID"),
        class("RTITextOperations"),
    ];

    encode(objects)
}

/// Build an `NSKeyedArchiver` payload that inserts `text` into the focused text field.
///
/// `get_rti_input_text_payload` (`rti_text_operations.py:79-147`). Note the object numbering is not
/// the same as [`rti_clear_text_payload`]'s, and neither is the key order inside object 1.
#[must_use]
pub fn rti_input_text_payload(session_uuid: &[u8], text: &str) -> Vec<u8> {
    let objects = vec![
        Value::String("$null".to_owned()),
        dictionary([
            ("keyboardOutput", Value::Uid(Uid::new(2))),
            ("$class", Value::Uid(Uid::new(7))),
            ("targetSessionUUID", Value::Uid(Uid::new(5))),
        ]),
        dictionary([
            ("insertionText", Value::Uid(Uid::new(3))),
            ("$class", Value::Uid(Uid::new(4))),
        ]),
        Value::String(text.to_owned()),
        class("TIKeyboardOutput"),
        dictionary([
            ("NS.uuidbytes", Value::Data(session_uuid.to_vec())),
            ("$class", Value::Uid(Uid::new(6))),
        ]),
        class("NSUUID"),
        class("RTITextOperations"),
    ];

    encode(objects)
}

/// Wrap an `$objects` array in the shared `$version`/`$archiver`/`$top` envelope and serialise.
///
/// Writing a binary plist to an in-memory `Vec` cannot fail — the only error paths in
/// [`plist::Value::to_writer_binary`] are I/O failures on the writer and value kinds that do not
/// exist in these two fixed graphs — so the `Result` is discarded rather than propagated, and an
/// empty payload would be caught immediately by the round-trip tests either way.
fn encode(objects: Vec<Value>) -> Vec<u8> {
    let archive = dictionary([
        ("$version", Value::Integer(ARCHIVE_VERSION.into())),
        ("$archiver", Value::String(ARCHIVER.to_owned())),
        (
            "$top",
            dictionary([("textOperations", Value::Uid(Uid::new(1)))]),
        ),
        ("$objects", Value::Array(objects)),
    ]);

    let mut buffer = Vec::new();
    if let Err(error) = archive.to_writer_binary(&mut buffer) {
        tracing::error!(%error, "could not encode an RTI payload");
        return Vec::new();
    }
    buffer
}

/// One `$objects` entry describing a class: `{"$classname": name, "$classes": [name, "NSObject"]}`.
fn class(name: &str) -> Value {
    dictionary([
        ("$classname", Value::String(name.to_owned())),
        (
            "$classes",
            Value::Array(vec![
                Value::String(name.to_owned()),
                Value::String("NSObject".to_owned()),
            ]),
        ),
    ])
}

/// Build a dictionary that keeps the order it was written in.
fn dictionary<const N: usize>(entries: [(&str, Value); N]) -> Value {
    let mut dictionary = Dictionary::new();
    for (key, value) in entries {
        dictionary.insert(key.to_owned(), value);
    }
    Value::Dictionary(dictionary)
}

#[cfg(test)]
mod tests {
    use super::{rti_clear_text_payload, rti_input_text_payload};
    use plist::Value;

    fn parse(payload: &[u8]) -> plist::Dictionary {
        Value::from_reader(std::io::Cursor::new(payload))
            .expect("the encoder must emit a valid binary plist")
            .into_dictionary()
            .expect("the archive envelope is a dictionary")
    }

    #[test]
    fn the_envelope_uses_rtis_archiver_name_not_the_generic_one() {
        for payload in [
            rti_clear_text_payload(b"0123456789abcdef"),
            rti_input_text_payload(b"0123456789abcdef", "x"),
        ] {
            let archive = parse(&payload);
            assert_eq!(
                archive.get("$archiver").and_then(Value::as_string),
                Some("RTIKeyedArchiver")
            );
            assert_eq!(
                archive.get("$version").and_then(Value::as_signed_integer),
                Some(100_000)
            );
        }
    }

    /// Object counts and the differing slot layout, straight from §6.
    #[test]
    fn the_two_shapes_have_upstreams_object_graphs() {
        let clear = parse(&rti_clear_text_payload(b"0123456789abcdef"));
        let objects = clear
            .get("$objects")
            .and_then(Value::as_array)
            .expect("$objects is an array");
        assert_eq!(objects.len(), 8);
        // Slot 4 is the empty `textToAssert` string that only the clear shape carries.
        assert_eq!(objects[4].as_string(), Some(""));

        let insert = parse(&rti_input_text_payload(b"0123456789abcdef", "hello"));
        let objects = insert
            .get("$objects")
            .and_then(Value::as_array)
            .expect("$objects is an array");
        assert_eq!(objects.len(), 8);
        // Slot 3 is the insertion text; there is no `textToAssert` anywhere.
        assert_eq!(objects[3].as_string(), Some("hello"));
    }

    #[test]
    fn the_binary_plist_starts_with_the_bplist_magic() {
        let payload = rti_clear_text_payload(b"0123456789abcdef");
        assert_eq!(&payload[..8], b"bplist00");
    }
}
