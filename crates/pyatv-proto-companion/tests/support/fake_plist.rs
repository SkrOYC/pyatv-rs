//! The RTI archive the reference device answers `_tiStart` with.
//!
//! Port of `FakeCompanionState.rti_encoded_data` (`tests/fake_device/companion.py:158-190`). The
//! three-level nesting is not decoration: the client reads
//! `["documentState", "docSt", "contextBeforeInput"]`, and each segment of that path exists because
//! this graph has one wrapper object contributing it (`docs/research/companion-port-spec.md` §5).
//! Flattening it would make the fixture answer a path the real device does not.
//!
//! Written by hand here rather than reusing `pyatv_proto_companion::plist_payloads`, for the same
//! reason the fake device re-derives the frame header: a fixture that shares an implementation with
//! the code under test cannot catch a bug in it. These are the *device's* payloads; those are the
//! client's, and they are different shapes.

use plist::{Dictionary, Uid, Value};

/// The `_tiD` payload for a focused text session holding `text`.
#[must_use]
pub fn rti_session(session_uuid: &[u8], text: &str) -> Vec<u8> {
    let archive = dictionary([
        (
            "$top",
            dictionary([
                ("sessionUUID", Value::Uid(Uid::new(1))),
                ("documentState", Value::Uid(Uid::new(2))),
            ]),
        ),
        (
            "$objects",
            Value::Array(vec![
                Value::String("$null".to_owned()),
                Value::Data(session_uuid.to_vec()),
                dictionary([("docSt", Value::Uid(Uid::new(3)))]),
                dictionary([("contextBeforeInput", Value::Uid(Uid::new(4)))]),
                Value::String(text.to_owned()),
            ]),
        ),
    ]);

    let mut buffer = Vec::new();
    archive
        .to_writer_binary(&mut buffer)
        .expect("the fixture archive must serialise");
    buffer
}

fn dictionary<const N: usize>(entries: [(&str, Value); N]) -> Value {
    let mut dictionary = Dictionary::new();
    for (key, value) in entries {
        dictionary.insert(key.to_owned(), value);
    }
    Value::Dictionary(dictionary)
}
