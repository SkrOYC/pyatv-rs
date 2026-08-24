//! Reading properties out of an `NSKeyedArchiver` binary plist.
//!
//! Port of `pyatv/protocols/companion/keyed_archiver.py` (28 lines, reproduced in full in
//! `docs/research/companion-port-spec.md` §5). It is deliberately **not** a general unarchiver:
//! upstream's own docstring says so, and this port keeps the same scope — parse the plist as an
//! ordinary binary plist, then walk a caller-supplied list of dictionary keys from `$top`,
//! dereferencing any `UID` it meets through the flat `$objects` array.
//!
//! The reader is used in both directions. The client decodes its own `_tiStart` response with it
//! (`api.py:423-427`) and pyatv's fake device decodes the client's `_tiC` event with the very same
//! function (`tests/fake_device/companion.py:534-546`), so it is kept public rather than tucked
//! behind the text-input module.
//!
//! Failures are **per path**: a missing key or an out-of-range UID yields `None` for that path and
//! leaves the others untouched, matching upstream's `except (IndexError, KeyError)` inside the
//! per-path loop.

use plist::Value;

use crate::{Error, Result};

/// Read one or more property paths out of an `NSKeyedArchiver`-shaped binary plist.
///
/// Each element of `paths` is a sequence of dictionary keys walked from `$top`. The returned
/// vector has one entry per path, in the same order.
///
/// # Errors
///
/// Returns [`Error::Envelope`] only when `archive` is not a plist at all, or when it has no
/// `$objects` array — both of which mean the device sent something that is not an archive, rather
/// than an archive missing one of the requested properties.
pub fn read_archive_properties(archive: &[u8], paths: &[&[&str]]) -> Result<Vec<Option<Value>>> {
    let document = Value::from_reader(std::io::Cursor::new(archive))
        .map_err(|error| Error::Envelope(format!("could not parse a keyed archive: {error}")))?;

    let root = document
        .as_dictionary()
        .ok_or_else(|| Error::Envelope("a keyed archive must be a dictionary".to_owned()))?;

    let objects = root
        .get("$objects")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Envelope("a keyed archive must have $objects".to_owned()))?;

    let top = root.get("$top");

    Ok(paths
        .iter()
        .map(|path| follow(top, path, objects))
        .collect())
}

/// Walk one path from `$top`, dereferencing every `UID` on the way.
///
/// Mirrors upstream's inner loop exactly, including the order of operations: index by the key
/// **first**, then dereference if the result is a UID. Doing it the other way round would follow
/// one reference too many on the last segment and return the pointed-at object instead of the
/// value.
fn follow(top: Option<&Value>, path: &[&str], objects: &[Value]) -> Option<Value> {
    let mut element = top?.clone();

    for key in path {
        element = element.as_dictionary()?.get(key)?.clone();
        if let Some(uid) = element.as_uid() {
            let index = usize::try_from(uid.get()).ok()?;
            element = objects.get(index)?.clone();
        }
    }

    Some(element)
}

/// Read a path expected to hold raw bytes, e.g. `NS.uuidbytes`.
#[must_use]
pub fn as_data(value: Option<&Value>) -> Option<&[u8]> {
    value?.as_data()
}

/// Read a path expected to hold a string, e.g. `contextBeforeInput`.
#[must_use]
pub fn as_string(value: Option<&Value>) -> Option<&str> {
    value?.as_string()
}

#[cfg(test)]
mod tests {
    use super::{as_data, as_string, read_archive_properties};
    use crate::plist_payloads::{rti_clear_text_payload, rti_input_text_payload};

    /// The exact three-path read the fake device performs on an inbound `_tiC`
    /// (`tests/fake_device/companion.py:534-546`), run against this port's own encoder. If the two
    /// halves disagree the round trip fails here rather than on a device.
    #[test]
    fn a_clear_text_payload_round_trips_through_the_reader() {
        let payload = rti_clear_text_payload(b"0123456789abcdef");
        let read = read_archive_properties(
            &payload,
            &[
                &["textOperations", "targetSessionUUID", "NS.uuidbytes"],
                &["textOperations", "textToAssert"],
                &["textOperations", "keyboardOutput", "insertionText"],
            ],
        )
        .expect("the payload this crate wrote must parse");

        assert_eq!(
            as_data(read[0].as_ref()),
            Some(b"0123456789abcdef".as_ref())
        );
        assert_eq!(as_string(read[1].as_ref()), Some(""));
        // "clear" carries no insertion text at all; the path must fail softly, not error.
        assert!(read[2].is_none());
    }

    #[test]
    fn an_input_text_payload_round_trips_through_the_reader() {
        let payload = rti_input_text_payload(b"0123456789abcdef", "hello");
        let read = read_archive_properties(
            &payload,
            &[
                &["textOperations", "targetSessionUUID", "NS.uuidbytes"],
                &["textOperations", "textToAssert"],
                &["textOperations", "keyboardOutput", "insertionText"],
            ],
        )
        .expect("the payload this crate wrote must parse");

        assert_eq!(
            as_data(read[0].as_ref()),
            Some(b"0123456789abcdef".as_ref())
        );
        // `textToAssert` is absent for the insert shape, not an empty string (§6).
        assert!(read[1].is_none());
        assert_eq!(as_string(read[2].as_ref()), Some("hello"));
    }

    #[test]
    fn a_non_plist_is_refused() {
        assert!(read_archive_properties(b"not a plist", &[&["x"]]).is_err());
    }
}
