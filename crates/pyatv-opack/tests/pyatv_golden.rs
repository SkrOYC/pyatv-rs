//! The `_systemInfo` golden vector from pyatv's `tests/support/test_opack.py:403-440`.
//!
//! Upstream this test is `assert DeepDiff(unpacked, data, ignore_order=True)`, which asserts that
//! a diff *exists* — and one always does, because `unpacked` is the `(value, remaining)` tuple
//! `unpack()` returns while `data` is the bare dict. The assertion is inverted and vacuous. The
//! port asserts what it was clearly meant to assert: that the payload survives a pack/unpack
//! round trip, both structurally and byte for byte.

use bytes::Bytes;
use pyatv_opack::{UintWidth, Value, opack, opack_array, pack, unpack};

/// The one transformation a round trip legitimately makes: an integer at or above `0x28` is
/// written with an explicit width, so it comes back as [`Value::SizedUint`]. Everything else must
/// survive untouched.
fn as_decoded(value: &Value) -> Value {
    match value {
        Value::Uint(number) if *number >= 0x28 => Value::SizedUint {
            value: *number,
            width: UintWidth::narrowest_for(*number),
        },
        Value::Array(items) => Value::Array(items.iter().map(as_decoded).collect()),
        Value::Dict(entries) => Value::Dict(
            entries
                .iter()
                .map(|(key, entry)| (as_decoded(key), as_decoded(entry)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn system_info() -> Value {
    opack! {
        "_i" => "_systemInfo",
        "_x" => 1_254_122_577u64,
        "_btHP" => false,
        "_c" => opack! {
            "_pubID" => "AA:BB:CC:DD:EE:FF",
            "_sv" => "230.1",
            "_bf" => 0u64,
            "_siriInfo" => opack! {
                "collectorElectionVersion" => 1.0f64,
                "deviceCapabilities" => opack! {
                    "seymourEnabled" => 1u64,
                    "voiceTriggerEnabled" => 2u64,
                },
                "sharedDataProtoBuf" => Bytes::from(vec![0x08u8; 512]),
            },
            "_stA" => opack_array![
                "com.apple.LiveAudio",
                "com.apple.siri.wakeup",
                "com.apple.Seymour",
                "com.apple.announce",
                "com.apple.coreduet.sync",
                "com.apple.SeymourSession",
            ],
            "_i" => "6c62fca18b11",
            "_clFl" => 128u64,
            "_idsID" => "44E14ABC-DDDD-4188-B661-11BAAAF6ECDE",
            "_hkUID" => opack_array![Value::Uuid([
                0x17, 0xED, 0x16, 0x0A, 0x81, 0xF8, 0x44, 0x88,
                0x96, 0x2C, 0x6B, 0x1A, 0x83, 0xEB, 0x00, 0x81,
            ])],
            "_dC" => "1",
            "_sf" => 256u64,
            "model" => "iPhone10,6",
            "name" => "iPhone",
        },
        "_t" => 2u64,
    }
}

#[test]
fn golden() {
    let original = system_info();
    let packed = pack(&original).expect("the golden payload must encode");
    let (decoded, consumed) = unpack(&packed).expect("the golden payload must decode");

    assert_eq!(consumed, packed.len(), "decoder left trailing bytes");
    assert_eq!(decoded, as_decoded(&original), "structure changed");
    assert_eq!(
        pack(&decoded).expect("a decoded payload must re-encode"),
        packed,
        "re-encoding a decoded payload must be byte-for-byte identical"
    );
}

/// The golden payload uses the key `"_i"` at two nesting levels, so the second occurrence has to
/// become a back-reference. Guard the interning specifically, since a decoder that got the index
/// numbering wrong would still pass a pure round-trip check.
#[test]
fn golden_interns_the_repeated_key() {
    let packed = pack(&system_info()).expect("the golden payload must encode");

    // `_i` is a two-byte string, so its encoding is 0x42 0x5F 0x69 and it is the very first thing
    // recorded in the object table: index 0, i.e. tag 0xA0.
    let key = [0x42, 0x5F, 0x69];
    let occurrences = packed.windows(key.len()).filter(|w| *w == key).count();
    assert_eq!(occurrences, 1, "`_i` should be spelled out exactly once");
    assert!(
        packed.contains(&0xA0),
        "`_i` should recur as a 0xA0 pointer"
    );
}

/// Field access on a decoded payload, mirroring how the Companion client reads responses.
#[test]
fn golden_fields_are_reachable() {
    let packed = pack(&system_info()).expect("the golden payload must encode");
    let (decoded, _) = unpack(&packed).expect("the golden payload must decode");

    assert_eq!(
        decoded.get("_i").and_then(Value::as_str),
        Some("_systemInfo")
    );
    assert_eq!(
        decoded.get("_x").and_then(Value::as_u64),
        Some(1_254_122_577)
    );
    assert_eq!(decoded.get("_btHP").and_then(Value::as_bool), Some(false));

    let content = decoded.get("_c").expect("_c must be present");
    assert_eq!(
        content.get("_i").and_then(Value::as_str),
        Some("6c62fca18b11")
    );
    assert_eq!(content.get("_sf").and_then(Value::as_u64), Some(256));
    assert_eq!(
        content
            .get("_stA")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(6)
    );

    let siri = content.get("_siriInfo").expect("_siriInfo must be present");
    assert_eq!(
        siri.get("collectorElectionVersion").and_then(Value::as_f64),
        Some(1.0)
    );
    assert_eq!(
        siri.get("sharedDataProtoBuf")
            .and_then(Value::as_bytes)
            .map(Bytes::len),
        Some(512)
    );
}
