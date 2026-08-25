//! USB HID usages and the opaque 60-byte `hidEventData` payload.
//!
//! Ported from `messages.send_hid_event` (`pyatv/protocols/mrp/messages.py:112-138`) and
//! `_KEY_LOOKUP` (`pyatv/protocols/mrp/__init__.py:78-96`).
//!
//! # Why the payload is a literal
//!
//! Only six of the sixty bytes carry information. The rest is a fixed blob pyatv's own author
//! never decoded, including the leading eight bytes his comment calls "mach `AbsoluteTime` which is
//! tricky to generate. The device does not seem to care much about the value though, so hardcode
//! something here." That empirical finding is the only evidence anyone has; a port that computes a
//! real timestamp here would be guessing where upstream measured. Reproduce it byte for byte.

use pyatv_core::consts::InputAction;

/// A USB HID usage page and usage, i.e. one button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    /// USB HID usage page.
    pub usage_page: u16,
    /// USB HID usage within that page.
    pub usage: u16,
}

impl Key {
    /// Declare a key.
    const fn new(usage_page: u16, usage: u16) -> Self {
        Self { usage_page, usage }
    }
}

/// Move the selection up.
pub const UP: Key = Key::new(1, 0x8C);
/// Move the selection down.
pub const DOWN: Key = Key::new(1, 0x8D);
/// Move the selection left.
pub const LEFT: Key = Key::new(1, 0x8B);
/// Move the selection right.
pub const RIGHT: Key = Key::new(1, 0x8A);
/// Stop playback. Declared upstream but unreachable: `RemoteControl.stop` uses `SEND_COMMAND`.
pub const STOP: Key = Key::new(12, 0xB7);
/// Next track. As [`STOP`], unreachable through the facade.
pub const NEXT: Key = Key::new(12, 0xB5);
/// Previous track. As [`STOP`], unreachable through the facade.
pub const PREVIOUS: Key = Key::new(12, 0xB6);
/// Activate the selected item.
pub const SELECT: Key = Key::new(1, 0x89);
/// Go back one level.
pub const MENU: Key = Key::new(1, 0x86);
/// Go to the top-level menu.
pub const TOP_MENU: Key = Key::new(12, 0x60);
/// Go to the home screen.
pub const HOME: Key = Key::new(12, 0x40);
/// Suspend the device.
pub const SUSPEND: Key = Key::new(1, 0x82);
/// Wake the device.
pub const WAKEUP: Key = Key::new(1, 0x83);
/// Step the volume up.
pub const VOLUME_UP: Key = Key::new(12, 0xE9);
/// Step the volume down.
pub const VOLUME_DOWN: Key = Key::new(12, 0xEA);

/// `_KEY_LOOKUP` in upstream's own order, for tests and diagnostics.
///
/// The commented-out `'mic': (12, 0x04)` Siri entry is omitted: it is dead upstream too.
pub const ALL: [(&str, Key); 15] = [
    ("up", UP),
    ("down", DOWN),
    ("left", LEFT),
    ("right", RIGHT),
    ("stop", STOP),
    ("next", NEXT),
    ("previous", PREVIOUS),
    ("select", SELECT),
    ("menu", MENU),
    ("topmenu", TOP_MENU),
    ("home", HOME),
    ("suspend", SUSPEND),
    ("wakeup", WAKEUP),
    ("volume_up", VOLUME_UP),
    ("volume_down", VOLUME_DOWN),
];

/// Length of every `hidEventData` payload pyatv sends: `8 + 35 + 6 + 11`.
pub const EVENT_DATA_LEN: usize = 60;

/// Byte offset of the `usagePage`/`usage`/`down` triple inside the payload.
///
/// The fake device slices `hidEventData[43:49]` to recover it (`tests/fake_device/mrp.py:501`).
pub const KEY_OFFSET: usize = 43;

/// The eight-byte pseudo-timestamp prefix (`messages.py:120`).
const ABSTIME: [u8; 8] = [0x43, 0x89, 0x22, 0xCF, 0x08, 0x02, 0x00, 0x00];

/// The 35 undecoded bytes between the timestamp and the key triple (`messages.py:130-133`).
const PREAMBLE: [u8; 35] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];

/// The 11 undecoded trailing bytes (`messages.py:135`).
const TRAILER: [u8; 11] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];

/// Build the `hidEventData` payload for one press or release.
///
/// Layout: `ABSTIME (8) ‖ PREAMBLE (35) ‖ usage_page:u16be ‖ usage:u16be ‖ down:u16be ‖ TRAILER
/// (11)`. The down flag is a **two-byte** big-endian `1` or `0`, not a single byte.
#[must_use]
pub fn event_data(usage_page: u16, usage: u16, down: bool) -> [u8; EVENT_DATA_LEN] {
    let mut data = [0u8; EVENT_DATA_LEN];
    data[..8].copy_from_slice(&ABSTIME);
    data[8..KEY_OFFSET].copy_from_slice(&PREAMBLE);
    data[KEY_OFFSET..KEY_OFFSET + 2].copy_from_slice(&usage_page.to_be_bytes());
    data[KEY_OFFSET + 2..KEY_OFFSET + 4].copy_from_slice(&usage.to_be_bytes());
    data[KEY_OFFSET + 4..KEY_OFFSET + 6].copy_from_slice(&u16::from(down).to_be_bytes());
    data[KEY_OFFSET + 6..].copy_from_slice(&TRAILER);
    data
}

/// How many press/release pairs an [`InputAction`] sends, and whether the press is held.
///
/// `_send_hid_key` (`__init__.py:296-324`): `SingleTap` is one pair, `DoubleTap` is two
/// back-to-back pairs, `Hold` is one pair with a hardcoded one-second gap.
#[must_use]
pub const fn presses_for(action: InputAction) -> (usize, bool) {
    match action {
        InputAction::SingleTap => (1, false),
        InputAction::DoubleTap => (2, false),
        InputAction::Hold => (1, true),
    }
}

#[cfg(test)]
mod tests {
    use super::{ALL, EVENT_DATA_LEN, KEY_OFFSET, LEFT, event_data, presses_for};
    use pyatv_core::consts::InputAction;

    /// The whole payload, hex-for-hex against `messages.py:120-136` with `use_page=1, usage=0x8B,
    /// down=True` — the exact example the `.proto` comment gives.
    #[test]
    fn the_payload_matches_upstreams_own_worked_example() {
        let expected = concat!(
            "438922cf08020000",
            "0000000000000000010000000000000002000000200000000300000001000000000000",
            "0001008b0001",
            "0000000000000001000000",
        );

        assert_eq!(hex::encode(event_data(1, 0x8B, true)), expected);
        assert_eq!(event_data(1, 0x8B, true).len(), EVENT_DATA_LEN);
    }

    /// A release differs from a press in exactly two bytes.
    #[test]
    fn press_and_release_differ_only_in_the_down_flag() {
        let press = event_data(LEFT.usage_page, LEFT.usage, true);
        let release = event_data(LEFT.usage_page, LEFT.usage, false);

        let differing: Vec<usize> = (0..EVENT_DATA_LEN)
            .filter(|&index| press[index] != release[index])
            .collect();
        assert_eq!(differing, vec![KEY_OFFSET + 5]);
    }

    #[test]
    fn every_key_is_distinct() {
        let mut seen: Vec<_> = ALL.iter().map(|(_, key)| *key).collect();
        let count = seen.len();
        seen.sort_by_key(|key| (key.usage_page, key.usage));
        seen.dedup();
        assert_eq!(seen.len(), count);
    }

    #[test]
    fn input_actions_map_to_upstreams_press_counts() {
        assert_eq!(presses_for(InputAction::SingleTap), (1, false));
        assert_eq!(presses_for(InputAction::DoubleTap), (2, false));
        assert_eq!(presses_for(InputAction::Hold), (1, true));
    }
}
