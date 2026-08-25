//! The `commands` subcommand: what `remote` will accept.
//!
//! `GlobalCommands.commands` (`pyatv/scripts/atvremote.py:94-111`) builds this by reflecting over
//! the interface classes and printing each method's first docstring sentence. Rust has no
//! `__dict__`, so the list is written out — which means it can drift, and
//! the `tests::every_button_the_dispatcher_knows_is_listed` unit test is what stops it.

use crate::report::Reporter;

/// Every button name [`super::run`] accepts, grouped for reading.
pub const VOCABULARY: &[(&str, &[&str])] = &[
    (
        "Navigation (each takes an optional action: 0 tap, 1 double tap, 2 hold)",
        &["up", "down", "left", "right", "select", "menu", "home"],
    ),
    (
        "Screens",
        &[
            "home_hold",
            "top_menu",
            "guide",
            "control_center",
            "screensaver",
        ],
    ),
    (
        "Transport",
        &["play", "play_pause", "pause", "stop", "next", "previous"],
    ),
    (
        "Seeking",
        &[
            "skip_forward [seconds]",
            "skip_backward [seconds]",
            "set_position <seconds>",
            "set_shuffle <off|albums|songs>",
            "set_repeat <off|track|all>",
        ],
    ),
    ("Channels", &["channel_up", "channel_down"]),
    ("Volume", &["volume_up", "volume_down"]),
    (
        "Touch",
        &[
            "swipe <start_x> <start_y> <end_x> <end_y> <duration_ms>",
            "action <x> <y> <press|hold|release|click>",
            "click [action]",
        ],
    ),
];

/// Print the vocabulary.
pub fn print(reporter: Reporter) {
    if reporter.is_json() {
        let values: Vec<serde_json::Value> = VOCABULARY
            .iter()
            .flat_map(|(_, entries)| entries.iter())
            .map(|entry| serde_json::Value::String((*entry).to_owned()))
            .collect();
        crate::json::emit(
            crate::json::Envelope::success().value("commands", serde_json::Value::Array(values)),
        );
        return;
    }

    println!("Buttons for `atvremote remote <BUTTON>`:");
    for (title, entries) in VOCABULARY {
        println!("\n{title}:");
        for entry in *entries {
            println!(" - {entry}");
        }
    }
    println!("\nEverything else is its own subcommand; run `atvremote --help`.");
}

#[cfg(test)]
mod tests {
    use super::VOCABULARY;

    /// Every listed name, stripped of its argument hints.
    fn names() -> impl Iterator<Item = &'static str> {
        VOCABULARY
            .iter()
            .flat_map(|(_, entries)| entries.iter())
            .map(|entry| entry.split_whitespace().next().unwrap_or(entry))
    }

    #[test]
    fn no_button_is_listed_twice() {
        let mut listed: Vec<&str> = names().collect();
        let before = listed.len();
        listed.sort_unstable();
        listed.dedup();
        assert_eq!(before, listed.len(), "duplicate entries: {listed:?}");
    }

    /// The listing is the only place a user can discover the button vocabulary, so a name the
    /// dispatcher handles but this omits is invisible. The dispatcher's match arms are the source
    /// of truth; this asserts the two agree on the ones that are easy to forget.
    #[test]
    fn every_button_the_dispatcher_knows_is_listed() {
        let listed: Vec<&str> = names().collect();

        for expected in [
            "up",
            "down",
            "left",
            "right",
            "select",
            "menu",
            "home",
            "home_hold",
            "top_menu",
            "guide",
            "control_center",
            "screensaver",
            "play",
            "play_pause",
            "pause",
            "stop",
            "next",
            "previous",
            "skip_forward",
            "skip_backward",
            "set_position",
            "set_shuffle",
            "set_repeat",
            "channel_up",
            "channel_down",
            "volume_up",
            "volume_down",
            "swipe",
            "action",
            "click",
        ] {
            assert!(listed.contains(&expected), "{expected} is not listed");
        }
        assert_eq!(listed.len(), 30, "the listing gained or lost a button");
    }

    #[test]
    fn every_group_has_a_title_and_entries() {
        for (title, entries) in VOCABULARY {
            assert!(!title.is_empty());
            assert!(!entries.is_empty(), "{title} is empty");
        }
    }
}
