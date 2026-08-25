//! End-to-end tests: the real binary, a hermetic device, no network.
//!
//! These are the CLI equivalent of pyatv's own smoke test (`tests/scripts/test_atvremote.py`),
//! which runs its scripts against fake devices and asserts on the exact strings they print. The
//! assertions here are deliberately about *output*, not about internals: what a user or a
//! supervising process sees is the contract this binary has.
//!
//! See [`support`] for why every invocation uses `--manual`.

mod support;

use support::{DEVICE_IDENTIFIER, DEVICE_PIN, Harness};

// ---------------------------------------------------------------------------
// Apps
// ---------------------------------------------------------------------------

/// `App.__str__` is `f"App: {name} ({identifier})"` (`pyatv/interface.py:721-723`), joined with
/// `", "` by `_pretty_print` (`atvremote.py:987-988`).
#[tokio::test]
async fn app_list_prints_pyatvs_joined_form() {
    let harness = Harness::start().await;
    harness
        .arrange(|state| {
            state.installed_apps = vec![
                ("com.apple.TVMusic".to_owned(), "Music".to_owned()),
                ("com.netflix.Netflix".to_owned(), "Netflix".to_owned()),
            ];
        })
        .await;

    let run = harness.run(&["app_list"]).await;
    run.expect_success().assert_contains(&[
        "App: Music (com.apple.TVMusic)",
        "App: Netflix (com.netflix.Netflix)",
    ]);
    assert!(
        run.stdout.contains(", "),
        "the entries must be comma-joined: {:?}",
        run.stdout
    );
}

#[tokio::test]
async fn app_list_json_is_a_list_of_name_identifier_objects() {
    let harness = Harness::start().await;
    harness
        .arrange(|state| {
            state.installed_apps = vec![("com.apple.TVMusic".to_owned(), "Music".to_owned())];
        })
        .await;

    let value = harness
        .run(&["--json", "app_list"])
        .await
        .expect_success()
        .json();

    assert_eq!(value["result"], "success");
    assert_eq!(value["app_list"][0]["name"], "Music");
    assert_eq!(value["app_list"][0]["identifier"], "com.apple.TVMusic");
}

#[tokio::test]
async fn launch_app_reaches_the_device_and_prints_nothing() {
    let harness = Harness::start().await;

    let run = harness.run(&["launch_app", "com.netflix.Netflix"]).await;
    run.expect_success();
    assert!(
        run.stdout.is_empty(),
        "a void command prints nothing: {:?}",
        run.stdout
    );

    let active = harness.inspect(|state| state.active_app.clone()).await;
    assert_eq!(active.as_deref(), Some("com.netflix.Netflix"));
}

// ---------------------------------------------------------------------------
// User accounts
// ---------------------------------------------------------------------------

/// `UserAccount.__str__` is `f"Account: {name} ({identifier})"` (`pyatv/interface.py:764-766`).
#[tokio::test]
async fn account_list_prints_pyatvs_joined_form() {
    let harness = Harness::start().await;
    harness
        .arrange(|state| {
            state.available_accounts = vec![("id-1".to_owned(), "Alice".to_owned())];
        })
        .await;

    harness
        .run(&["account_list"])
        .await
        .expect_success()
        .assert_contains(&["Account: Alice (id-1)"]);
}

#[tokio::test]
async fn switch_account_reaches_the_device() {
    let harness = Harness::start().await;
    harness
        .arrange(|state| {
            state.available_accounts = vec![("id-1".to_owned(), "Alice".to_owned())];
        })
        .await;

    harness
        .run(&["switch_account", "id-1"])
        .await
        .expect_success();
    assert_eq!(
        harness.inspect(|state| state.active_account.clone()).await,
        Some("id-1".to_owned())
    );
}

// ---------------------------------------------------------------------------
// Power
// ---------------------------------------------------------------------------

/// Python prints an enum member as `PowerState.On`; the JSON arm lowercases the member name
/// (`atvscript.py:79`).
#[tokio::test]
async fn power_state_renders_as_python_prints_the_enum() {
    let harness = Harness::start().await;
    harness.arrange(|state| state.powered_on = true).await;

    let run = harness.run(&["power_state"]).await;
    run.expect_success();
    assert_eq!(run.stdout.trim(), "PowerState.On");

    let value = harness
        .run(&["--json", "power_state"])
        .await
        .expect_success()
        .json();
    assert_eq!(value["power_state"], "on");
}

// ---------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_button_press_reaches_the_device() {
    let harness = Harness::start().await;

    let run = harness.run(&["remote", "menu"]).await;
    run.expect_success();
    assert!(
        run.stdout.is_empty(),
        "a button prints nothing: {:?}",
        run.stdout
    );

    assert!(
        harness.inspect(|state| state.latest_button.is_some()).await,
        "the device must have seen a button"
    );
}

/// `atvscript menu` answers `{"command": "menu"}` (`atvscript.py:332-334`).
#[tokio::test]
async fn a_button_press_echoes_its_name_in_json() {
    let harness = Harness::start().await;

    let value = harness
        .run(&["--json", "remote", "menu"])
        .await
        .expect_success()
        .json();

    assert_eq!(value["result"], "success");
    assert_eq!(value["command"], "menu");
}

/// Upstream's `button=arg` spelling has to keep working (`atvremote.py:836-846`).
#[tokio::test]
async fn a_button_accepts_upstreams_equals_form() {
    let harness = Harness::start().await;

    let value = harness
        .run(&["--json", "remote", "up=1"])
        .await
        .expect_success()
        .json();
    assert_eq!(value["command"], "up");
}

/// `_LOGGER.error("Unknown command: %s", cmd)` then `return 1` (`atvremote.py:950-951`).
#[tokio::test]
async fn an_unknown_button_fails_with_exit_code_one() {
    let harness = Harness::start().await;

    let run = harness.run(&["remote", "nonsense"]).await;
    run.expect_failure();
    assert!(
        run.stderr.contains("unknown command"),
        "the error must name the problem: {:?}",
        run.stderr
    );
}

// ---------------------------------------------------------------------------
// Keyboard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keyboard_text_round_trips_through_the_cli() {
    let harness = Harness::start().await;
    harness
        .arrange(|state| state.rti_text = Some(String::new()))
        .await;

    harness.run(&["text_set", "hello"]).await.expect_success();

    let run = harness.run(&["text_get"]).await;
    run.expect_success();
    assert_eq!(run.stdout.trim(), "hello");

    harness
        .run(&["text_append", " world"])
        .await
        .expect_success();
    let value = harness
        .run(&["--json", "text_get"])
        .await
        .expect_success()
        .json();
    assert_eq!(value["text"], "hello world");

    harness.run(&["text_clear"]).await.expect_success();
    let value = harness
        .run(&["--json", "text_get"])
        .await
        .expect_success()
        .json();
    assert_eq!(value["text"], "");
}

#[tokio::test]
async fn text_focus_state_renders_as_python_prints_the_enum() {
    let harness = Harness::start().await;
    harness
        .arrange(|state| state.rti_text = Some("x".to_owned()))
        .await;

    let run = harness.run(&["text_focus_state"]).await;
    run.expect_success();
    assert!(
        run.stdout.trim().starts_with("KeyboardFocusState."),
        "the enum must print Python-style: {:?}",
        run.stdout
    );

    let value = harness
        .run(&["--json", "text_focus_state"])
        .await
        .expect_success()
        .json();
    assert!(
        ["unknown", "focused", "unfocused"].contains(&value["focus_state"].as_str().unwrap_or("")),
        "focus_state must be a lowercased member name: {value}"
    );
}

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

/// `print(float)` always shows a decimal point, which Rust's `Display` does not
/// (`report::float`).
#[tokio::test]
async fn volume_prints_with_pythons_trailing_decimal() {
    let harness = Harness::start().await;
    harness.arrange(|state| state.volume = 20.0).await;

    let run = harness.run(&["volume"]).await;
    run.expect_success();
    assert!(
        run.stdout.trim().contains('.'),
        "a float must keep its decimal point: {:?}",
        run.stdout
    );

    let value = harness
        .run(&["--json", "volume"])
        .await
        .expect_success()
        .json();
    assert!(value["volume"].is_number(), "{value}");
}

#[tokio::test]
async fn set_volume_reaches_the_device() {
    let harness = Harness::start().await;

    harness.run(&["set_volume", "42"]).await.expect_success();
    let volume = harness.inspect(|state| state.volume).await;
    assert!((volume - 42.0).abs() < 1.0, "volume was {volume}");
}

// ---------------------------------------------------------------------------
// Device facts and features
// ---------------------------------------------------------------------------

/// `print("Model/SW:", devinfo)` / `print("     MAC:", devinfo.mac)`
/// (`atvremote.py:436-441`).
#[tokio::test]
async fn device_info_keeps_upstreams_two_line_shape() {
    let harness = Harness::start().await;

    let run = harness.run(&["device_info"]).await;
    run.expect_success()
        .assert_contains(&["Model/SW:", "     MAC:"]);
}

#[tokio::test]
async fn device_info_json_carries_the_scan_sub_object() {
    let harness = Harness::start().await;

    let value = harness
        .run(&["--json", "device_info"])
        .await
        .expect_success()
        .json();

    let info = &value["device_info"];
    for key in ["mac", "model", "model_str", "operating_system", "version"] {
        assert!(info.get(key).is_some(), "{key} is missing from {info}");
    }
}

/// The list and its legend (`atvremote.py:443-465`).
#[tokio::test]
async fn features_prints_the_list_and_the_legend() {
    let harness = Harness::start().await;

    harness
        .run(&["features"])
        .await
        .expect_success()
        .assert_contains(&[
            "Feature list:",
            "-------------",
            "Legend:",
            "Available: Supported by device and usable now",
            "Unsupported: Not supported by this device (or by pyatv)",
        ]);
}

/// `features=all` includes the unsupported ones (`atvremote.py:445-448`), so the list must grow.
#[tokio::test]
async fn features_all_lists_more_than_features_alone() {
    let harness = Harness::start().await;

    let some = harness
        .run(&["--json", "features"])
        .await
        .expect_success()
        .json();
    let all = harness
        .run(&["--json", "features", "--all"])
        .await
        .expect_success()
        .json();

    let count = |value: &serde_json::Value| {
        value["features"]
            .as_object()
            .map(serde_json::Map::len)
            .unwrap_or_default()
    };
    assert!(
        count(&all) > count(&some),
        "--all must add the unsupported features: {} vs {}",
        count(&all),
        count(&some)
    );
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// Every key `output_playing` emits, present even on an idle device
/// (`atvscript.py:210-226`).
#[tokio::test]
async fn playing_json_carries_every_documented_key() {
    let harness = Harness::start().await;

    let run = harness.run(&["--json", "playing"]).await;
    // Companion serves no metadata, so this is the *unsupported* path — and it must still be one
    // parseable JSON object, which is the whole point of the mode.
    let value = run.json();
    assert!(
        value["result"] == "success" || value["result"] == "failure",
        "{value}"
    );

    if value["result"] == "success" {
        for key in [
            "media_type",
            "device_state",
            "title",
            "artist",
            "album",
            "genre",
            "total_time",
            "position",
            "shuffle",
            "repeat",
            "hash",
            "app",
            "app_id",
        ] {
            assert!(value.get(key).is_some(), "{key} is missing from {value}");
        }
    } else {
        assert_eq!(value["error"], "unsupported_command");
    }
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

/// `--pin` makes pairing non-interactive (`atvremote.py:617-625`); the two success lines are
/// upstream's, verbatim (`atvremote.py:230-238`).
#[tokio::test]
async fn pair_with_a_supplied_pin_succeeds_without_a_prompt() {
    let harness = Harness::unpaired().await;

    let mut args = harness.address_flags();
    args.extend([
        "--pin".to_owned(),
        DEVICE_PIN.to_string(),
        "pair".to_owned(),
    ]);

    let run = support::run_binary(&args, None).await;
    run.expect_success().assert_contains(&[
        "Pairing seems to have succeeded, yey!",
        "You may now use these credentials:",
    ]);

    assert!(
        harness.inspect(|state| state.has_paired).await,
        "the device must have completed pair-setup"
    );
}

#[tokio::test]
async fn pair_reads_the_pin_from_stdin_when_none_was_supplied() {
    let harness = Harness::unpaired().await;

    let mut args = harness.address_flags();
    args.push("pair".to_owned());

    let run = support::run_binary(&args, Some(format!("{DEVICE_PIN}\n"))).await;
    run.expect_success()
        .assert_contains(&["Pairing seems to have succeeded, yey!"]);
    assert!(
        run.stderr.contains("Enter PIN on screen:"),
        "the prompt goes to stderr so a redirected stdout stays clean: {:?}",
        run.stderr
    );
}

// ---------------------------------------------------------------------------
// The `cli` REPL
// ---------------------------------------------------------------------------

/// `DeviceCommands.cli` (`atvremote.py:392-408`): the two opening lines, one connection, and
/// `exit` to leave.
#[tokio::test]
async fn the_repl_runs_several_commands_over_one_connection() {
    let harness = Harness::start().await;
    harness
        .arrange(|state| {
            state.installed_apps = vec![("com.apple.TVMusic".to_owned(), "Music".to_owned())];
            state.powered_on = true;
        })
        .await;

    let run = harness
        .run_with_input(&["cli"], "app_list\npower_state\nexit\n")
        .await;

    run.expect_success()
        .assert_contains(&["App: Music (com.apple.TVMusic)", "PowerState.On"]);
    assert!(
        run.stdout.contains("Enter commands and press enter"),
        "the opening lines are upstream's: {:?}",
        run.stdout
    );
}

/// `if command == "cli": print("Command not available here")` (`atvremote.py:402-404`).
#[tokio::test]
async fn the_repl_refuses_to_re_enter_itself() {
    let harness = Harness::start().await;

    let run = harness.run_with_input(&["cli"], "cli\nexit\n").await;
    run.expect_success()
        .assert_contains(&["Command not available here"]);
}

/// A bad line must not end the session.
#[tokio::test]
async fn the_repl_survives_an_unknown_command() {
    let harness = Harness::start().await;
    harness.arrange(|state| state.powered_on = true).await;

    let run = harness
        .run_with_input(&["cli"], "nonsense\npower_state\nexit\n")
        .await;
    run.expect_success().assert_contains(&["PowerState.On"]);
}

/// End of input ends the loop, so the REPL is pipeable.
#[tokio::test]
async fn the_repl_stops_at_end_of_input() {
    let harness = Harness::start().await;
    harness.arrange(|state| state.powered_on = true).await;

    harness
        .run_with_input(&["cli"], "power_state\n")
        .await
        .expect_success()
        .assert_contains(&["PowerState.On"]);
}

// ---------------------------------------------------------------------------
// Failure paths
// ---------------------------------------------------------------------------

/// A failure under `--json` must still be one parseable line, with `result: failure` — that is
/// what a supervising process reads (`atvscript.py:416-417`).
#[tokio::test]
async fn a_failure_is_still_one_json_object() {
    // Port 1 is not listening, so the connection cannot succeed.
    let args: Vec<String> = [
        "--manual",
        "--address",
        "127.0.0.1",
        "--port",
        "1",
        "--protocol",
        "companion",
        "--id",
        DEVICE_IDENTIFIER,
        "--storage",
        "none",
        "--json",
        "playing",
    ]
    .iter()
    .map(|flag| (*flag).to_owned())
    .collect();

    let run = support::run_binary(&args, None).await;
    run.expect_failure();

    let value = run.json();
    assert_eq!(value["result"], "failure");
    assert!(value.get("exception").is_some(), "{value}");
    assert!(
        value["datetime"]
            .as_str()
            .is_some_and(|it| it.contains('T')),
        "even a failure carries a timestamp: {value}"
    );
}

/// `--manual` without its three required flags is refused before anything is dialled
/// (`atvremote.py:729-731`).
#[tokio::test]
async fn manual_mode_without_a_port_is_refused() {
    let args: Vec<String> = [
        "--manual",
        "--address",
        "127.0.0.1",
        "--protocol",
        "companion",
        "--id",
        "abc",
        "playing",
    ]
    .iter()
    .map(|flag| (*flag).to_owned())
    .collect();

    let run = support::run_binary(&args, None).await;
    run.expect_failure();
    assert!(
        run.stderr.contains("--port"),
        "the error must name what is missing: {:?}",
        run.stderr
    );
}

// ---------------------------------------------------------------------------
// Commands that need no device
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_commands_listing_needs_no_device() {
    let run = support::run_binary(&["commands".to_owned()], None).await;

    run.expect_success()
        .assert_contains(&["set_position", "volume_up", "swipe"]);
}

#[tokio::test]
async fn the_commands_listing_has_a_json_form() {
    let args = ["--json".to_owned(), "commands".to_owned()];
    let value = support::run_binary(&args, None)
        .await
        .expect_success()
        .json();

    let names: Vec<&str> = value["commands"]
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(names.iter().any(|name| name.starts_with("set_position")));
}

// ---------------------------------------------------------------------------
// delay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delay_waits_and_acknowledges() {
    let harness = Harness::start().await;

    let started = std::time::Instant::now();
    let value = harness
        .run(&["--json", "delay", "150"])
        .await
        .expect_success()
        .json();

    assert_eq!(value["command"], "delay");
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(150),
        "delay must actually wait"
    );
}
