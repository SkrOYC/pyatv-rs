# Step 8 gap analysis — facade completion, CLI parity, hardening

Ground truth: `/tmp/pyatv-ref` at commit `b277a4c` (pyatv release 0.18.0). Rust workspace: `/mnt/empty/canvas` on `feat/airplay-mrp-tunnel`, as it stood when this was written. `crates/pyatv-proto-dmap` and `crates/pyatv-proto-airplay` are being edited concurrently by other workers — findings that touch those two crates are a snapshot, not a final verdict, and should be re-checked before acting on them.

All citations are `path:line` or `path:line-range`. Rust paths are relative to the repo root; pyatv paths are relative to `/tmp/pyatv-ref`.

---

## 1. CLI parity — `atvremote` and `atvscript`

### 1.1 Global options

| pyatv flag (`pyatv/scripts/atvremote.py:551-684`, `pyatv/scripts/__init__.py:91-113`) | atvremote-rs (`cli/atvremote/src/cli.rs:14-58`) | Status |
| --- | --- | --- |
| `command` (positional, `nargs="+"`, chained) | `#[command] pub command: Command` (one subcommand per invocation) | **Different shape.** pyatv chains multiple `cmd1 cmd2=arg …` on one line and runs them in sequence (`atvremote.py:862-884`); clap's subcommand model runs exactly one. No multi-command chaining. |
| `-i/--id` | `id: Option<String>` (`cli.rs:16-17`) | Present, but pyatv's `TransformIdentifiers` (`scripts/__init__.py:78-89`) accepts a **comma-separated list** and matches any of them; Rust takes one string only. |
| `-n/--name` | — | **Missing.** No `--name` flag; can't select a device by advertised name. |
| `--address` | — | **Missing.** No manual-address flag at all. |
| `--protocol` (global, used both for scan filtering and manual mode) | Only exists per-subcommand on `Pair { protocol }` (`cli.rs:118-122`) | **Missing globally.** Can't restrict `scan`/connect to one protocol. |
| `--port` | — | **Missing** (manual mode has no equivalent, see below). |
| `-t/--scan-timeout` | `scan_timeout: u64` (`cli.rs:24-25`), default 5s vs pyatv's 3s (`atvremote.py:589`) | Present, default differs. |
| `-s/--scan-hosts` | `scan_hosts: Vec<IpAddr>` (`cli.rs:20-21`) | Present. |
| `--scan-protocols` | — | **Missing.** `commands.rs:34-41` hardcodes `protocols: HashSet::new()` (no filter ever applied). |
| `--version` | Provided by clap's `#[command(... version ...)]` (`cli.rs:13`) | Present but only reports the Rust crate version, not "atvremote X / pyatv Y" the way `atvremote.py:606-611` does (no equivalent "library version" to report). |
| `--remote-name` | — | **Missing.** `pair.rs:106-111` documents this directly: no keyword channel to `pyatv::pair` for the on-screen name, defaults to whatever the library hardcodes. |
| `-p/--pin` | — | **Missing.** Pairing is always interactive (`commands/pair.rs:49` prompts and blocks on stdin); no way to pre-supply a PIN non-interactively the way `atvremote.py:617-625` does. |
| `--pairing-guid` | — | **Missing** (DMAP-specific anyway, moot until DMAP pairing is wired — §1.4). |
| `-m/--manual` | — | **Missing entirely.** No manual-device mode; every command must resolve through `scan`. |
| `--service-properties` | — | **Missing** (only relevant to `--manual`). |
| `--<protocol>-credentials` (one flag per `Protocol`, 5 total: dmap/mrp/airplay/companion/raop, `atvremote.py:649-656`) | Only `--companion-credentials` and `--airplay-credentials` (`cli.rs:31-54`) | **3 of 5 missing**: no `--mrp-credentials`, `--dmap-credentials`, `--raop-credentials`. |
| `--airplay-password` / `--raop-password` | — | **Missing.** No password override flags at all. |
| `-v/--verbose`, `--debug` | `verbose: u8` (`cli.rs:56-58`), mapped to a `tracing` filter (`cli.rs:68-75`) | Present in spirit; pyatv's are two independent flags mapping to `INFO`/`DEBUG` on the root Python logger, this is a single repeatable `-v` count (0=warn…3=trace). Behaviourally similar, textually different. |
| `--mdns-debug` | — | **Missing** (raises `pyatv.core.mdns` to a custom `TRAFFIC` level upstream). |
| `--storage`, `--storage-filename` | `storage_filename: Option<PathBuf>` (`cli.rs:27-29`) only | **`--storage none` (in-memory) missing** — no way to run without touching disk. `--storage-filename` exists but there is no `--storage {file,none}` choice. |

### 1.2 Subcommands

pyatv has no fixed subcommand list — `_handle_device_command` (`atvremote.py:889-951`) dispatches by matching the typed command string against `retrieve_commands()` on each interface class in turn, in this priority: `DeviceCommands`, `SettingsCommands`, `interface.Audio` (deliberately ahead of `RemoteControl`, comment at `atvremote.py:914-915`), `RemoteControl`, `Metadata`, `Power`, `Playing`, `Stream`, `Keyboard`, `DeviceInfo`, `Apps`, `UserAccounts`, `TouchGestures`. Below, "pyatv command" means one of those method/property names.

**Global (no device) commands** — `GlobalCommands` (`atvremote.py:85-377`):

| Command | pyatv behaviour | atvremote-rs | Status |
| --- | --- | --- | --- |
| `commands` | Prints every command grouped by interface (`atvremote.py:94-111`) | — | **Missing.** No introspection/listing subcommand. |
| `help <cmd>` | Prints the method signature + docstring (`atvremote.py:113-146`) | clap `--help` covers flags/subcommands but not per-button help for `remote <button>` | **Missing** in pyatv's sense (per-interface-method help). |
| `scan` | `scan()` then prints `BaseConfig.__str__` per device, `"Scan Results\n" + "="*40` header (`atvremote.py:148-160`, `_print_found_apple_tvs:739-743`) | `Command::Scan` → `commands.rs:47-61` | **Implemented**, but **no header/banner** — `scan.rs:47-61` prints one device per line with no `"Scan Results\n========================================"` framing pyatv always prints first. |
| `pair --protocol X` | `pair()` (`atvremote.py:162-238`) | `Command::Pair` → `commands/pair.rs` | **Implemented**, closely: same prompt text (`"Enter PIN on screen: "`), same success/failure lines. Missing: `device_provides_pin=false` path (upstream lets the *caller* pick a PIN and prints `"Use pin N to pair..."`; Rust always requires the device to show one — see `pair.rs:43-47`), and no `--pin`/`--remote-name`/`--pairing-guid` to feed it (§1.1). |
| `wizard` | Interactive multi-device setup wizard: lists devices in a table, prompts for password/pairing per service, connects and prints `playing()` (`atvremote.py:242-376`) | — | **Missing entirely.** No wizard command. |

**Device commands** — `DeviceCommands` (`atvremote.py:379-470`, non-API, atvremote-specific):

| Command | pyatv behaviour | atvremote-rs | Status |
| --- | --- | --- | --- |
| `cli` | Interactive REPL reading `pyatv> ` and dispatching each line (`atvremote.py:392-408`) | — | **Missing.** |
| `artwork_save[=width,height,file_name]` | Saves to `{file_name}.png`, default `artwork` (`atvremote.py:410-419`) | `Command::Artwork { output, width, height }` (`cli.rs:177-190`, `commands/device.rs:378-405`) | **Implemented differently**: takes an explicit output path rather than a bare filename + hardcoded `.png` suffix, and — per `device.rs:373-377` — deliberately does *not* force `.png` since the bytes aren't always PNG. A documented, reasoned divergence, not a bug. |
| `push_updates` | Blocks on stdin ENTER, prints `Playing.__str__` + 20-dash rule per update (`atvremote.py:421-434`, `PushListener` at `504-513`) | `Command::PushUpdates { timeout }` (`commands/device.rs:245-283`) | **Implemented**, and improved: adds Ctrl-C and an optional `--timeout`, output format matches (`commands/output.rs:67-83`). |
| `device_info` | `Model/SW: {devinfo}` / `MAC: {devinfo.mac}` (`atvremote.py:436-441`) | `Command::DeviceInfo` (`commands/device.rs:113-123`) | **Implemented**, byte-for-byte per the comment there. |
| `features[=all]` | Feature list + legend, `all` includes `Unsupported` (`atvremote.py:443-465`) | `Command::Features` (`commands/device.rs:126-132`) | **Implemented**, but the `=all` argument (`include_unsupported=True`) is **not exposed** — `output::print_features` (`output.rs:51-65`) always calls with `false` per `device.rs:128`. |
| `delay=<ms>` | `asyncio.sleep(ms/1000)` (`atvremote.py:467-470`), useful for chained commands | — | **Missing** — moot without chained commands (§1.1), but also not present standalone. |

**Settings commands** — `SettingsCommands` (`atvremote.py:473-501`): `print_settings`, `remove_settings`, `change_setting=<name>,<value>`, `unset_setting=<name>` — **all four missing**. `pyatv::Settings`/`update_model_field`/`stringify_model` equivalents exist in `pyatv-core::storage::settings` but nothing in the CLI surfaces them.

**Interface-backed commands**, grouped by pyatv class:

*`RemoteControl`* (`interface.py:292-465`, 29 methods incl. deprecated `volume_up/volume_down/suspend/wakeup`) — dispatched in atvremote-rs through one `Command::Remote { button }` argument, matched in `output::press` (`commands/output.rs:112-141`):

- Covered by name match: `up, down, left, right, select, menu, home, home_hold, top_menu, guide, control_center, screensaver, play, play_pause, pause, stop, next, previous, skip_forward, skip_backward, channel_up, channel_down` (22 names).
- **Missing from the button dispatcher:** `set_position`, `set_shuffle`, `set_repeat` (all three need a typed argument pyatv passes via `cmd=arg` parsing at `atvremote.py:830-851`, and `output::press` has no argument slot at all — `press(remote, button)` takes only a button name, no value); the deprecated `volume_up`/`volume_down`/`suspend`/`wakeup` (arguably fine to drop — pyatv itself tells callers to use `Audio`/`Power` instead).
- **Argument handling gap:** pyatv's directional/select/home/menu/click buttons accept an optional `InputAction` suffix (`up=1` for double-tap, parsed at `atvremote.py:836-846`); atvremote-rs always sends `InputAction::SingleTap` (`output.rs:113`, noted directly in the doc comment at `output.rs:105-106`).

*`Metadata`* (`interface.py:789-829`): `device_id`, `artwork`, `artwork_id`, `playing`, `app` — `playing` implemented (`Command::Playing`, `commands/device.rs:228-237`) and `artwork` implemented (`Command::Artwork`); **`device_id`, `artwork_id`, and standalone `app`** (print current app) have **no subcommand**.

*`Power`* (`interface.py:929-949`): `power_state`, `turn_on`, `turn_off` — all three **implemented** (`Command::PowerState/TurnOn/TurnOff`).

*`Playing`* properties (16, `interface.py:472-489`) — reachable only via `Command::Playing`'s `Display` rendering, matching `Playing.__str__` (ported field-for-field in `crates/pyatv-core/src/models/playing.rs:95-149`, verified against `interface.py:540-589` with dedicated tests, `models/playing.rs:174-314`). No way to query one field in isolation the way `atvremote artist` does upstream (`retrieve_commands(Playing)` makes every property its own atvremote command, `atvremote.py:895,928-930`).

*`Stream`* (`interface.py:874-901`): `play_url` implemented (`Command::PlayUrl`), `stream_file` implemented (`Command::StreamFile`) — but see §2 for the signature gap (no `metadata`/`override_missing_metadata`, no stdin `-` special-case). `close` has no standalone subcommand (not meaningful as one; it's invoked implicitly on Ctrl-C in both `play_url`/`stream_file`, `commands/device.rs:314-322,357-364`).

*`Apps`* (`interface.py:732-743`): `app_list`, `launch_app` — both **implemented** (`Command::AppList/LaunchApp`).

*`UserAccounts`* (`interface.py:775-786`): `account_list`, `switch_account` — **both missing**, no subcommand at all despite `pyatv_core::interface::UserAccounts` existing.

*`Audio`* (`interface.py:1162-1233`): `volume` + `set_volume` folded into one `Command::Volume { level: Option<f32> }` (`commands/device.rs:210-224`, documented as a deliberate fold of two pyatv commands into one). **Missing:** `volume_up`, `volume_down` (as `Audio` methods, distinct from the deprecated `RemoteControl` ones — no subcommand reaches `atv.audio().volume_up()`), `output_devices`, `add_output_devices`, `remove_output_devices`, `set_output_devices` — none of the AirPlay-2 output-device commands are exposed.

*`Keyboard`* (`interface.py:1247-1278`): `text_focus_state`, `text_get`, `text_clear`, `text_append`, `text_set` — **all five missing**, no subcommand touches `atv.keyboard()` even though `pyatv_core::interface::Keyboard` and `CompanionKeyboard` (`crates/pyatv-proto-companion/src/facade/input.rs:25-75`) both exist.

*`TouchGestures`* (`interface.py:1281-1317`): `swipe`, `action`, `click` — **all three missing** from the CLI, despite `CompanionTouchGestures` (`crates/pyatv-proto-companion/src/facade/input.rs:77-`) implementing the trait.

*`DeviceInfo`* fields (`interface.py:952-1078`) are folded into `Command::DeviceInfo`'s two-line print rather than individually addressable — matches pyatv's own `DeviceCommands.device_info`, not the per-field `atvremote model` style upstream also supports via `retrieve_commands(interface.DeviceInfo)` — actually **upstream does not expose `DeviceInfo` fields as individual atvremote commands either** (`device_info` isn't in the `_handle_device_command` list at `atvremote.py:889-951`); no gap here.

### 1.3 `atvscript` — JSON scripting mode

**Not implemented at all.** `crates/pyatv/`, `cli/atvremote/` — there is no second binary or `--json`/`--output json` mode anywhere in the workspace (`cli/atvremote/Cargo.toml` defines exactly one `[[bin]]`, `atvremote`). pyatv's `atvscript.py` (432 lines) is a distinct entry point with: `scan` (device list as JSON, `atvscript.py:229-253`), `playing` (JSON of `Playing` + app, `:298-307`), `push_updates` (JSON per event: power, volume, output devices, keyboard focus, connection lost/closed, playstatus, `:309-330`), and any bare `RemoteControl` command name (`:332-334`). The `output()`/`output_playing()` envelope (`result`, `datetime`, optional `error`/`exception`/`stacktrace`, merged `values`, `atvscript.py:192-226`) has no Rust equivalent, structured or otherwise. This is the single largest CLI-parity gap in absolute surface area — everything a supervising process would script against (structured errors, machine-parseable scan/playing/push output) is missing.

### 1.4 Cross-cutting CLI blockers

- **DMAP is unreachable from the CLI** because it is unreachable from `pyatv::connect`/`pyatv::pair` at all (§2, `crates/pyatv/src/connect.rs:255-260`, `crates/pyatv/src/pair.rs:134-136`) — no CLI fix is possible until that lands, and the worker currently on `pyatv-proto-dmap` may change this mid-flight.
- No `atvremote commands`/`help` introspection means there is no single place a user can discover the button-name vocabulary `remote` accepts other than reading `output::press`'s match arms.

---

## 2. Facade / interface parity

### 2.1 `pyatv/interface.py` abstract classes vs `crates/pyatv-core/src/interface/*.rs`

**`RemoteControl`** (`interface.py:292-465`) vs `crates/pyatv-core/src/interface/control.rs:17-71`: full method-name parity for the 22 non-deprecated methods, including `guide`/`control_center` (`control.rs:36-39`, added upstream in 0.17.0 — confirmed present). The four deprecated pyatv methods (`volume_up`, `volume_down`, `suspend`, `wakeup`) are **intentionally absent** — their functionality lives only on `Audio`/`Power` in Rust, which is the direction pyatv itself is pushing users; not a gap, a cleanup. Signatures: `async fn` vs pyatv's `async def` map 1:1 modulo the `BoxFuture` wrapper documented at `crates/pyatv-core/src/interface.rs:8-13`. `set_position` takes `f32` (`control.rs:61`) vs pyatv's `int` seconds (`interface.py:428`) — deliberate widening, not a bug, but worth flagging since the wire protocols mostly carry seconds as integers or milliseconds; verify each protocol's conversion doesn't silently truncate.

**`Keyboard`** (`interface.py:1247-1278`) vs `control.rs:79-90`: full parity (`text_focus_state`, `text_get`, `text_set`, `text_append`, `text_clear`). No `KeyboardListener` (`interface.py:1236-1244`, `focusstate_update`) trait exists anywhere in `pyatv-core` — confirmed by an empty grep for `KeyboardListener` across `crates/pyatv-core`, `crates/pyatv`, `cli/`. `atvscript`'s `KeyboardPrinter` (`atvscript.py:137-153`) has nothing to port to.

**`TouchGestures`** (`interface.py:1281-1317`) vs `control.rs:98-117`: full parity (`swipe`, `action`, `click`), including the documented reasoning for why `click` takes `InputAction` not `TouchAction` (`control.rs:111-116`, matches `interface.py:1301-1317`).

**`Metadata`** (`interface.py:789-829`) vs `crates/pyatv-core/src/interface/playback.rs:16-36`: `device_id`, `playing`, `artwork(width, height)`, `artwork_id`, `app` all present with matching signatures. One divergence: `artwork_id` returns `Option<String>` (`playback.rs:32`) where pyatv's property either returns a string or raises `NotSupportedError` (`interface.py:811-814`) — reasonable Rust-idiomatic translation, not a defect.

**`PushUpdater`** (`interface.py:844-871`) vs `playback.rs:54-69`: `active`, `start(initial_delay)`, `stop` present. Listener registration differs by design (`set_listener`, single weak slot, `playback.rs:57-64`) vs pyatv's `StateProducer`-backed `.listener =` property — behaviourally equivalent, documented.

**`Stream`** (`interface.py:874-901`) vs `playback.rs:77-86`: **signature gap**. pyatv's `stream_file`:
```python
async def stream_file(self, file: Union[str, io.BufferedIOBase, asyncio.streams.StreamReader], /, metadata: Optional[MediaMetadata] = None, override_missing_metadata: bool = False, **kwargs) -> None
```
(`interface.py:886-901`) vs Rust's `fn stream_file(&self, path: &Path) -> BoxFuture<'_, Result<()>>` (`playback.rs:82`). Missing: the `metadata: Option<MediaMetadata>` override (pyatv's `MediaMetadata` struct at `interface.py:74-84`, which exists in Rust models? — **not found**; grep for `MediaMetadata` in `crates/pyatv-core` is empty), `override_missing_metadata: bool`, and the ability to stream from something other than a filesystem path (pyatv accepts a `BufferedIOBase`/`StreamReader`, and `atvremote`'s own dispatcher special-cases `-` for stdin at `atvremote.py:963-964`; Rust's CLI has no such special-case, `commands/device.rs:340-371` always treats the argument as a filesystem `Path`). `play_url`'s signature also drops pyatv's `**kwargs` (`interface.py:882`, used upstream for protocol-specific options) — acceptable simplification given Rust has no equivalent open-ended kwargs idiom, but any caller-supplied AirPlay start parameters pyatv exposes there have no Rust equivalent.

**`Power`** (`interface.py:929-949`) vs `crates/pyatv-core/src/interface/device.rs:16-24`: full parity (`power_state`, `turn_on(await_new_state)`, `turn_off(await_new_state)`).

**`Apps`** (`interface.py:732-743`) vs `device.rs:31-36`: full parity.

**`UserAccounts`** (`interface.py:775-786`) vs `device.rs:69-74`: full parity at the trait level (not surfaced by the CLI, §1.2).

**`Audio`** (`interface.py:1162-1233`) vs `device.rs:44-62`: **the biggest interface-level gap in the workspace.**
- `output_devices` returns `List[OutputDevice]` upstream (`interface.py:1214-1218`, each with `identifier`, `name`, `volume` — `interface.py:1116-1136`) vs Rust's `fn output_devices(&self) -> Vec<String>` (`device.rs:55`) — **identifiers only, no name or per-device volume**. This loses information `atvscript`'s `AudioPrinter.outputdevices_update` needs (`atvscript.py:99-116`, prints `{"name": ..., "identifier": ...}` per device) and that `FacadeAudio._output_devices_changed` tracks upstream (`core/facade.py:463-473`).
- `set_volume` drops the `output_device: Optional[OutputDevice]` parameter (`interface.py:1181-1188`) — Rust's `set_volume(&self, level: f32)` (`device.rs:48`) can only set the *group* volume, never one output device's volume within a multi-speaker group.
- No `pyatv_core::models::OutputDevice` type exists at all — confirmed: the only `OutputDevice` struct in the workspace is an MRP-internal one at `crates/pyatv-proto-mrp/src/state/volume.rs:19`, not exported through `pyatv-core`'s public interface.
- **No `AudioListener` trait** (`interface.py:1139-1159`: `volume_update`, `volume_device_update`, `outputdevices_update`) anywhere in the workspace — confirmed by empty grep. There is consequently no way to be notified of a volume or output-device change; a caller must poll `Audio::volume()`.

**`Features`** (`interface.py:1081-1113`) vs `device.rs:80-86`: `get_feature`, `all_features(include_unsupported)` present. `in_state(states, *feature_names)` (`interface.py:1097-1113`, a convenience the CLI itself uses at `atvremote.py:423-428,870-873`) has **no Rust equivalent** — every call site in `cli/atvremote` re-implements the single-feature check inline (e.g. `commands/device.rs:248,304,347`), and there is no multi-feature/multi-state variant at all.

**`AppleTV`** (`interface.py:1514-1599`) vs `crates/pyatv-core/src/interface.rs:41-92`: `connect`, `close`, `settings` (missing — see below), `device_info`, `service`, `remote_control`, `metadata`, `push_updater`, `stream`, `power`, `features`, `apps`, `user_accounts`, `audio`, `keyboard`, `touch` all present in spirit. **`AppleTV.settings` (`interface.py:1531-1534`) has no Rust equivalent** — `crates/pyatv-core/src/interface.rs:41-92` has no `fn settings(&self) -> &Settings`, so a connected `AppleTV` cannot hand back its own `Settings` object the way `SettingsCommands` needs (`atvremote.py:483-501`); this is exactly why §1.2's four settings subcommands can't be built without first adding this accessor (or threading `Storage` through the CLI separately, which is also possible but diverges from upstream's shape).

**Listener types**: `DeviceListener` (`interface.py:904-915`) ↔ `crate::interface::DeviceListener` (`interface.rs:170-175`) — parity. `PowerListener` (`interface.py:918-926`) ↔ `crate::interface::PowerListener` (`interface.rs:185-188`) — parity. `PushListener` (`interface.py:832-841`) ↔ `crate::interface::PlaybackListener` (`playback.rs:41-46`) — parity (different name, same shape). `AudioListener` and `KeyboardListener` — **both missing**, as noted above.

**`App`/`UserAccount`/`ArtworkInfo`/`Playing`** data types (`interface.py:65-73,469-700,703-729,746-772`) ↔ `crates/pyatv-core/src/models/playing.rs` — full field parity, `Playing::Display` independently verified line-for-line against `__str__` with dedicated tests (`models/playing.rs:174-314`).

### 2.2 `pyatv/core/facade.py` vs `crates/pyatv-core/src/facade.rs`

**Priority tables**: `DEFAULT_PRIORITIES` (`facade.py:38-44`: MRP, DMAP, Companion, AirPlay, RAOP) ↔ `facade.rs:34-40` — **exact match**. `FacadePower.OVERRIDE_PRIORITIES` (`facade.py:311-318`: Companion, MRP, DMAP, AirPlay, RAOP) ↔ `POWER_PRIORITIES` (`facade.rs:46-52`) — **exact match**, including the "Companion implements power better than MRP" comment reproduced verbatim.

**`FacadeFeatures.add_mapping`** (`facade.py:274-284`, highest-priority protocol wins, later registrations only override if they outrank the incumbent) ↔ `FacadeFeatures::add_mapping` in `crates/pyatv-core/src/facade/features.rs` — logic ported and independently regression-tested (`facade.rs:441-462`, guards the exact "handle taken before a later protocol registers" bug pyatv's own priority-index comparison avoids).

**`FacadeAudio` volume/output-device fan-out** (`facade.py:434-544`): pyatv's `FacadeAudio` listens to three `CoreStateDispatcher` channels (`UpdatedState.Volume/OutputDevices/OutputDeviceVolume`) and only fires its listener when the value actually changed (`facade.py:451-461,463-473,475-493`). **No Rust equivalent exists** — there is no `FacadeAudio` type in `crates/pyatv-core/src/facade.rs`; `Audio` is relayed through a plain `Relayer<dyn Audio>` (`facade.rs:166`) with no change-detection, no listener fan-out, and (per §2.1) no `OutputDevice`/`AudioListener` types for it to fan out to even if it existed. This is the facade-side twin of the interface gap above and should be designed together.

**`FacadeStream.play_url` gating** (`facade.py:369-375`: raises `NotSupportedError` unless `FeatureName.PlayUrl` is `Available`, *before* relaying): in Rust this check is **not in the facade** — `crates/pyatv-core/src/interface/playback.rs:77-86`'s `Stream` trait has no such gate, and the only place it happens is the CLI itself (`cli/atvremote/src/commands/device.rs:304-306`, `bail!` on unavailable). A caller going through the library directly (not the CLI) gets no such guard — `pyatv::connect(...).stream().play_url(...)` on a device without the feature will hit whatever the underlying protocol does instead of a clean `NotSupportedError`. Given `pyatv-core` has no `FacadeStream` type at all (Stream is relayed via a bare `Relayer<dyn Stream>`, `facade.rs:163`), this gate has nowhere to live yet.

**`FacadeMetadata.artwork` cache**: pyatv's `FacadeMetadata` (`facade.py:213-258`) does **not** actually cache artwork itself (worth correcting an assumption in the task prompt) — it is a pure relay, `artwork` just calls `self.relay("artwork")(...)` (`facade.py:227-236`). No gap here; nothing to port.

**`FacadePushUpdater` combining** (`facade.py:597-644`): `start`/`stop` iterate *every* registered instance and set each as `self` (`facade.py:625-634`, so multiple protocols can be started/stopped together), while `playstatus_update`/`playstatus_error` only forward from `main_instance` (`facade.py:636-644`, so only the highest-priority protocol's updates reach the caller even if two are running). Rust's facade has **no `FacadePushUpdater`** — `push_updater` is a bare `Relayer<dyn PushUpdater>` (`facade.rs:162`) exposed via `AppleTV::push_updater() -> Option<Arc<dyn PushUpdater>>` (`interface.rs:47`), which returns only `main_instance()` (`facade.rs:316-318`). Starting the *main* instance is right, but there is no mechanism to also start a lower-priority protocol's updater in the background the way upstream's `start`/`stop` loop over `self.instances` does — moot today since no two connected protocols currently both implement `PushUpdater` at once in practice (MRP/DMAP/RAOP all can, but a device rarely offers more than one), but worth a note before DMAP + MRP coexist on one device.

**`FacadeAppleTV.takeover`/`release`** (`facade.py:804-830`, backed by `Relayer.takeover`/`release` in `pyatv/core/relayer.py:117-127`): lets one protocol temporarily claim exclusive ownership of one or more interfaces — used concretely by AirPlay's `play_url` to take over `RemoteControl` for the duration of playback (`pyatv/protocols/airplay/__init__.py:125,139,261,368`), so that e.g. `stop()` routes to the AirPlay stream instead of MRP while a URL is playing. **Entirely absent from Rust.** `crates/pyatv-core/src/relayer.rs:1-145` has no `takeover`/`release` method (confirmed: no `_takeover_protocol`-equivalent field, `search_order` at `relayer.rs:51-57` walks only the fixed `priorities` list), and `crates/pyatv-core/src/facade.rs` has no `takeover` method on `FacadeAppleTV` at all. Concretely: today, in this port, calling `remote_control().stop()` while `stream().play_url()` is in flight goes straight to MRP/Companion, not to the AirPlay stream — a real behavioural divergence from pyatv, not just a missing convenience method.

**`state_was_updated`** (`facade.py:921-927`, closes the whole facade when a protocol reports itself lost): the Rust equivalent is `FacadeAppleTV: DeviceListener` (`facade.rs:296-305`), which fans the event out to registered listeners but — unlike upstream — **does not close the facade itself**. Confirm this divergence is intentional; upstream tears the whole connection down on any protocol's `connection_lost`/`connection_closed`, and the Rust port currently leaves that entirely to the caller.

### 2.3 Per-protocol coverage matrix (which protocol crate implements which capability trait)

Built by cross-referencing each protocol's `interfaces = {...}` dict upstream against each crate's `impl <Trait> for` sites.

| Capability | pyatv MRP (`protocols/mrp/__init__.py:1118-1124`) | Rust MRP (`crates/pyatv-proto-mrp/src/facade{,/*.rs}`) | pyatv Companion (`protocols/companion/__init__.py:673-682`) | Rust Companion (`crates/pyatv-proto-companion/src/facade{,/*.rs}`) | pyatv AirPlay (`protocols/airplay/__init__.py:313-319`) | Rust AirPlay (`crates/pyatv-proto-airplay/src/setup/interfaces.rs`) | pyatv RAOP (`protocols/raop/__init__.py:546-553`) | Rust RAOP (`crates/pyatv-proto-airplay/src/raop/facade{,/*.rs}`) | pyatv DMAP (`protocols/dmap/__init__.py:676-682`) | Rust DMAP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RemoteControl | ✓ | ✓ (`facade/remote.rs:187`) | ✓ | ✓ (`facade/remote.rs:72`) | ✓ | ✓ (`interfaces.rs:236`) | ✓ | ✓ (`facade/updates.rs:130`) | ✓ | **✗ none** |
| Metadata | ✓ | ✓ (`facade/metadata.rs:214`) | — | — | — | — | ✓ | ✓ (`facade/updates.rs:74`) | ✓ | **✗** |
| PushUpdater | ✓ | ✓ (`facade/metadata.rs:312`) | — | — | — | — | ✓ | ✓ (`facade/updates.rs:215`) | ✓ | **✗** |
| Power | ✓ | ✓ (`facade/power.rs:43`) | ✓ | ✓ (`facade/device.rs:185`) | — | — | — | — | — | **✗** |
| Audio | ✓ | ✓ (`facade/audio.rs:138`) | ✓ | ✓ (`facade/device.rs:246`) | — | — | ✓ | ✓ (`raop/facade.rs:256`) | ✓ | **✗** |
| Features | ✓ | ✓ (`facade/features.rs:217`) | ✓ | ✓ (`facade.rs:147`) | ✓ | ✓ (`interfaces.rs:37`) | ✓ | ✓ (`raop/facade.rs:317`) | ✓ | **✗** |
| Stream | — | — | — | — | ✓ | ✓ (`interfaces.rs:169`) | ✓ | ✓ (`raop/facade.rs:212`) | — | — |
| Apps | — | — | ✓ | ✓ (`facade/device.rs:44`) | — | — | — | — | — | — |
| UserAccounts | — | — | ✓ | ✓ (`facade/device.rs:79`) | — | — | — | — | — | — |
| Keyboard | — | — | ✓ | ✓ (`facade/input.rs:47`) | — | — | — | — | — | — |
| TouchGestures | — | — | ✓ | ✓ (`facade/input.rs:89`) | — | — | — | — | — | — |

**Result: every protocol currently wired matches pyatv's own interface assignment exactly, trait for trait.** The only row that diverges from upstream is DMAP, which is 100% unimplemented on the Rust side — no `SetupData`/`setup()` equivalent exists in `crates/pyatv-proto-dmap` (confirmed: `find crates/pyatv-proto-dmap/src -name '*.rs'` returns only `error.rs, lib.rs, pairing.rs, parser.rs, tags.rs` — no `facade*`), and `crates/pyatv/src/connect.rs:255-260` / `crates/pyatv/src/pair.rs:134-136` both stub it out with `TODO(step-5)` comments. Given the concurrent DMAP worker, re-run this table's DMAP column before treating it as current.

---

## 3. `const.py` / `helpers.py` parity

### 3.1 `const.py` (`/tmp/pyatv-ref/pyatv/const.py`)

All seven enums (`Protocol`, `MediaType`, `DeviceState`, `RepeatState`, `ShuffleState`, `PowerState`, `KeyboardFocusState`, `OperatingSystem`, `DeviceModel`, `InputAction`, `PairingRequirement`, `TouchAction`) are reproduced in `crates/pyatv-core/src/consts.rs`, with discriminants pinned by tests (`consts.rs:356-431`) including the deliberately non-contiguous `DeviceModel` numbering and the `TouchAction` gap at `2`. `FeatureName` is reproduced in full in `crates/pyatv-core/src/features.rs`, order- and membership-pinned against a literal copy of `const.py:252-457` (`features.rs:429-516`) — this is exactly the "FeatureName was realigned" work CLAUDE.md references, and it checks out: **no drift found**. One naming note, already documented in-repo: `FeatureName::TouchAction`/`ItunesStoreIdentifier` intentionally spell differently from the Python variant names but render identically via `as_str()` (`features.rs:129-131,184-186`).

`MAJOR_VERSION`/`MINOR_VERSION`/`PATCH_VERSION`/`__version__` (`const.py:7-11`) have no Rust equivalent surfaced to callers beyond Cargo's own crate version (`workspace.package.version = "0.1.0"`, `Cargo.toml:7`) — not a meaningful gap, just note that nothing in this workspace can currently print an "atvremote X / library Y" banner the way `atvremote.py:610` does, because there is no `pyatv_core::const::VERSION`-equivalent constant tied to a spec-compatible version number.

### 3.2 `helpers.py` (`/tmp/pyatv-ref/pyatv/helpers.py`)

| Function | Status |
| --- | --- |
| `get_unique_id(service_type, service_name, properties)` (`helpers.py:54-87`) | **Ported**, faithfully, in `crates/pyatv-mdns/src/scan/handlers/mod.rs:105-`, called from every protocol's scan handler (`scan/handlers/{mrp,airplay,companion,raop,dmap}.rs`) and covered by tests mirroring the docstring's cases (`scan/handlers/mod.rs:184-`). Not re-exported through the `pyatv-core`/`pyatv` public API the way `pyatv.helpers.get_unique_id` is importable by a library consumer — it currently lives at `pyatv_mdns::scan::handlers::get_unique_id`, which is a much less discoverable path than upstream's `pyatv.helpers`. Consider re-exporting from `crates/pyatv/src/lib.rs` if external callers are expected to use it directly (mirrors upstream's module layout, where `helpers.py` is a public top-level module). |
| `is_streamable(filename)` (`helpers.py:90-102`, wraps `miniaudio.get_file_info`) | **Not ported.** No Rust equivalent anywhere in the workspace (confirmed by grep). There is no `miniaudio`-equivalent probe crate wired in; `pyatv-proto-airplay`'s RAOP stack uses `symphonia` for actual decoding (per `deny.toml`'s MPL exceptions) but nothing exposes a cheap "can this be streamed" pre-check the way upstream's helper does. |
| `is_device_supported(conf)` (`helpers.py:105-122`) | **Not ported.** No function anywhere checks whether every service on a `BaseConfig` is `Unsupported`/`Disabled` pairing-wise. Trivial to add against `crates/pyatv-core/src/models/config/mod.rs` (`PairingRequirement` is already there) — this is a small, high-value addition since it is exactly the check a UI would want before offering to pair a device at all. |
| `auto_connect(handler, timeout, not_found, loop)` (`helpers.py:19-51`) | **Not ported.** No convenience "scan, take first, connect, run closure, close" wrapper exists in `crates/pyatv/src/lib.rs` or elsewhere. Low-value for a Rust API (callers can trivially compose `scan()`+`connect()` themselves without the closure-passing idiom Python needed), but it is public API surface upstream and its absence is a real, if minor, parity gap for anyone porting example code. |
| Service-type constants (`HOMESHARING_SERVICE`, `DEVICE_SERVICE`, `MEDIAREMOTE_SERVICE`, `AIRPLAY_SERVICE`, `COMPANION_SERVICE`, `RAOP_SERVICE`, `HSCP_SERVICE`, `helpers.py:10-16`) | Present under a different name/location: `pyatv_mdns`'s `ServiceType` enum (used throughout `scan/handlers/*.rs`) covers the same set. Not a gap, just a different public path (enum vs. bare string constants) — worth confirming `ServiceType` is re-exported somewhere a library consumer would find it as easily as `pyatv.helpers.MEDIAREMOTE_SERVICE`. |

---

## 4. Hardening checklist

| Item | Status | Evidence |
| --- | --- | --- |
| `cargo-deny` bans tightened to `deny` | **Not done — `multiple-versions = "warn"` still** | `deny.toml:52-55`. Live run (`cargo deny check bans`, this session) currently reports 5 duplicate-version warnings: `hashbrown` (×2), `logos`, `logos-codegen`, `logos-derive`, `syn` (×2 each). Flipping to `deny` today would **break the build** until these are resolved with `skip`/`skip-tree` entries or the duplicate is eliminated upstream in the dependency graph — do that resolution *before* flipping the switch, not after. |
| `cargo hack --feature-powerset` wired into devenv/CI | **Not wired.** `cargo-hack` is not installed (`which cargo-hack` → not found) and not listed in `devenv.nix`'s `packages` (`devenv.nix:28-36`) or `qualityGate` (`devenv.nix:5-17`). Relevant because the workspace has at least one meaningfully feature-gated crate (`pyatv-pairing`'s `test-server`, per CLAUDE.md's own callout) whose powerset is currently unchecked. |
| `cargo-msrv` wired into devenv/CI | **Not wired.** Same story: not installed, not in `devenv.nix`. `rust-version = "1.88"` is declared (`Cargo.toml:8`) but nothing verifies the workspace actually still builds at that floor — only the pinned 1.98.0 toolchain is ever exercised. |
| `criterion` benchmarks for hot codec/audio paths | **None exist.** No `[[bench]]` targets, no `benches/` directory anywhere in the workspace (`find . -type d -name benches` empty), and `criterion` is not a dependency of any crate (`grep -rn criterion Cargo.toml crates/*/Cargo.toml` empty). The obvious candidates per the crate layout — `pyatv-opack`'s (de)serializer, `pyatv-proto-mrp`'s protobuf/varint framing, `pyatv-proto-airplay`'s RAOP pacing/fifo (`crates/pyatv-proto-airplay/src/raop/{pacing,fifo}.rs`) and AES-GCM/ChaCha framing in `pyatv-pairing` — have zero benchmark coverage today. |
| `RUSTDOCFLAGS=-D warnings cargo doc` | **Fails, run live this session.** `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps` exits 101. **7 of 10 workspace crates fail**: `pyatv-mdns`, `pyatv-core`, `pyatv-pairing`, `pyatv-proto-companion`, `pyatv`, `pyatv-proto-airplay`, `pyatv-proto-mrp`. **3 pass clean**: `pyatv-opack`, `pyatv-proto-dmap`, `atvremote` (cli). Failure categories, with representative sites: broken intra-doc links to items that don't exist under their cited name (`crates/pyatv-core/src/device_info/lookup.rs:129` → `OperatingSystem::TvOS` should be `TvOs`; `crates/pyatv-core/src/interface/playback.rs:40` → `PushUpdater::add_listener` doesn't exist, should be `set_listener`; `crates/pyatv-proto-companion/src/facade.rs:236` → `Error::InvalidCredentials` doesn't exist; six occurrences of `Error::Pairing`/`Error::Timeout`/`Error::Decode` unresolved in `crates/pyatv-proto-mrp/src/auth.rs:61-126` and `state.rs:311` — these files reference a bare `Error` without the `crate::` prefix rustdoc needs), links to private items from public docs (`crates/pyatv-core/src/airplay/service_details.rs:118`, `models/config/mod.rs:208`, `storage.rs:6`; similarly in `pyatv-pairing`, `pyatv-proto-airplay`, `pyatv/src/connect.rs:18`), redundant explicit link targets (`storage.rs:6`, `pyatv-proto-mrp/src/message.rs:6`, `protobuf/extensions.rs:14,114`), function/module name collisions (`mdns/mod.rs:20-21` `unicast`/`multicast`; `pyatv/src/lib.rs:3` `scan`/`pair`/`connect`), and two unrelated unclosed-`<data>`-tag warnings inside the *generated* protobuf doc comments (`target/.../out/mrp_protobuf.rs:3697,3699` — these come from `prost-build`'s codegen echoing hex dumps from the `.proto` source comments verbatim into rustdoc, not from hand-written code; fixing requires either escaping in the source `.proto` comments or `#[allow(rustdoc::invalid_html_tags)]` on the generated module). None of this is caught by the current quality gate (`devenv.nix:5-17` has no `cargo doc` step at all), so it has been silently accumulating. |
| `#![deny(missing_docs)]` per crate | **Not set anywhere.** `grep -rn missing_docs crates/*/src/lib.rs Cargo.toml` is empty; the workspace lint table (`Cargo.toml:44-49`) sets `missing_debug_implementations = "warn"` and `pedantic = "warn"` but nothing for `missing_docs`. In practice the crates read as extremely well-documented already (every file reviewed for this analysis had thorough module- and item-level doc comments), so turning this on is likely to surface few real gaps — but it is currently unenforced, meaning nothing stops that from regressing. |
| README / user docs | **Minimal.** `README.md` is 69 lines. `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/RISKS.md`, `docs/research/*` are all developer/design-facing; there is no user-facing "how do I install and use `atvremote`" or "how do I depend on `pyatv` as a library" document comparable to pyatv's own `docs/` (mkdocs site) or even a usage section in its README. Given the CLI gaps in §1, user docs should probably wait until subcommand coverage stabilizes rather than be written now. |

---

## 5. Prioritised task list

Sizes: **S** = well under a day, **M** = a few days, **L** = the better part of a week or crosses multiple crates. "Live" = needs verification against a real device/tvOS, not just hermetic tests.

### Must-have for a coherent Step 8 close

1. **[L, no live needed for the mechanism itself, but validate against a real chained MRP+AirPlay session]** Add `Relayer::takeover`/`release` and `FacadeAppleTV::takeover` (§2.2). This is the one item on this list that is a genuine *behavioural* bug today, not just missing surface: without it, `remote_control().stop()` during an in-flight `play_url()` routes to the wrong protocol. Port `pyatv/core/relayer.py:117-127` and `facade.py:804-830` directly; wire AirPlay's `play_url` (`crates/pyatv-proto-airplay/src/setup/interfaces.rs`) to call it the way `pyatv/protocols/airplay/__init__.py:125,139` does.
2. **[L]** Design and add `FacadeAudio` (output-device change fan-out), a public `pyatv_core::models::OutputDevice { identifier, name, volume }`, and the `AudioListener` trait (§2.1, §2.2). Widen `Audio::output_devices()` to return `Vec<OutputDevice>` and `Audio::set_volume` to take an optional target device. This is the interface-level gap with the most downstream effect (blocks `atvscript`-equivalent JSON push updates, blocks any multi-speaker UI).
3. **[M]** Wire DMAP into `FacadeAppleTV` via `crates/pyatv/src/connect.rs` and `pair.rs` once the concurrent DMAP worker lands a `setup()`-equivalent — this single change unblocks the DMAP column in §2.3 and every DMAP-dependent CLI command. **Coordinate with the DMAP worker rather than duplicating their work.**
4. **[S]** Fix all seven crates' `RUSTDOCFLAGS=-D warnings cargo doc` failures (§4) — every failure found is a one- or two-line fix (a `TvOs` typo, a `crate::` prefix, an explicit link target removal, a `mod@`/`()` disambiguation, or `#[allow(rustdoc::private_intra_doc_links)]` on a handful of genuinely-intentional links to private implementation detail). Do this before wiring a doc check into CI, or CI goes red on day one.
5. **[S]** Add `RUSTDOCFLAGS=-D warnings cargo doc --workspace --all-features` as a step in `devenv.nix`'s `qualityGate` (`devenv.nix:5-17`), after item 4 lands.

### High CLI value, moderate effort

6. **[M]** Add an `atvscript`-equivalent: either a `--output json` flag on `atvremote` or a second `atvscript` binary in `cli/`, covering at minimum `scan`, `playing`, and `push_updates` in the `output()`/`output_playing()` envelope shape (§1.3). This is the single largest CLI gap and the one most likely to matter to an automation-oriented user.
7. **[S]** Add the missing `--<protocol>-credentials` flags for MRP, DMAP, RAOP (§1.1) — mechanical, follows the existing Companion/AirPlay pattern in `cli/atvremote/src/cli.rs:31-54` and `commands/device.rs:49-79` exactly.
8. **[M]** Add CLI subcommands for `Keyboard`, `TouchGestures`, `UserAccounts`, and the missing `Audio` methods (`volume_up`/`volume_down`/`output_devices`/`add_output_devices`/`remove_output_devices`/`set_output_devices`) — all backing traits already exist (§2.1); this is purely `cli.rs` + `commands/device.rs` wiring, following the existing subcommand pattern.
9. **[S]** Add `--name`, `--scan-protocols`, `-m/--manual` + `--address`/`--port` (§1.1) to `cli/atvremote/src/cli.rs` and thread through `commands.rs::resolve_device`/`scan_options`.
10. **[S]** Add `Command::Commands`/`--list` (mirrors pyatv's `commands`) so button/subcommand names are discoverable without reading source (§1.2).

### Lower priority / smaller

11. **[S, live-validate against a device that reports `Suspend`/pairing-disabled state]** Port `helpers::is_device_supported` (§3.2) — small, self-contained, useful for a "should I even offer to pair this" check.
12. **[S]** Re-export `get_unique_id` (and ideally `ServiceType`) from the `pyatv` umbrella crate so library consumers don't need to depend on `pyatv-mdns` directly for it (§3.2).
13. **[M, live-validate against a paired device with a legacy `.pyatv.conf`]** Add `AppleTV::settings()` (§2.1) and then the four `SettingsCommands` subcommands (§1.2) — gated on the accessor landing first.
14. **[S]** Resolve the 5 duplicate-version warnings (`hashbrown`, `logos`×3, `syn`) via `cargo update`/`skip-tree`, then flip `deny.toml`'s `multiple-versions` to `deny` (§4) — do this as one change, not two, so the ban lands already green.
15. **[M]** Wire `cargo-hack --feature-powerset` and `cargo-msrv` into `devenv.nix` (§4) — mechanical devenv package + script additions, but budget time for whatever the powerset run turns up on `pyatv-pairing`'s `test-server` feature.
16. **[L, needs representative payloads captured live per docs/research/README.md's own guidance]** Add `criterion` benches for `pyatv-opack`'s codec, MRP's protobuf/varint path, and RAOP's pacing/fifo (§4) — sizeable because it needs realistic fixture data, not just any input.
17. **[S]** Set `#![deny(missing_docs)]` per crate (§4) — given the existing doc quality, likely a near-zero-diff enforcement change; do after item 4-5 so it doesn't compound with the rustdoc-link fixes.
18. **[M]** Add `Playing` field-level, `TouchAction`-argument, and `InputAction`-suffix support to `atvremote remote` (§1.2) so directional/select presses can specify double-tap/hold, matching pyatv's `cmd=arg` parsing.
19. **[Not recommended without a concrete consumer]** `auto_connect` helper (§3.2) — low value in Rust; skip unless something in this workspace or a downstream consumer actually wants the closure-based convenience wrapper.
20. **[M, needs a device/network path exercising a genuinely large file over stdin]** Extend `Stream::stream_file` to accept a reader (not just `&Path`) and add the CLI's `-` stdin special-case, plus port `MediaMetadata`/`override_missing_metadata` (§2.1) — bundle with item 6 if both land around the same time, since `atvscript` and `stream_file` share the same underlying `MediaMetadata` gap.

**Items needing live-device validation before considered "done," beyond what's marked inline above:** 1 (takeover — must be checked against a real overlapping AirPlay+MRP session, this is exactly the kind of interaction hermetic tests tend to miss), 2 (multi-speaker AirPlay-2 output-device volume, needs a HomePod/stereo-pair-capable setup), 3 (DMAP, needs a real gen 1–3 Apple TV or tvOS ≤12 device — per `docs/ROADMAP.md` Step 7 this is explicitly lowest priority and frozen upstream, so live validation may reasonably slip past Step 8), 13 (settings round-trip against a `.pyatv.conf` a real pairing produced).
