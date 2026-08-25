# pyatv-rs

A pure-Rust library and CLI for discovering, pairing with, and controlling Apple TV and AirPlay-compatible devices — a reimplementation of [pyatv](https://github.com/postlund/pyatv) targeting Rust 2024.

It is a **controller**, not a receiver: it drives an Apple TV, HomePod or AirPlay speaker the way a remote does. It does not accept incoming streams, does not do screen mirroring, and does not implement FairPlay DRM. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §1 for the full goals and non-goals.

## Relationship to pyatv

pyatv is the reference. It is MIT-licensed, so porting from its source is legally clean, and that is exactly what this project does: the wire formats, the facade-over-priority-relay design, the `scan()`/`pair()`/`connect()` entry points, the `Playing` output block, the `atvremote` command vocabulary and the `atvscript` JSON schema are all reproduced from pyatv rather than reinvented. Where behaviour is copied, the Rust source cites the upstream file and line.

Two consequences worth knowing up front:

- **Credentials interoperate.** Settings are stored in `$HOME/.pyatv.conf` — the same path, and the same bytes, that pyatv's own `FileStorage` writes. A device you paired with pyatv works here without re-pairing, and vice versa.
- **Deliberate divergences are documented, not silent.** This port verifies the accessory's SRP proof, the pair-setup M6 signature and the pair-verify M2 signature, all three of which pyatv skips (`docs/RISKS.md` M6). It corrects pyatv's vendored `AudioRoute.proto`, which silently drops now-playing metadata on tvOS 27 (`docs/RISKS.md` L12). It zero-pads DMAP pairing GUIDs, which pyatv does not — roughly one in sixteen of pyatv's own GUIDs fail its own login regex.

Prior art from GPL/LGPL projects (owntone, UxPlay, shairport-sync, rairplay) was read for behavioural truth only, never copied. The licence map is in [`docs/research/prior-art.md`](docs/research/prior-art.md).

## Status

Early but substantial: every protocol is implemented and the full quality gate is green, but not every path has met real hardware. Nothing here has been published to crates.io and there is no tagged release yet.

The live-verified work was done against one device — an Apple TV 4K (gen 3) running tvOS 27. "Hermetic" below means the code is covered by socket-level tests against an in-process fake device plus known-answer tests generated from pyatv, but has not been run against real hardware.

| Area | State |
|---|---|
| Discovery (mDNS/DNS-SD, multicast and unicast) | Live-verified |
| HAP pairing (SRP6a-3072, pair-setup and pair-verify, transport ciphers) | Live-verified |
| Companion (OPACK, pairing, apps, power, keyboard, touch, accounts) | Live-verified |
| AirPlay 2 control channel, event and data-stream channels | Live-verified |
| MRP over the AirPlay tunnel (now-playing, push updates) | Live-verified |
| MRP over direct TCP (pre-tvOS-15 devices) | Hermetic only |
| AirPlay `play_url` | Hermetic only — the live probe plays video, so it needs a human at the TV |
| RAOP audio streaming (`stream_file`) | Hermetic only — the live probe plays audio and changes volume |
| Legacy DMAP (Apple TV gen 1–3) | Hermetic only — no such device available to test against |
| Facade relaying, CLI parity, `--json` | In progress (Step 8) |

Known limitations on current tvOS, from the risk register:

- **Volume is unavailable over the MRP tunnel on tvOS 27.** No availability message arrives after bring-up, so volume features report `Unavailable` and Companion registers no audio interface (`docs/RISKS.md` L13).
- **AirPlay pair-setup shows no PIN on modern tvOS.** Companion pairing is the only pairing path; the AirPlay tunnel then authenticates with those same HAP credentials (`docs/RISKS.md` M7).

[`docs/ROADMAP.md`](docs/ROADMAP.md) is the authoritative, per-step status; [`docs/RISKS.md`](docs/RISKS.md) is the full risk register.

## Building

### With devenv (recommended)

The toolchain and every dev tool are pinned reproducibly by [devenv](https://devenv.sh), so you do not need a system Rust install and you cannot accidentally build against the wrong compiler.

```sh
devenv shell            # Rust stable, clippy, rustfmt, nextest, cargo-deny, cargo-hack, protoc

cargo build --workspace
cargo run -p atvremote -- --help
```

If you use direnv, `cd`-ing into the repository activates the environment automatically. From outside the shell, prefix commands so they use the pinned toolchain: `devenv shell -- bash -lc 'cargo build --workspace'`.

### With plain cargo

Rust 2024 edition, MSRV 1.88. There are no system dependencies to install: the MRP `.proto` corpus is vendored and compiled by `protox` rather than `protoc`, so the build is pure Rust and works offline.

```sh
cargo build --workspace
cargo install --path cli/atvremote     # installs the `atvremote` binary
```

## CLI quickstart

`atvremote` mirrors pyatv's tool of the same name. Find a device, pair once, then control it.

```sh
# 1. Find what is on the network.
atvremote scan
```

```
Scan Results
========================================
       Name: Living Room
   Model/SW: Apple TV 4K (gen 3), tvOS 27.0 build 25J123
    Address: 10.0.0.5
        MAC: AA:BB:CC:DD:EE:FF
 Deep Sleep: False
Identifiers:
 - 01234567-89AB-CDEF-0123-456789ABCDEF
Services:
 - Protocol: AirPlay, Port: 7000, Credentials: None, Requires Password: False, Password: None, Pairing: Mandatory
 - Protocol: Companion, Port: 49153, Credentials: None, Requires Password: False, Password: None, Pairing: Mandatory
```

```sh
# 2. Pair. On modern tvOS this is the pairing path — a PIN appears on the TV, type it in.
#    Credentials are written to $HOME/.pyatv.conf and reused by every later command.
atvremote --id 01234567-89AB-CDEF-0123-456789ABCDEF pair --protocol companion

# Non-interactively, if you can read the PIN some other way:
atvremote -n "Living Room" pair --protocol companion --pin 1234
```

```sh
# 3. Control it. --id or --name selects the device; both accept what `scan` printed.
atvremote -n "Living Room" playing
atvremote -n "Living Room" remote select
atvremote -n "Living Room" remote menu
atvremote -n "Living Room" remote up 1          # 0 tap, 1 double tap, 2 hold
atvremote -n "Living Room" remote set_position 90
atvremote -n "Living Room" app_list
atvremote -n "Living Room" launch_app com.netflix.Netflix
atvremote -n "Living Room" push_updates          # follow now-playing until interrupted
```

`atvremote commands` prints the full button vocabulary. Everything else — power, volume, output devices, keyboard, artwork, settings, `play_url`, `stream_file` — is its own subcommand; see `atvremote --help`.

### Machine-readable output

`--json` emits pyatv's `atvscript` schema, one object per line, instead of a second binary:

```sh
atvremote -n "Living Room" --json playing
```

```json
{
  "album": null, "app": "Netflix", "app_id": "com.netflix.Netflix",
  "artist": null, "content_identifier": null,
  "datetime": "2026-08-25T09:41:07.123456+00:00",
  "device_state": "playing", "episode_number": null, "genre": null,
  "hash": "azyFEzFpSNOSGq9ZvcaX4A", "itunes_store_identifier": null,
  "media_type": "video", "position": 312, "repeat": null, "result": "success",
  "season_number": null, "series_name": null, "shuffle": null,
  "title": "The Sea Beast", "total_time": 7135
}
```

That is shown formatted for readability; the real output is one object per line, flushed as it is produced, with keys in the alphabetical order above. Every `Playing` property is always present, `null` rather than omitted when unset. Commands `atvscript` does not have — `features`, `device_info`, `app_list` and the rest — get a key named after the command inside the same envelope.

## Library use

Depend on the `pyatv` crate — it is the only one applications need, and it re-exports the whole curated API.

```rust
use std::sync::Arc;
use std::time::Duration;

use pyatv::{InputAction, ScanOptions, Storage};

#[tokio::main]
async fn main() -> pyatv::Result<()> {
    // Credentials and settings live in $HOME/.pyatv.conf — the same file, and the same bytes,
    // that pyatv's own FileStorage reads and writes.
    let storage: Arc<dyn Storage> =
        Arc::new(pyatv::FileStorage::new(pyatv::FileStorage::default_path()?));
    storage.load()?;

    let devices = pyatv::scan(ScanOptions {
        timeout: Duration::from_secs(5),
        ..ScanOptions::default()
    })
    .await?;

    let Some(config) = devices.first() else {
        println!("no devices found");
        return Ok(());
    };
    println!("connecting to {} at {}", config.name, config.address);

    // `None` means "every protocol this device advertises that we can bring up".
    let atv = pyatv::connect(config, None, Arc::clone(&storage)).await?;

    if let Some(metadata) = atv.metadata() {
        println!("{}", metadata.playing().await?);
    }
    if let Some(remote) = atv.remote_control() {
        remote.select(InputAction::SingleTap).await?;
    }

    atv.close().await
}
```

Three things about that shape are load-bearing:

- **Capability accessors return `Option`.** `atv.metadata()`, `atv.apps()`, `atv.audio()` and the rest are `None` when no connected protocol provides that capability at all. `Error::NotSupported` is reserved for per-method gaps. This is a deliberate deviation from pyatv, which always hands back an object and raises at call time.
- **A protocol that fails to connect is skipped, not fatal.** A device with working AirPlay but unpaired Companion still gives you video streaming. `connect()` only fails when nothing connected.
- **`connect()` does not start push updates.** Set a listener on `atv.push_updater()` and call `start(0)`, exactly as upstream requires.

Pairing from a library is the same three-step handler the CLI drives:

```rust
let handler = pyatv::pair(config, pyatv::Protocol::Companion, Arc::clone(&storage)).await?;
handler.begin().await?;
handler.pin(1234)?;            // the code shown on the TV
handler.finish().await?;       // credentials land in storage on success
```

`pyatv::helpers::auto_connect` collapses scan-connect-use-close into one call when you are just trying things out.

## Where credentials are stored

`$HOME/.pyatv.conf` (`%USERPROFILE%\.pyatv.conf` on Windows) — a JSON document, byte-compatible with pyatv's. It holds per-device settings and the HAP credentials produced by pairing.

- `atvremote --storage-filename <path>` points at a different file.
- `atvremote --storage none` keeps everything in memory and touches no disk.
- `atvremote print_settings`, `change_setting`, `unset_setting` and `remove_settings` inspect and edit it.
- In a library, pass any `Arc<dyn Storage>`: `FileStorage` for the on-disk format, `MemoryStorage` for tests, or your own implementation.

The file contains long-term private keys. Treat it like an SSH key.

## Workspace layout

```
crates/
  pyatv-core          traits, enums, models, facade + relayer, storage, errors
  pyatv-mdns          mDNS/DNS-SD discovery
  pyatv-pairing       HAP crypto: SRP, TLV8, HKDF, sessions, credentials
  pyatv-opack         Apple OPACK serializer/deserializer
  pyatv-proto-mrp     MediaRemote Protocol (direct + AirPlay-tunneled)
  pyatv-proto-companion   Companion link + OPACK services
  pyatv-proto-airplay AirPlay 1/2, RAOP audio, RTSP/HTTP codec
  pyatv-proto-dmap    legacy DMAP/DAAP
  pyatv               umbrella: scan/pair/connect + the public API
cli/
  atvremote           command-line client
docs/
  ARCHITECTURE.md ROADMAP.md RISKS.md research/
```

The dependency direction is strict: protocol crates depend on `pyatv-core`, `pyatv-core` depends on no protocol crate, and only the `pyatv` umbrella knows about more than one protocol at a time.

## Contributing

The quality gate is not advisory. Warnings are errors, clippy runs at `pedantic`, and nothing merges without all five of these green:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo test --workspace --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

Inside the devenv shell, `check` runs all five in one command, and CI runs the identical script so the two cannot drift. Three slower checks — `check-features` (feature powerset), `check-msrv`, and `cargo deny check` — have their own scripts and should be run when you touch dependencies, feature flags or a public API.

Beyond that, the one rule that matters most: **do not implement a protocol from memory.** Every wire format here is grounded in a research report under `docs/research/`, each written against live sources and citing pyatv by file and line. Read the relevant report before touching a codec, and add a known-answer test rather than trusting inherited behaviour. `CLAUDE.md` is the working guide and carries the crypto invariants that are easiest to get subtly wrong.

Branch names follow `type/description`. Commit messages and PR bodies should explain the what and the why in prose.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design decisions and rationale: the facade/relayer model, crate decomposition, sans-io cores, why not `reqwest`/`hyper`, testing strategy.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — the phased plan and per-step delivery status.
- [`docs/RISKS.md`](docs/RISKS.md) — the risk register, including every known live-hardware finding.
- [`docs/research/README.md`](docs/research/README.md) — the indexed research corpus: seventeen wire-level and ecosystem deep-dives that are the ground truth for every protocol here.
- `CLAUDE.md` — the working guide for contributors and autonomous agents.

## License

MIT. See [`LICENSE`](LICENSE). This matches pyatv, from which this project is ported.

## Acknowledgements

This project stands on the reverse-engineering work of [pyatv](https://github.com/postlund/pyatv) and its maintainer Pierre Ståhl, and on the broader open AirPlay/HomeKit community. It is not affiliated with, authorized by, or endorsed by Apple. Apple TV, AirPlay, HomePod and HomeKit are trademarks of Apple Inc.
