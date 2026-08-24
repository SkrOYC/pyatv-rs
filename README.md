# pyatv-rs

A pure-Rust library and CLI for discovering, pairing with, and controlling Apple TV and AirPlay-compatible devices — a reimplementation of [pyatv](https://github.com/postlund/pyatv) targeting Rust 2024.

> **Status: Step 0 (foundation).** The repository, toolchain, workspace, CI, and the full protocol research corpus are in place. Protocol implementation begins at Step 1. See `docs/ROADMAP.md`.

## What it does (target scope)

Client/controller functionality across the protocols a modern Apple TV / HomePod speaks:

- **Discovery** of devices on the local network (mDNS/DNS-SD).
- **Pairing** via HAP (HomeKit) SRP and legacy AirPlay device-auth.
- **Control** — remote input, power, now-playing metadata and push updates, app launch, keyboard, touch gestures.
- **Streaming** — `play_url` and RAOP audio.

Across five wire protocols: MRP, Companion, AirPlay (1/2), RAOP, and legacy DMAP. It is a controller, not a receiver, and does not implement FairPlay DRM. See `docs/ARCHITECTURE.md` for the design and non-goals.

## Getting started (development)

The toolchain and all dev tooling are provided reproducibly by [devenv](https://devenv.sh); you do not need a system Rust install.

```sh
# Enter the reproducible dev shell (Rust stable, clippy, rustfmt, nextest, cargo-deny, protoc, ...).
devenv shell

# Inside the shell — build and run the quality gate.
cargo build --workspace
check            # cargo fmt --check && clippy -D warnings && nextest run

# Try the CLI.
cargo run -p atvremote -- --help
```

If you use direnv, `cd` into the repo auto-activates the environment. Outside the devenv shell, prefix cargo commands with `devenv shell -- bash -lc '...'` so they use the pinned toolchain rather than any system Rust.

## Layout

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
  pyatv               umbrella: scan/pair/connect + public API
cli/
  atvremote           command-line client
docs/
  ARCHITECTURE.md ROADMAP.md RISKS.md research/
```

## Documentation

- `CLAUDE.md` — working guide for autonomous agents (start here if you are one).
- `docs/ARCHITECTURE.md` — design decisions and rationale.
- `docs/ROADMAP.md` — phased implementation plan.
- `docs/RISKS.md` — risk register with mitigations.
- `docs/research/` — seven grounded protocol/ecosystem deep-dives (`docs/research/README.md` indexes them).

## License

MIT, matching pyatv. Prior-art from GPL/LGPL projects was studied for behavioral truth only, never copied — see `docs/research/prior-art.md`.

## Acknowledgements

This project stands on the reverse-engineering work of [pyatv](https://github.com/postlund/pyatv) and the broader open AirPlay/HomeKit community. It is not affiliated with or endorsed by Apple.
