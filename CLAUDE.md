# pyatv-rs — agent working guide

This file is the entry point for any autonomous Claude Code session working in this repository. It is deliberately self-contained: assume you start with no memory of how the project got here. Read this file, then `docs/ARCHITECTURE.md`, then the specific research report under `docs/research/` for whatever you are about to touch. The research reports are the ground truth for wire formats — do not implement a protocol from memory.

## What this project is

A pure-Rust reimplementation of [pyatv](https://github.com/postlund/pyatv), the Python library for discovering, pairing with, and controlling Apple TV and AirPlay-compatible devices. The goal is behavioral parity with pyatv (a client/controller library — not a receiver) across its five wire protocols: MRP, Companion, AirPlay (1/2), RAOP audio, and legacy DMAP. Target: Rust 2024 edition, current stable toolchain.

pyatv is MIT-licensed, so reading and porting from its source is legally clean. Several other references (owntone, UxPlay, shairport-sync, rairplay) are GPL/LGPL — read them for behavioral truth only, never copy code. See `docs/research/prior-art.md` for the license map.

## Toolchain and environment — read before running anything

The development environment is defined by **devenv** (`devenv.nix`). The toolchain (Rust stable, currently 1.98.0 via the rust-overlay input) comes from `devenv.lock`, not from the host and not from `rust-toolchain.toml`.

- If you are running inside a `devenv shell`, `cargo`/`rustc` are already the correct pinned versions — just use them. Confirm with `rustc --version`.
- If you are NOT inside the devenv shell (e.g. the host has a different, older Rust), prefix every build command: `devenv shell -- bash -lc 'cd <repo> && cargo ...'`. The host toolchain may be older than what edition-2024 features require, so never run bare `cargo` unless you have confirmed the version.
- `rust-toolchain.toml` exists only for non-Nix contributors and CI using rustup; inside devenv it is ignored.
- Host caveat: `~/.config/nix/nix.conf` may contain a stale GitHub `access-tokens` entry that 401s cold Nix fetches. `devenv shell` works because the closure is already in the store, but `devenv update` / adding a new input may fail until that token is refreshed (`gh auth token`) or the line removed. This is a host issue, not a repo issue.

## The quality gate — non-negotiable

Before considering any change complete, the following must all pass (there is a `check` script in the devenv that runs the first three):

```
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features          # or: cargo test --workspace --all-features
cargo test --workspace --doc --all-features
```

`--all-features` matters for **single-crate runs**, not for the workspace run. `pyatv-pairing`'s `test-server` feature gates its reference HAP accessory and with it every end-to-end and negative-path pairing test, so `cargo test -p pyatv-pairing` without the flag silently skips them (130 + 2 + 8 tests instead of 130 + 15 + 8 + 5 + 2). A `--workspace` run picks the feature up either way, because `pyatv-proto-companion` dev-depends on `pyatv-pairing` with `features = ["test-server"]` and Cargo unifies features across the workspace — `cargo test --workspace` and `cargo test --workspace --all-features` currently run the same 794 tests. Keep the flag in the gate anyway: it is what makes the guarantee independent of one crate's dev-dependency list.

Warnings are errors. `missing_debug_implementations` and clippy `pedantic` are on at the workspace level (`[workspace.lints]`). Derive `Debug` on public types. Only add `#[allow(...)]` with a written justification comment. Git hooks (rustfmt + clippy) run on commit.

## Workspace shape

Virtual manifest at the root; members under `crates/` and `cli/`. Dependency direction is strict: **protocol crates depend on `pyatv-core`; `pyatv-core` depends on no protocol crate.** The umbrella `pyatv` crate is the only place that wires concrete protocols together.

- `pyatv-core` — public trait interfaces, enums, device/config/service models, `Relayer<T>`, `FacadeAppleTV`, `Storage` trait, the crate-wide `Error`. No protocol dependencies.
- `pyatv-mdns` — mDNS/DNS-SD discovery (multicast browse/resolve; unicast host-scan).
- `pyatv-pairing` — shared HAP crypto: TLV8, HKDF-SHA512, SRP6a (both profiles), Ed25519/X25519, the `HAPSession` ChaCha20-Poly1305 transport framing, credentials, and the legacy AirPlay AES-CTR/GCM path.
- `pyatv-opack` — Apple OPACK serializer/deserializer (hand-written; no crate exists).
- `pyatv-proto-mrp` — MediaRemote Protocol (protobuf + transport, direct and AirPlay-tunneled).
- `pyatv-proto-companion` — Companion link (frame header + OPACK + HAP pairing).
- `pyatv-proto-airplay` — AirPlay 1/2, RAOP audio, custom RTSP/HTTP-on-one-socket codec.
- `pyatv-proto-dmap` — legacy DMAP/DAAP.
- `pyatv` — umbrella: `scan()`/`pair()`/`connect()` and the curated public API.
- `cli/atvremote` — thin clap-based CLI, mirrors pyatv's `atvremote`.

Module-size rule: keep source files well under 500 LoC; split by responsibility before adding more. Follow the standards in the `rust-core-logic` skill (structured errors via `thiserror` in libraries, `Result` for expected failures, sans-io protocol cores where practical, no `unsafe` without a safety comment).

## Design invariants (the things easy to get subtly wrong)

These come straight from the research and are the highest-risk interop details. Read the cited report section before implementing.

- **Protocol relaying.** One `FacadeAppleTV` implements every public trait by delegating to a priority-ordered per-capability registry (`Relayer<T>`). Default priority `[MRP, DMAP, Companion, AirPlay, RAOP]`, with per-facade overrides (Power prefers Companion). Re-extract the current `FeatureName` set and priorities from pyatv `const.py`/`core/facade.py` at implementation time — they change every release. (`docs/research/pyatv-architecture.md`)
- **Modern tvOS tunnels MRP through AirPlay.** tvOS 15+ (build major ≥ 19) removed the standalone MRP port; MRP protobufs are carried inside an AirPlay 2 data-stream channel. Design `MrpTransport` as a trait with a direct-TCP impl and a tunnel impl sharing one state machine. (`docs/research/mrp-companion.md`)
- **HAP SRP M1 uses UNPADDED `H(g)`.** RustCrypto `srp`'s `process_reply()` hardcodes padded `g`; you must bypass it and call `srp::utils::compute_m1_rfc5054(..., g_no_pad = true, ...)` directly. This is the single biggest crypto interop gotcha. (`docs/research/crypto-pairing.md` §9)
- **Two different SRP profiles.** HAP: 3072-bit group, SHA-512, username `"Pair-Setup"`. Legacy AirPlay: 2048-bit group, SHA-1, and a non-standard doubled-hash session key `K = SHA1(S‖0x00000000) ‖ SHA1(S‖0x00000001)` with no crate support. Do not merge them. (`crypto-pairing.md` §2)
- **Three ChaCha20 nonce layouts.** Handshake TLV uses fixed ASCII nonces (`PV-Msg02/03`, `PS-Msg05/06`). HAPSession transport uses `4 zero bytes ‖ 8-byte LE counter`, per-direction counters, 1024-byte frame cap, AAD = the 2 length bytes. Companion uses a plain 12-byte LE counter (no zero prefix), 4-byte frame header as AAD. Parameterize by explicit zero-prefix width; do not share one function. (`crypto-pairing.md` §5)
- **Per-channel HKDF salt/info strings are all distinct** and listed verbatim in `crypto-pairing.md` §3. The AirPlay event channel swaps read/write info strings because the receiver opens that socket. Getting one backwards decrypts garbage in exactly one direction.
- **Legacy AirPlay quirks to replicate byte-for-byte:** the pair-setup IV last-byte `+1` increment, the opaque trailing blob encrypted alongside the signature, and reuse of the Ed25519 seed as the SRP client ephemeral. (`crypto-pairing.md` §5.4, §6)
- **Ports come from mDNS SRV records at scan time,** not hardcoded — except the fixed knock ports `3689, 7000, 49152, 32498` used to wake sleeping devices before a unicast scan. (`pyatv-architecture.md`)
- **Do not implement FairPlay** — pyatv only parses that a stream advertises it; there is no open implementation and it is out of scope. (`crypto-pairing.md` §5.5)
- **OPACK and Companion have zero Rust prior art** and OPACK has no public spec — pyatv's `opack.py` and its `atvproxy` MITM tool are the only ground truth. Round-trip test aggressively. (`prior-art.md`, `mrp-companion.md`)

## Validate against reality, not against pyatv's assumptions

pyatv has open, unresolved tvOS-26-era issues (AirPlay `play_url`, RTSP heartbeat desync, discovery flakiness) and its maintainer has flagged reduced bandwidth. Treat pyatv `master` as the spec-of-record but not as guaranteed-correct against the newest tvOS. Where a behavior matters, plan a capture-based known-answer test (pyatv's `atvproxy` is built for exactly this MITM capture) rather than trusting inherited behavior. Several pyatv pairing paths even have `# TODO` unverified-signature comments — decide deliberately whether to be stricter.

## Workflow conventions

- Branch names: `type/description` (e.g. `feat/mrp-direct-transport`, `chore/ci-cache`).
- Commits and PRs: human-written, descriptive, explain the what and why. No AI-tool attribution or session metadata anywhere in commit messages.
- Use `cargo add` / `cargo new` (the CLI) to manage packages and scaffold crates; don't hand-edit `[dependencies]` you could add via CLI.
- Prefer `bun` and `eza -T --git-ignore` where a JS runtime or a tree view is needed.
- Verify crate versions and API signatures against docs.rs / crates.io before use — the dependency landscape (especially `srp`, the `dalek` crates) moves fast and training data is stale.

## Where to look

- `docs/ARCHITECTURE.md` — the design decisions and rationale.
- `docs/ROADMAP.md` — phased implementation plan (this is step 0; step 1 is discovery + pairing).
- `docs/RISKS.md` — the risk register with mitigations.
- `docs/research/` — seven grounded deep-dives; `docs/research/README.md` indexes them.
