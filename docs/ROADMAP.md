# Roadmap

Phased implementation plan. This repository is at the end of **Step 0**. Each phase below is sized to land as a reviewable unit with its own passing quality gate, and each names the research report(s) that carry the wire-level detail. Phases are ordered so that every phase produces something testable end-to-end against a real device as early as possible.

The guiding sequence mirrors how you actually bring an Apple TV under control: find it (discovery), prove who you are (pairing), then speak each protocol. Discovery and pairing are foundational and unlock everything else, so they come first.

## Step 0 — Foundation (this repo) ✅

Repository, reproducible devenv toolchain, Cargo workspace with all crates scaffolded and compiling under the quality gate, CI, and the full research corpus. Delivered:

- devenv environment (`devenv.nix`) providing pinned Rust stable, rustfmt/clippy/rust-analyzer, cargo-nextest, cargo-deny, protoc, git hooks, and a `check` quality-gate script.
- Virtual workspace: `pyatv-core`, `pyatv-mdns`, `pyatv-pairing`, `pyatv-opack`, `pyatv-proto-{mrp,companion,airplay,dmap}`, `pyatv` umbrella, `cli/atvremote`.
- Config: `rustfmt.toml`, `rust-toolchain.toml`, `deny.toml`, `.config/nextest.toml`, `.github/workflows/ci.yml`.
- `docs/research/` — seven grounded deep-dives; `docs/ARCHITECTURE.md`; `docs/RISKS.md`; this roadmap; `CLAUDE.md`.

## Step 1 — Discovery (in progress, branch `feat/discovery`)

Spec of record: `docs/research/discovery-port-spec.md` (line-cited against pyatv `b277a4c`). Decision taken: port pyatv's own hand-written mDNS stack (codec + unicast/multicast scanners) instead of wrapping `mdns-sd` — see `docs/ARCHITECTURE.md`. Landed so far: the sans-io DNS codec (`pyatv_mdns::dns`), the core config/service models with pyatv's exact merge and priority rules, the device-model/version lookup tables, and the AirPlay feature/status-flag parsers (`pyatv_core::{device_info,airplay}`).

Make `scan()` real. Multicast mDNS browse/resolve of all service types in `pyatv-mdns`, parsing the TXT records into device models (the AirPlay 64-bit feature/status flags, model identifiers, OS/build version for the tvOS-15 gating heuristic). Populate `pyatv-core`'s config/service models and the `DeviceInfo` trait. Unicast host-scan and the sleeping-device "knock" (ports 3689/7000/49152/32498) can be a follow-up within this phase. Deliverable: `atvremote scan` lists real devices on the LAN with correct identifiers, model, and advertised protocols. (`docs/research/pyatv-architecture.md`, `docs/research/airplay-raop-dmap.md`)

## Step 2 — HAP pairing core

Implement `pyatv-pairing` end to end for the HAP profile: TLV8 codec, HKDF-SHA512 derivations, SRP6a-3072/SHA-512 with the unpadded-`H(g)` M1 fix, Ed25519/X25519 identities, pair-setup (M1–M6) and pair-verify (M1–M4), the `HAPSession` ChaCha20-Poly1305 transport framing, and `HapCredentials` persistence. Validate with known-answer tests from `atvproxy` captures before any device work. This is the highest-risk phase; treat the crypto invariants in `CLAUDE.md` as law. Deliverable: a successful pair + encrypted-session handshake against a real device (initially over whichever protocol is simplest to reach). (`docs/research/crypto-pairing.md`, `docs/research/mrp-companion.md`)

## Step 3 — Companion protocol

`pyatv-opack` (serializer/deserializer with aggressive round-trip tests) plus `pyatv-proto-companion`: the 4-byte frame header, OPACK payloads, Companion's distinct 12-byte-counter ChaCha20 nonce layout, and the Companion services (app launch/list, keyboard, touch gestures, power, media). Companion is chosen before MRP because it does not require the AirPlay tunnel and exercises pairing + OPACK + the facade wiring in one comparatively self-contained protocol. Deliverable: `atvremote` can launch apps and send remote-control input via Companion. (`docs/research/mrp-companion.md`)

## Step 4 — MRP

`pyatv-proto-mrp`: vendor pyatv's `.proto` files, spike prost/protox against the proto2 extension layout (fall back to `rust-protobuf` if extensions don't compile), implement the varint-length-prefixed protobuf framing and the MRP state machine behind the `MrpTransport` trait, first over **direct TCP** (older devices), then over the **AirPlay 2 data-stream tunnel** for tvOS 15+. This is the richest metadata/now-playing source and the default top-priority protocol in the facade. Deliverable: live now-playing metadata and push updates. (`docs/research/mrp-companion.md`)

## Step 5 — AirPlay control + play_url

`pyatv-proto-airplay`: the custom RTSP/HTTP-on-one-socket codec, the auth flavors (legacy device-auth, HAP transient, HAP normal — gated by the mDNS feature/status flags), the event and data-stream channels, and `play_url` streaming of a URL to the device. This phase also delivers the AirPlay side of the MRP tunnel that Step 4 rides on, so there is a dependency/ordering nuance: the tunnel transport itself belongs here even though MRP messages ride it. Deliverable: `atvremote play_url` works; AirPlay-tunneled MRP is available to modern devices. (`docs/research/airplay-raop-dmap.md`)

## Step 6 — RAOP audio streaming

The RAOP sender in `pyatv-proto-airplay` (or a dedicated `pyatv-proto-raop` if it grows): RTSP ANNOUNCE/SETUP/RECORD/SET_PARAMETER/FLUSH/TEARDOWN, RTP audio packetization, timing/control UDP channels, metadata/artwork/progress, and volume. Decode input media with `symphonia`, resample with `rubato`. **Open question to resolve first:** whether current devices need ALAC encoding or accept raw PCM (L16) — pyatv's SDP template suggests PCM; confirm with a live capture before pulling in an ALAC encoder. Deliverable: `atvremote stream_file` plays local audio to a device. (`docs/research/airplay-raop-dmap.md`, `docs/research/rust-crates.md`)

## Step 7 — Legacy DMAP

`pyatv-proto-dmap`: HTTP + Home Sharing pairing (pairing GUID), DMAP tag encoding, and long-poll push updates, for Apple TV gen 1–3 / tvOS ≤ 12. Lowest priority — it is legacy and frozen upstream — but included for parity. Deliverable: control and metadata for a legacy device. (`docs/research/airplay-raop-dmap.md`)

## Step 8 — Facade completion, CLI parity, hardening

Wire every protocol into `FacadeAppleTV`, finalize the `Relayer` priorities and per-capability overrides against current pyatv source, complete `atvremote` command coverage (and consider an `atvscript`-equivalent JSON mode), tighten `cargo-deny` bans to `deny`, run `cargo hack` feature-powerset checks, add `criterion` benchmarks for the hot codec/audio paths, and write user-facing docs. Deliverable: a coherent library + CLI at rough feature parity with pyatv for supported devices.

## Cross-cutting, every phase

- No phase merges without the full quality gate green.
- Every codec/crypto layer ships with round-trip property tests and, where a real exchange exists, `atvproxy`-captured known-answer tests.
- Re-verify crate versions and pyatv `master` behavior at the start of each phase — both move, and this plan was written against a 2026-08 snapshot.
- Keep `docs/RISKS.md` current: close risks as they are retired, add new ones as reverse-engineering surfaces them.
