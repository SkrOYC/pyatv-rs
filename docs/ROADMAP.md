# Roadmap

Phased implementation plan. Steps 0-8 are delivered. An Apple TV 4K running tvOS 27 has exercised the modern-device paths, including the completed facade and CLI. The media-streaming probes reached shared pyatv and tvOS compatibility failures rather than Rust-specific failures. See `docs/research/live-parity-validation-2026-08-25.md` for the evidence and scope.

The guiding sequence mirrors how you actually bring an Apple TV under control: find it (discovery), prove who you are (pairing), then speak each protocol. Discovery and pairing are foundational and unlock everything else, so they come first.

## Step 0 — Foundation (this repo) ✅

Repository, reproducible devenv toolchain, Cargo workspace with all crates scaffolded and compiling under the quality gate, CI, and the full research corpus. Delivered:

- devenv environment (`devenv.nix`) providing pinned Rust stable, rustfmt/clippy/rust-analyzer, cargo-nextest, cargo-deny, protoc, git hooks, and a `check` quality-gate script.
- Virtual workspace: `pyatv-core`, `pyatv-mdns`, `pyatv-pairing`, `pyatv-opack`, `pyatv-proto-{mrp,companion,airplay,dmap}`, `pyatv` umbrella, `cli/atvremote`.
- Config: `rustfmt.toml`, `rust-toolchain.toml`, `deny.toml`, `.config/nextest.toml`, `.github/workflows/ci.yml`.
- `docs/research/` — seven grounded deep-dives; `docs/ARCHITECTURE.md`; `docs/RISKS.md`; this roadmap; `CLAUDE.md`.

## Step 1 — Discovery ✅

Delivered on `feat/discovery` (commits c0addfb..069bf0a). Spec of record: `docs/research/discovery-port-spec.md` (line-cited against pyatv `b277a4c`). Verified against a real Apple TV 4K (gen 3, tvOS 27.0) over both multicast and unicast paths. Decision taken: port pyatv's own hand-written mDNS stack (codec + unicast/multicast scanners) instead of wrapping `mdns-sd` — see `docs/ARCHITECTURE.md`. Landed so far: the sans-io DNS codec (`pyatv_mdns::dns`), the core config/service models with pyatv's exact merge and priority rules, the device-model/version lookup tables, and the AirPlay feature/status-flag parsers (`pyatv_core::{device_info,airplay}`).

Make `scan()` real. Multicast mDNS browse/resolve of all service types in `pyatv-mdns`, parsing the TXT records into device models (the AirPlay 64-bit feature/status flags, model identifiers, OS/build version for the tvOS-15 gating heuristic). Populate `pyatv-core`'s config/service models and the `DeviceInfo` trait. Unicast host-scan and the sleeping-device "knock" (ports 3689/7000/49152/32498) can be a follow-up within this phase. Deliverable: `atvremote scan` lists real devices on the LAN with correct identifiers, model, and advertised protocols. (`docs/research/pyatv-architecture.md`, `docs/research/airplay-raop-dmap.md`)

## Step 2 — HAP pairing core ✅

Delivered on `feat/hap-pairing` (commits 7893ceb..48ecfd5): the full HAP client core with pyatv-generated cross-implementation KATs, transport ciphers, legacy AirPlay auth, and `atvremote pair --protocol airplay` over HTTP verified live up to the PIN prompt (the device answers `/pair-pin-start` and M1 → M2). Closed live via Step 3: the same HAP core paired over Companion with an on-screen PIN (device key identical to pyatv's own pairing), and the resulting credentials pass AirPlay `/pair-verify` on port 7000 with strict proof and signature checks. AirPlay pair-setup itself shows no PIN on this device (RISKS M7). Spec of record: `docs/research/hap-pairing-port-spec.md`; crate APIs re-verified in `docs/research/crate-verification-2026-08-24.md`. Decisions: verify the accessory SRP proof, the M6 / pair-verify signatures and the final state TLV (pyatv skips all three — see RISKS M6); hermetic client↔server tests are built on a port of pyatv's `server_auth.py` behind the `test-server` feature; the three ChaCha20 nonce layouts are one type parameterised by an explicit zero-prefix width.

Implement `pyatv-pairing` end to end for the HAP profile: TLV8 codec, HKDF-SHA512 derivations, SRP6a-3072/SHA-512 with the unpadded-`H(g)` M1 fix, Ed25519/X25519 identities, pair-setup (M1–M6) and pair-verify (M1–M4), the `HAPSession` ChaCha20-Poly1305 transport framing, and `HapCredentials` persistence. Validate with known-answer tests from `atvproxy` captures before any device work. This is the highest-risk phase; treat the crypto invariants in `CLAUDE.md` as law. Deliverable: a successful pair + encrypted-session handshake against a real device (initially over whichever protocol is simplest to reach). (`docs/research/crypto-pairing.md`, `docs/research/mrp-companion.md`)

## Step 3 — Companion protocol ✅

Delivered on `feat/companion`. Live validation against the Apple TV 4K on tvOS 27 covers pairing, re-pairing, credential revocation, app queries and launch, device information, power, remote buttons, touch gestures, text input, accounts, and output-device queries. The encrypted session and every tested facade path completed successfully. tvOS continues to reject `_sessionStop` with `Session not found`; the client ignores this cleanup error as pyatv does. The wire-format specification remains `docs/research/companion-port-spec.md`.

`pyatv-opack` (serializer/deserializer with aggressive round-trip tests) plus `pyatv-proto-companion`: the 4-byte frame header, OPACK payloads, Companion's distinct 12-byte-counter ChaCha20 nonce layout, and the Companion services (app launch/list, keyboard, touch gestures, power, media). Companion is chosen before MRP because it does not require the AirPlay tunnel and exercises pairing + OPACK + the facade wiring in one comparatively self-contained protocol. Deliverable: `atvremote` can launch apps and send remote-control input via Companion. (`docs/research/mrp-companion.md`)

## Step 4 — AirPlay 2 control channel + MRP tunnel + MRP ✅

Reordered from the original plan: on tvOS 15 and later, MRP uses the AirPlay 2 remote-control tunnel. The tvOS 27 device confirmed that Companion HAP credentials authenticate the tunnel without an AirPlay PIN. The delivered tunnel returns now-playing metadata, carries push updates and playback controls, and stays open with two-second feedback requests. Hardware also established that inbound HAP blocks can exceed 8.9 kB (L11), the vendored pyatv `AudioRoute.proto` is wrong for tvOS 27 (L12), and volume availability changes with playback state (L13). The specification remains `docs/research/airplay-control-mrp-tunnel-port-spec.md`.

`pyatv-proto-mrp`: vendor pyatv's `.proto` files, spike prost/protox against the proto2 extension layout (fall back to `rust-protobuf` if extensions don't compile), implement the varint-length-prefixed protobuf framing and the MRP state machine behind the `MrpTransport` trait, first over **direct TCP** (older devices), then over the **AirPlay 2 data-stream tunnel** for tvOS 15+. This is the richest metadata/now-playing source and the default top-priority protocol in the facade. Deliverable: live now-playing metadata and push updates. (`docs/research/mrp-companion.md`)

## Step 5 — AirPlay `play_url` ✅ (live-probed; shared tvOS failure)

Delivered in a5e2202 (`pyatv_proto_airplay::stream`): AirPlay 1 and 2 flows with pyatv-extracted golden bodies and socket-level tests. The live AirPlay 2 probe completed authentication and setup, honored `skipRecord=true`, and received `200 OK` from `/play`. tvOS then returned `500 Internal Server Error` to the first `/playback-info` request without fetching either a public or LAN-hosted file. This matches the upstream pyatv regression on tvOS 26 and later. The AirPlay 1 control timed out during pair-verify on this AirPlay 2 device. See `docs/research/live-parity-validation-2026-08-25.md`.

`pyatv-proto-airplay`: the custom RTSP/HTTP-on-one-socket codec, the auth flavors (legacy device-auth, HAP transient, HAP normal — gated by the mDNS feature/status flags), the event and data-stream channels, and `play_url` streaming of a URL to the device. This phase also delivers the AirPlay side of the MRP tunnel that Step 4 rides on, so there is a dependency/ordering nuance: the tunnel transport itself belongs here even though MRP messages ride it. Deliverable: `atvremote play_url` works; AirPlay-tunneled MRP is available to modern devices. (`docs/research/airplay-raop-dmap.md`)

## Step 6 — RAOP audio streaming ✅ (live-probed; shared tvOS failure)

Delivered in a5e2202 (`pyatv_proto_airplay::{raop,audio}`): both generations, RTP, AEAD, synchronization, and timing packets are pinned by 16 pyatv-generated known-answer tests. The decoder produces 44.1 kHz, signed 16-bit stereo PCM, which matches pyatv. A live tvOS 27 run completed HAP authentication and the event-channel setup, then timed out waiting for the audio-stream `SETUP` response. pyatv `0.18.0` failed at the same request with the same credentials and WAV. The AirPlay 1 branch reached `ANNOUNCE`, where this device closed the connection. See `docs/research/live-parity-validation-2026-08-25.md`.

The implementation includes RTSP session control, RTP audio packetization, timing and control channels, metadata, artwork, progress, and volume. ALAC encoding is not required for pyatv parity because pyatv always sends PCM. The remaining interoperability work is to capture a successful Apple sender and identify the tvOS 27 audio-stream setup change.

## Step 7 — Legacy DMAP ✅ (hermetic; no gen 1–3 device available)

Delivered in 3d17a46 (`pyatv-proto-dmap`, `pyatv_mdns::publish`): tag table, codec, DaapRequester with pyatv's retry ladder, client and facade traits, client-as-server pairing with the MD5 code pinned by known-answer vectors, and a minimal RFC 6762 responder for `_touch-remote._tcp`. Divergence: pairing GUIDs are zero-padded (pyatv's are not, and ~1 in 16 fail its own login regex). Spec: `docs/research/dmap-port-spec.md`.

`pyatv-proto-dmap`: HTTP + Home Sharing pairing (pairing GUID), DMAP tag encoding, and long-poll push updates, for Apple TV gen 1–3 / tvOS ≤ 12. Lowest priority — it is legacy and frozen upstream — but included for parity. Deliverable: control and metadata for a legacy device. (`docs/research/airplay-raop-dmap.md`)

## Step 8 — Facade completion, CLI parity, hardening ✅

Gap analysis: `docs/research/step8-parity-gap-analysis.md`. Delivered in 3d17a46, fc5a6db and 201bcb8: per-method relaying with takeover/release, `FacadePushUpdater` through the trait object, listener hubs that filter on each relayer's current main protocol, `atvremote` at command parity (38 subcommands, 30 buttons, `--json` in the `atvscript` envelope), rustdoc/feature-powerset/MSRV/deny/bench gates, five criterion benches, and a user-facing README. The independent review caught two blockers (responder multicast bind — RISKS L14; uncapped chunked-body buffers in DMAP) which are fixed and pinned by tests.

Outcome: every protocol is wired into `FacadeAppleTV`; per-method relaying and takeover match pyatv; the CLI has command and JSON-envelope parity; and the documentation, feature-power checks, MSRV check, dependency policy, and benchmarks are in place. The live tvOS 27 pass establishes practical parity for the modern-device capabilities that the available hardware can exercise.

## Cross-cutting, every phase

- No phase merges without the full quality gate green.
- Every codec/crypto layer ships with round-trip property tests and, where a real exchange exists, `atvproxy`-captured known-answer tests.
- Re-verify crate versions and pyatv `master` behavior at the start of each phase — both move, and this plan was written against a 2026-08 snapshot.
- Keep `docs/RISKS.md` current: close risks as they are retired, add new ones as reverse-engineering surfaces them.
