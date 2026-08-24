# Architecture

This document records the design decisions for pyatv-rs and the reasoning behind them. It is the synthesis of the seven research reports under `docs/research/`; where a claim needs a wire-level citation, it points there. It should be read after the root `CLAUDE.md` and before touching any crate.

## 1. Goals and non-goals

**Goal:** behavioral parity with pyatv as a *client/controller* library — discover devices on the LAN, pair with them, and control playback, power, apps, keyboard, and audio streaming across the protocols a modern Apple TV / HomePod speaks. Embeddable as a library (for a future GUI, Home Assistant integration, etc.) with a thin CLI on top, mirroring how pyatv ships a library plus `atvremote`.

**Non-goals (for now):** acting as an AirPlay *receiver* (accepting streams / screen mirroring / video decode — a materially different problem, and pyatv itself does not do it); implementing FairPlay DRM (no open implementation exists, depends on Apple hardware key material, and pyatv only *parses* its advertisement); byte-for-byte reuse of any GPL/LGPL reference implementation.

## 2. The unifying model: facade over a priority relay

pyatv presents one object that implements every capability, and internally routes each capability call to whichever connected protocol can best serve it. We mirror this exactly because it is the core of the library's value.

- The public API is a set of **traits** in `pyatv-core` (`RemoteControl`, `Metadata`, `PushUpdater`, `Stream`, `Power`, `Apps`, `Audio`, `Keyboard`, `TouchGestures`, `UserAccounts`, `Features`) — the Rust analogue of pyatv's `interface.py` ABCs — plus `DeviceInfo` as a plain data struct (faithful to pyatv, where device info is data rather than an ABC). Facade accessors return `Option<Arc<dyn Trait>>`, absent when no connected protocol provides the capability, with `Error::NotSupported` reserved for per-method gaps — a deliberate, more idiomatic deviation from pyatv, which always hands back a facade and raises `NotSupportedError` at call time.
- `FacadeAppleTV` is a single struct that implements all of those traits. Each trait implementation delegates through a **`Relayer<T>`**: a generic, priority-ordered registry that returns the first protocol implementation (in priority order) that supports the requested method.
- Default priority is `[MRP, DMAP, Companion, AirPlay, RAOP]`, with per-capability overrides (e.g. `Power` prefers Companion). These, and the full `FeatureName` enum, **must be re-extracted from pyatv `const.py` / `core/facade.py` at implementation time** — they grow every release (Guide/ControlCenter were added in 0.17.0). See `docs/research/pyatv-architecture.md`.
- Each protocol module contributes a `SetupData`-equivalent (protocol id, connect/close callables, device info, the set of interfaces it implements, and its supported `FeatureName`s), which is registered into the facade's per-capability relayers at connect time. `pyatv-core` defines the shape; the umbrella `pyatv` crate does the wiring so that `pyatv-core` never depends on a concrete protocol crate.

**Push updates** are delivered as a single authoritative stream per capability (fed only by the "main instance" protocol for that capability), not a naive merge of callbacks from every connected protocol — mirroring pyatv's `FacadePushUpdater`. In Rust this is a `tokio::sync::broadcast` (or `mpsc`) channel owned by the facade.

## 3. Crate decomposition and dependency direction

A virtual Cargo workspace. The hard rule is the dependency direction: **protocol crates depend on `pyatv-core`; `pyatv-core` depends on no protocol crate.** This keeps the public API and the facade free of protocol-specific types and lets the umbrella crate be the single composition root.

```
pyatv-core   ← foundation: traits, enums, models, Relayer, FacadeAppleTV, Storage, Error
   ▲  ▲  ▲
   │  │  └───────────── pyatv-mdns        (discovery)
   │  └──────────────── pyatv-pairing     (HAP crypto; depends on core)
   │                        ▲
   │                        │  pyatv-opack (OPACK; light deps)
   │                        │     ▲
   ├── pyatv-proto-mrp ─────┤     │
   ├── pyatv-proto-companion ─────┘  (mrp/companion depend on pairing; companion also on opack)
   ├── pyatv-proto-airplay ─┘
   └── pyatv-proto-dmap
                    ▲
                    │
   pyatv (umbrella) ┘  ← depends on core + mdns + every protocol crate; owns scan/pair/connect + public re-exports
                    ▲
   cli/atvremote ───┘  ← depends only on the pyatv umbrella
```

Rationale for the split: `pyatv-core` is the stable API boundary; the protocol crates can be developed, tested, and feature-gated independently; `pyatv-pairing` and `pyatv-opack` are shared crypto/serialization primitives with the highest test-value and the highest interop risk, so they earn their own crates with focused test suites. The CLI stays thin so all logic remains embeddable.

Protocols will additionally be exposed as Cargo features on the umbrella crate (`mrp`, `companion`, `airplay`, `raop`, `dmap`) so a consumer can build a slim binary; `cargo hack --each-feature` in CI guards against accidental cross-feature coupling.

## 4. Sans-io protocol cores

Where practical, each protocol's framing and state machine is written as plain synchronous Rust (no tokio types) — a "sans-io" core — with a thin tokio I/O adapter layered on top. This is the recommendation from `docs/research/rust-crates.md` and it matters here because these protocols are exactly the kind of thing that is painful to test through real sockets: byte-level framing, nonce counters, pairing state machines. A sans-io core is driven by feeding it bytes and reading out frames, which makes known-answer tests against captured device traffic (see §7) straightforward and deterministic. The adapter owns the `TcpStream`/`UdpSocket`, the tokio codec, and the timers.

Concretely: `MrpTransport` is a trait so the same MRP message state machine runs over both the direct-TCP varint-framed transport and the AirPlay-tunneled plist-framed transport (`docs/research/mrp-companion.md`). The HAP session framing, the OPACK codec, the TLV8 codec, and the RTSP/HTTP codec are all sans-io.

## 5. Networking: why not reqwest/hyper

AirPlay speaks a non-standard HTTP/RTSP dialect over a single socket with reverse connections and an event channel — a client and server role on the same connection. Off-the-shelf HTTP clients cannot model that. The AirPlay crate therefore implements a custom `tokio_util::codec` `Decoder`/`Encoder` that parses both requests and responses on one socket, buffers on `Content-Length` (partial frame → `Ok(None)`), and hands binary-plist bodies up as opaque `Bytes` for the `plist` crate to decode. See `docs/research/airplay-raop-dmap.md` and `docs/research/rust-crates.md` §5.

Discovery uses `mdns-sd` for multicast browse/resolve of `_mediaremotetv._tcp`, `_companion-link._tcp`, `_airplay._tcp`, `_raop._tcp`, and the DMAP service types. Unicast host scanning (querying a specific IP, used to wake and probe a known device) is **not** covered by `mdns-sd` and needs a small hand-rolled DNS codec (optionally over `hickory-proto` wire types) — tracked as a `pyatv-mdns` sub-task, not a blocker for multicast discovery.

## 6. Cryptography and pairing

All HAP-based protocols (MRP, Companion, modern AirPlay) share one pairing engine in `pyatv-pairing`, built on the RustCrypto stack (`sha2`, `sha1`, `hkdf`, `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `aes`, `ctr`, `aes-gcm`, `srp`). The exact primitives, parameters, salt/info strings, nonce constructions, and credential formats are documented byte-for-byte in `docs/research/crypto-pairing.md`; the design invariants that are easiest to get wrong are enumerated in `CLAUDE.md` and must not be paraphrased from memory.

The one structural decision worth recording here: RustCrypto `srp`'s high-level `Client::process_reply()` cannot be used for HAP pairing because it hardcodes padded `H(g)` in the M1 proof while HAP needs the unpadded form. The integration strategy is to call `srp`'s public low-level building blocks (`compute_premaster_secret`, `compute_u_padded`, `compute_k`, and `srp::utils::compute_m1_rfc5054(..., g_no_pad = true, ...)`) directly, replicating the ~15 lines of `process_reply()` with that one flag flipped — no fork required. The legacy AirPlay profile's doubled-SHA1 session key and AES-CTR/GCM device-auth path have no crate support and are composed manually from `srp`'s premaster-secret primitive. `srp` may still be a `0.7.0` release candidate at implementation time; pin the exact validated version and back it with known-answer tests before trusting it against hardware.

`TLV8` is hand-rolled (≈30 lines) rather than taking an unvetted single-author dependency. `OPACK` is hand-rolled because no crate exists and the format is Apple-undocumented.

## 7. Testing and validation strategy

- **Unit tests** live beside the code (`#[cfg(test)]`); **integration tests** exercise public APIs from `tests/`.
- **Round-trip property tests** (`proptest`) for every codec: TLV8, OPACK, MRP varint framing, HAP session framing, RTSP.
- **Known-answer tests against captured device traffic** are the load-bearing validation for the crypto and framing layers. pyatv's `atvproxy` is a MITM tool built precisely to capture these exchanges (fake mDNS device, per-hop re-encryption, plaintext logging, hardcoded PIN 1111); capture fixtures with it and assert byte-exact behavior. This is how we avoid inheriting pyatv's own unverified paths and how we validate against a real tvOS 26.x device rather than against pyatv's assumptions.
- **Snapshot tests** (`insta`) for stable structured output (e.g. parsed device metadata) against captured fixtures.
- The quality gate (`cargo fmt --check`, `clippy -D warnings`, `nextest`, doctests) runs locally via the devenv `check` script, on commit via git hooks, and in CI across an OS matrix plus a pinned-MSRV job, with `cargo-deny` for advisories/licenses/bans.

## 8. Error handling and storage

Libraries return structured `thiserror` enums with preserved context (operation, device id, protocol). The top-level CLI may aggregate with `anyhow`. `Result` is used for all expected failures; panics are reserved for genuine programmer errors.

Credentials and settings persist through a `Storage` trait with a default file-backed implementation, mirroring pyatv's storage abstraction. Byte-for-byte compatibility with pyatv's existing `~/.pyatv.conf` JSON schema (so users can migrate credential exports) is treated as a **separate, explicit decision**, not assumed free — it requires reverse-engineering pyatv's `StorageModel`/`Settings` field names. The credential *string* format (colon-joined lowercase hex, documented in `crypto-pairing.md` §7) is replicated exactly regardless.

## 9. Open architectural decisions

These are deferred to the point where they must be made, and are tracked in `docs/RISKS.md`:

- MSRV policy: currently a provisional `1.88` floor (let-chains), CI-verified with `cargo-msrv`. Decide whether to adopt a rolling "N releases behind stable" policy.
- Whether `~/.pyatv.conf` on-disk compatibility is a shipped feature or just the credential-string format.
- Whether AirPlay 2 tunneled MRP is a full protobuf transport or a thin relay of the standalone MRP message set (affects whether one MRP codec serves both transports — current plan assumes it does, via the `MrpTransport` trait).
- Whether any FFI (macOS Keychain for credential storage) is in scope, which would reintroduce `unsafe extern` surface.
