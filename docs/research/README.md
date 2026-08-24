# Research corpus

Seven grounded deep-dives produced during Step 0 (2026-08-24). Each was written against live sources — pyatv `master`, pyatv.dev, crates.io/docs.rs, and protocol reverse-engineering references — not from model memory, and each cites its sources inline and ends with an "Open questions" section. They are the wire-level ground truth for implementation; the synthesis lives in `../ARCHITECTURE.md`, `../ROADMAP.md`, and `../RISKS.md`.

All version numbers, service records, algorithm parameters, and behavior notes are a point-in-time snapshot of 2026-08-24. Re-verify before relying on any specific version or on pyatv behavior — both move.

| Report | Covers |
|---|---|
| `pyatv-architecture.md` | pyatv module layout and public API surface; the interface ABCs and enums; scan/pair/connect flow; the facade + `Relayer` priority model and `SetupData`; the storage abstraction; the `atvremote`/`atvscript`/`atvproxy` CLIs; mDNS service types; current upstream state and open tvOS-26 issues. |
| `mrp-companion.md` | MRP transport (varint-prefixed protobuf), the tvOS-15 gating heuristic and AirPlay-tunneled MRP; Companion frame format and services; OPACK byte-tag table; the shared HAP pairing primitives and per-channel crypto constants. |
| `airplay-raop-dmap.md` | AirPlay 1/2 HTTP/RTSP quirks and auth flavors; the 64-bit mDNS feature/status flags; `play_url`; RAOP/AirTunes RTSP + RTP audio, timing/control channels, metadata/volume; DMAP/DAAP + Home Sharing; all relevant mDNS service types and TXT keys. |
| `crypto-pairing.md` | The full crypto/pairing stack byte-for-byte: both SRP6a profiles, exact HKDF salt/info strings, the three ChaCha20 nonce layouts, TLV8, Ed25519/X25519 signed-payload layouts, legacy AES-CTR/GCM quirks, credential formats, and the RustCrypto crate mapping (including where `srp` falls short). The highest-risk report. |
| `rust-crates.md` | Ecosystem crate selection with verified current versions: runtime, mDNS, protobuf, plist, the custom HTTP/RTSP codec rationale, OPACK, RAOP audio codecs, serde/error/tracing/testing/CLI stacks; the sans-io design recommendation. |
| `rust-2024-tooling.md` | Edition 2024 semantics that matter for new code; current toolchain; virtual workspace layout with `[workspace.package]`/`[workspace.dependencies]`/`[workspace.lints]`; `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, MSRV policy, nextest, and GitHub Actions CI conventions — with concrete config snippets. |
| `prior-art.md` | Existing Rust and notable non-Rust implementations of these protocols, each with license (critically, copyleft vs permissive), scope, maintenance, and reusable lessons; the gap analysis of what has never been done in Rust and where the reverse-engineering risk concentrates. |
