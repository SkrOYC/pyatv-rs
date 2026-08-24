# MRP protobuf codegen spike: prost vs rust-protobuf, and the proto2 extension problem

Spike date: 2026-08-24. Resolves risk **M2** ("prost/protox may not compile pyatv's proto2 extension-based `.proto` files"). Everything below was measured on this machine against the real vendored corpus, inside the devenv shell (rustc 1.98.0, `protoc` 35.1 from `$PROTOC`). Nothing here is recalled from training data: every claim names the file or command that produced it.

**Outcome: prost compiles the corpus perfectly and silently drops every `extend` block. The gap is real but small and fully closable, so the crate stays on prost + protox and carries a 100-line wire-level extension extractor, generated from the same descriptor set at build time. rust-protobuf 3.7.2 was spiked too and does support extensions natively; it was not chosen, for reasons recorded below.**

## 1. The corpus

Vendored verbatim into `crates/pyatv-proto-mrp/proto/pyatv/protocols/mrp/protobuf/` from pyatv commit `b277a4c8222ecdcbaab8a24e3e713ca44765adb4` (release 0.18.0), MIT, with the upstream licence text alongside as `proto/LICENSE-pyatv.md` and provenance in `proto/README.md`. The nested directory layout is deliberate: every file imports its siblings as `pyatv/protocols/mrp/protobuf/X.proto`, so preserving the path lets the files stay byte-identical to upstream while `proto/` alone works as the include root.

| Property | Value |
| --- | --- |
| `.proto` files | 77 |
| `syntax` | `proto2` in all 77 |
| `package` declarations | none, so all generated types land in one flat module |
| Files declaring `extend ProtocolMessage { … }` | 55, one field each |
| Message-typed extensions | 54 |
| Scalar extensions | 1 — `optional string getKeyboardSessionMessage = 29` in `GetKeyboardSessionMessage.proto` |
| Imports | all internal; the most common are `ProtocolMessage.proto` (55 files), `PlayerPath.proto` (14), `Common.proto` (7). No well-known types, so codegen needs nothing from `google/protobuf/` |
| `ProtocolMessage.Type` enum values | 83 (`docs/research/mrp-companion.md` §1.3 says 84 — corrected here, counted off the descriptor) |
| Extension ranges reserved on `ProtocolMessage` | `6 to 77`, `79 to 84`, `86 to max` |

The envelope pattern is the whole point of the corpus: a sender sets `ProtocolMessage.type` to a `Type` constant and puts the actual payload in the extension field that constant designates. pyatv reads it with `message.Extensions[SendCommandMessage_pb2.sendCommandMessage]` and wraps that in `protobuf.extract_inner()`.

### The type-to-extension mapping is not the identity

`docs/research/mrp-companion.md` §1.3 states that "extension field number == enum value". That is **wrong for every one of the 55 messages** — not a single type value equals its extension field number — verified by dumping pyatv's own `_EXTENSION_LOOKUP` and comparing:

- `SEND_COMMAND_MESSAGE = 1` → extension field 6
- `SET_STATE_MESSAGE = 4` → field 9
- `DEVICE_INFO_MESSAGE = 15` → field 20
- `SET_DISCOVERY_MODE_MESSAGE = 101` → field 82
- `CONFIGURE_CONNECTION_MESSAGE = 120` → field 94
- `DEVICE_INFO_UPDATE_MESSAGE = 37` → field 20 as well: two type values share one extension (pyatv's `REUSED_MESSAGES`)

Anything deriving the field number from the enum value would produce garbage on every message, so the mapping is taken from the `.proto` files, never computed.

## 2. Versions verified

Checked on 2026-08-24 with `cargo info` and the crates.io API, not from memory.

| Crate | Version | Published | Licence | Note |
| --- | --- | --- | --- | --- |
| `prost` | 0.14.4 | 2026-06-07 | Apache-2.0 | rust-version 1.85 |
| `prost-build` | 0.14.4 | 2026-06-07 | Apache-2.0 | rust-version 1.85 |
| `prost-types` | 0.14.4 | 2026-06-07 | Apache-2.0 | used in `build.rs` to walk the descriptor set |
| `protox` | 0.9.1 | 2025-12-02 | MIT OR Apache-2.0 | pure-Rust protobuf compiler; depends on `prost ^0.14`, `prost-reflect ^0.16` |
| `prost-reflect` | 0.16.5 | — | MIT OR Apache-2.0 | pulled in transitively by protox; has `DynamicMessage::get_extension` (see §5, option C) |
| `protobuf` (rust-protobuf) | **3.7.2** | 2025-03-10 | MIT | `max_stable_version` on crates.io |
| `protobuf-codegen` | 3.7.2 | 2025-03-10 | MIT | same release train |
| `heck` | 0.5.0 | — | MIT OR Apache-2.0 | build dependency; the same casing crate prost-build itself uses |

**Trap worth recording:** `cargo info protobuf` reports `4.36.0-rc.2` as the latest version, but the `protobuf` 4.x line on crates.io is **not** rust-protobuf. Its licence is BSD-3-Clause and it is Google's own Rust runtime, a different project that took over the crate name. rust-protobuf (Stepan Cheg, MIT) tops out at 3.7.2, and every 4.x release so far is either an `-rc` or a `-release`-suffixed prerelease, so `max_stable_version` is still 3.7.2. Anything that "upgrades protobuf to 4" would be a silent project switch, not a version bump.

## 3. Spike A — prost-build, with protoc and with protox

Scratch crate at `/tmp/spike-prost`, `build.rs` compiling all 77 files twice into separate output directories: once through `prost_build::Config::compile_protos` (which shells out to `$PROTOC`, protobuf 35.1), once through `protox::compile(...)` + `prost_build::Config::compile_fds(...)`.

**Both succeeded on the first attempt, with no errors and no warnings, and the two outputs are byte-identical:**

```
$ md5sum protoc/_.rs protox/_.rs
44c6280d3bb587a7ec59c9ba81f6ebe3  protoc/_.rs
44c6280d3bb587a7ec59c9ba81f6ebe3  protox/_.rs
```

189 KB, 4367 lines, every message and enum in the corpus. So the first half of M2 is answered outright: protox 0.9.1 has full parity with protoc 35.1 on this corpus, and `docs/research/rust-crates.md` §3's open question ("validate protox empirically against the real corpus") is closed in protox's favour.

### What prost did with the `extend` blocks: nothing

`ProtocolMessage` generates with exactly its seven declared fields and no extension accessor of any kind:

```rust
pub struct ProtocolMessage {
    #[prost(enumeration = "protocol_message::Type", optional, tag = "1")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub identifier: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "3")]
    pub authentication_token: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(enumeration = "error_code::Enum", optional, tag = "4")]
    pub error_code: ::core::option::Option<i32>,
    #[prost(uint64, optional, tag = "5")]
    pub timestamp: ::core::option::Option<u64>,
    #[prost(string, optional, tag = "78")]
    pub error_description: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "85")]
    pub unique_identifier: ::core::option::Option<::prost::alloc::string::String>,
}
```

Grepping the whole 4367-line output for `extend`/`extension` finds one hit, and it is the unrelated `supports_extended_motion` field of `DeviceInfoMessage`. The payload message types (`SendCommandMessage`, `SetStateMessage`, …) are all generated correctly — it is only the `extend` blocks that vanish.

This is by design, not a bug in our usage. In `prost-build` 0.14.4 the string `extension` appears exactly once in the entire source tree, in a doc comment about output filenames:

```
$ grep -rn "extension" prost-build-0.14.4/src/*.rs
config.rs:648:    /// The filename will be appended with the `.rs` extension.
```

**And prost does not retain unknown fields either.** `prost::encoding::skip_field` discards them, and `grep -rln "unknown_fields\|UnknownField" prost-0.14.4/src/` returns nothing. So the extension bytes are not merely unnamed after a decode — they are gone. Recovering them *after* `ProtocolMessage::decode` is impossible; they have to come off the original buffer.

That is the whole of the M2 finding: **prost compiles pyatv's proto2 corpus flawlessly, then silently drops the one construct MRP is built around.** Left unaddressed it would not fail the build — it would produce a client that can read `type` and nothing else, which is exactly the kind of silent interop failure the risk register exists to catch.

## 4. Spike B — rust-protobuf 3.7.2

Run anyway, cheaply, so the comparison rests on evidence rather than on reputation. Scratch crate at `/tmp/spike-rustprotobuf`, `protobuf_codegen::Codegen::new().pure()` (its own pure-Rust parser, no protoc) over the same 77 files. It compiled the corpus without errors and emitted 78 files, one per input plus `mod.rs`, with an `exts` module wherever the input had an `extend` block — 55 of them, as expected:

```rust
// SendCommandMessage.rs
pub mod exts {
    pub const sendCommandMessage: ::protobuf::ext::ExtFieldOptional<
        super::super::ProtocolMessage::ProtocolMessage, super::SendCommandMessage
    > = ::protobuf::ext::ExtFieldOptional::new(6,
        ::protobuf::descriptor::field_descriptor_proto::Type::TYPE_MESSAGE);
}

// GetKeyboardSessionMessage.rs — the scalar case, handled by the same type
pub mod exts {
    pub const getKeyboardSessionMessage: ::protobuf::ext::ExtFieldOptional<
        super::super::ProtocolMessage::ProtocolMessage, ::std::string::String
    > = ::protobuf::ext::ExtFieldOptional::new(29,
        ::protobuf::descriptor::field_descriptor_proto::Type::TYPE_STRING);
}
```

So the fallback in M2's mitigation is real: rust-protobuf gives typed `get`/`set` on extensions for free, message-typed and scalar alike, and it preserves pyatv's names exactly (`RegisterHIDDeviceMessage`, not prost's `RegisterHidDeviceMessage`).

## 5. The decision

**prost 0.14.4 + protox 0.9.1 + a hand-written extension extractor.** Options weighed:

- **A — prost + extractor (chosen).** Idiomatic Rust output: plain structs, `Option<T>` for proto2 optional, no runtime reflection, no embedded descriptors, `Debug` and `PartialEq` derived. Keeps the crate on the workspace's already-chosen protobuf stack (`rust-crates.md` §3) and on the same `prost` generation as anything else that may need it. Cost: about 100 lines of wire-format code plus a build-time table, which is the honest price and is fully pinned by known-answer tests (§7).
- **B — rust-protobuf 3.7.2.** Would have deleted the extractor. Rejected on four counts: (i) its generated API is reflection-heavy (`MessageField`, `SpecialFields`, embedded `file_descriptor_proto_data` in every module) where prost's is plain data, and those types would surface in this crate's public API; (ii) it ships a blanket `#![allow(clippy::all)] #![allow(non_snake_case)] #![allow(non_upper_case_globals)] #![allow(missing_docs)]` header and non-idiomatic identifiers (`pub const sendCommandMessage`), which is a much bigger lint carve-out than the narrow `clippy::pedantic` allow prost's output needs; (iii) 78 generated files against prost's one; (iv) crate-name risk — the `protobuf` name on crates.io now serves Google's separate 4.x project, so 3.7.2 is the end of a line whose future is not ours to predict, and switching crates later would be a rewrite of the whole message layer rather than of one module.
- **C — `prost-reflect` `DynamicMessage`.** Already in the dependency graph via protox, and `DynamicMessage::get_extension(&ExtensionDescriptor)` does exactly the right thing. Rejected because it means embedding the whole `FileDescriptorSet` in the binary, doing name-based lookups at runtime, and converting dynamic `Value`s into typed messages anyway — strictly more machinery than reading one field off a buffer, for a corpus that is frozen at build time.

protox over protoc is settled by §3: identical output, no external binary, no `$PROTOC`, no network. Verified: `env -u PROTOC cargo build --offline -p pyatv-proto-mrp` succeeds from a clean `build.rs` re-run.

## 6. The extension extractor

Three pieces, all in `crates/pyatv-proto-mrp/`.

**`build.rs`** compiles the corpus with protox, hands the `FileDescriptorSet` to `prost-build` for the messages, and then walks the same descriptor set a second time to emit `OUT_DIR/mrp_extensions.rs`:

- one typed handle per extension, named after it — `pub const SEND_COMMAND_MESSAGE: MessageExtension<super::SendCommandMessage> = MessageExtension::new("sendCommandMessage", 6);` — with the scalar one rendered as `StringExtension` instead;
- `ALL`, the 55 `(name, number)` pairs, for enumeration and for a test that notices a corpus refresh;
- `TYPE_TO_NUMBER`, the sorted `ProtocolMessage.Type` → field-number table, 56 entries.

The type-to-extension derivation is a port of pyatv's own generator (`scripts/protobuf.py`, `extract_message_info`): `constant.title().replace("_", "").replace("Hid", "HID")`, lower-case the first letter, and look for an extension with that name; then apply `REUSED_MESSAGES` to give `DEVICE_INFO_UPDATE_MESSAGE` the `deviceInfoMessage` field. Verified against pyatv's live `_EXTENSION_LOOKUP`: **all 55 of pyatv's entries reproduce exactly, with no conflicts.**

One deliberate divergence. pyatv's generator additionally requires a file named `<MessageName>.proto` to exist, and `updatePlayerMessage` is declared inside `UpdatePlayerPath.proto`, so pyatv silently has no entry for `UPDATE_PLAYER_MESSAGE = 58` and its `extract_inner()` raises on that message. Keying off the extension itself rather than off a filename recovers it, giving 56 entries where pyatv has 55. This changes no bytes we send — it only lets us decode a message pyatv cannot — and it is pinned by a named test so it stays a decision rather than an accident.

`build.rs` also applies `heck`'s `to_upper_camel_case` to the payload type name, because prost-build does: the corpus' `RegisterHIDDeviceMessage` becomes `RegisterHidDeviceMessage` in generated Rust while the *field* stays `registerHIDDeviceMessage`. The generated handle bridges the two, and `extensions::REGISTER_HID_DEVICE_MESSAGE.name()` still returns pyatv's spelling.

**`src/protobuf/wire.rs`** is the sans-io half: a `Scanner` over the top-level fields of a serialised message (key varint → field number + wire type, then varint / fixed64 / fixed32 / length-delimited), `find_length_delimited(buffer, number)` returning the payload slice with last-occurrence-wins semantics, and `splice_length_delimited(buffer, number, payload)` inserting a field **in ascending tag order**, replacing any existing field with that number. Groups (wire types 3 and 4) are rejected explicitly rather than skipped; the corpus contains none. The varint reader is the existing `crate::variant`, which already implements the identical encoding for MRP's outer length prefix.

Tag order matters more than it looks. The Python reference serialises fields in ascending field-number order, and extension numbers interleave with the envelope's own: in a real `SEND_COMMAND_MESSAGE` the layout is field 1 (`type`), field 6 (the extension), field 85 (`uniqueIdentifier`). Appending the extension after prost's output would put field 6 last — still valid protobuf, still decodable by any device, but no longer byte-identical to pyatv, which would make byte-exact known-answer testing impossible. Splicing keeps the vectors comparable as whole buffers. It does assume prost emits its own fields in tag order, which it does, and which the vectors would catch immediately if it ever stopped.

**`src/protobuf/extensions.rs`** is the typed surface: `MessageExtension<M>::decode(&[u8]) -> Result<Option<M>>` and `::encode(&ProtocolMessage, &M) -> Result<Vec<u8>>`, the same pair on `StringExtension` for the one scalar, plus `number_for_type(i32)` and `raw_for_type(&[u8], i32)` for a dispatcher that has a type value but not yet a Rust type. `MessageExtension<M>` holds `PhantomData<fn() -> M>` so it stays `Copy`/`Send`/`Sync` for any `M`, and implements `Debug` by hand so no `M: Debug` bound leaks.

The shape of a call site is deliberately close to pyatv's:

```rust
let bytes = extensions::SEND_COMMAND_MESSAGE.encode(&envelope, &inner)?;
let inner = extensions::SEND_COMMAND_MESSAGE.decode(&bytes)?;
```

The envelope is therefore handled twice on purpose: `prost` decodes `ProtocolMessage` for the seven declared fields, and the extractor reads the payload off the same bytes. That is one extra linear scan of a buffer that is almost always well under a kilobyte.

## 7. Known-answer vectors

`crates/pyatv-proto-mrp/tests/kat/mrp_extension_kat.json`, generated by `gen_mrp_extension_kat.py` in the same directory, running against pyatv `b277a4c` on its own protobuf runtime (7.36.0, Python 3.14.7) — the same pattern `pyatv-pairing` uses for the SRP vectors. Six of the eight vectors are built by *pyatv's own helpers* (`messages.command`, `messages.seek_to_position`, `messages.device_information`, `messages.crypto_pairing`, `messages.get_keyboard_session`), so the vectors are an independent second implementation rather than a restatement of ours. Determinism comes from patching `messages.uuid4`, which stamps every envelope with a random `uniqueIdentifier`.

The vectors cover `SendCommandMessage` (bare, and with a nested `CommandOptions`), `SetStateMessage`, `DeviceInfoMessage`, `DeviceInfoMessage` again under the `DEVICE_INFO_UPDATE_MESSAGE` alias, `CryptoPairingMessage`, `RegisterHIDDeviceMessage`, and the scalar `getKeyboardSessionMessage`.

Each one is put through the full round trip in `tests/protobuf_extensions.rs`: decode the envelope with prost, extract and decode the payload, re-encode both, and compare the result with pyatv's buffer **byte for byte**. All eight match. One test asserts the negative directly — that prost alone loses the payload — by re-encoding a decoded envelope and showing the extension gone:

```
pyatv:  0801 2000 32020801 aa0524…   (field 1, field 4, extension field 6, field 85)
prost:  0801 2000          aa0524…
```

## 8. What the MRP transport needs from this at Step 4

- **Receive.** Read a frame (`variant::read` length prefix, decrypt if the session is up), `ProtocolMessage::decode` it for `type`, `identifier` and `errorCode`, then dispatch on `type`. `extensions::number_for_type` says whether a payload is expected at all; `raw_for_type` hands back its bytes; the matching generated constant decodes it. `Error::UnhandledMessage(i32)` already exists for the types with no extension (`UNKNOWN_MESSAGE`, `GET_STATE_MESSAGE`, the game-controller family — 27 of the 83).
- **Send.** Build the envelope (`type`, a fresh uppercase UUID `uniqueIdentifier`, `errorCode = 0`, as `messages.create` does), then `EXTENSION.encode(&envelope, &payload)` for the bytes to frame. The first message on any direct socket must be `DEVICE_INFO_MESSAGE` with pyatv's exact impersonation strings (`docs/research/mrp-companion.md` §1.4); `extensions::DEVICE_INFO_MESSAGE` and the generated `DeviceInfoMessage` are what that will be built from.
- **Both transports share this.** Nothing in `protobuf/` touches I/O, sockets or encryption, so the direct-TCP and AirPlay-tunnel implementations of `MrpTransport` sit underneath it unchanged, as `mrp-companion.md` §3.4 requires.
- **Not yet built, and out of scope here:** the `Type`-to-handler dispatch table itself, the `ErrorCode.Enum` → typed-error mapping (~50 device-side codes are already generated), and `messages.py`'s message constructors. All three are ordinary Rust over the types this spike landed.

## 9. Residual risk

- A future corpus refresh could add an extension of a scalar type other than `string`; `build.rs` panics loudly on one rather than skipping it, so it fails the build instead of the device.
- The tag-order splice depends on prost emitting fields in tag order. Undocumented but stable, and pinned by eight byte-exact vectors.
- pyatv's `_EXTENSION_LOOKUP` is regenerated by pyatv from its own `.proto` files, so it moves when the corpus moves. `proto/README.md` tells the next person to regenerate the vectors from the same checkout they vendor from; the test asserting exactly 55 extensions turns any drift into a failure.
- The vectors are pyatv-generated, not device-captured. They prove parity with the reference implementation, not that the reference implementation is right about the newest tvOS. An `atvproxy` capture at Step 4 is what would close that, per `docs/RISKS.md` L1.
