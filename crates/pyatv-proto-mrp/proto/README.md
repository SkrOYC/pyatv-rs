# Vendored pyatv MRP protobuf definitions

`pyatv/protocols/mrp/protobuf/` copied **verbatim** from [pyatv](https://github.com/postlund/pyatv) at commit `b277a4c8222ecdcbaab8a24e3e713ca44765adb4` (release 0.18.0). 77 `.proto` files, all `syntax = "proto2"`, no `package` declaration.

There is no official Apple source for these definitions: they were reverse-engineered and are hand-maintained by the pyatv project, which makes this directory the only spec of record for the MediaRemote message layer. Copy, do not rewrite — the enclosing directory layout (`pyatv/protocols/mrp/protobuf/`) is preserved because every file's `import` statements are written against that exact path, so the vendored tree compiles with `proto/` as the sole include directory and the files stay byte-identical to upstream.

## License

pyatv is MIT-licensed; the license text as shipped upstream is reproduced in `LICENSE-pyatv.md` next to this file.

> Copyright (c) 2020 Pierre Ståhl
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction […]

## Shape of the corpus

- 77 files, 0 with a `package` declaration, so every generated Rust type lands in one flat module.
- 55 of them declare a proto2 extension of the envelope: `extend ProtocolMessage { optional X x = N; }`, one field each. 54 are message-typed; exactly one is scalar (`optional string getKeyboardSessionMessage = 29` in `GetKeyboardSessionMessage.proto`).
- Imports are all internal to the corpus (55 files import `ProtocolMessage.proto`, 14 import `PlayerPath.proto`, and so on). Nothing imports a well-known type, so codegen needs no `google/protobuf/*.proto` on the include path.
- `ProtocolMessage.proto` reserves the extension ranges `6 to 77`, `79 to 84` and `86 to max`, and carries the `ProtocolMessage.Type` enum (83 values) plus `ErrorCode.Enum`.

The extension field number is **not** the same as the `Type` enum value for most messages (`SEND_COMMAND_MESSAGE = 1` carries extension field 6, `CONFIGURE_CONNECTION_MESSAGE = 120` carries extension field 94), and `DEVICE_INFO_UPDATE_MESSAGE` reuses `DEVICE_INFO_MESSAGE`'s extension. `build.rs` derives the mapping from these files the same way pyatv's `scripts/protobuf.py` does; see `docs/research/mrp-protobuf-spike.md`.

## Refreshing

```sh
cp /path/to/pyatv/pyatv/protocols/mrp/protobuf/*.proto \
   crates/pyatv-proto-mrp/proto/pyatv/protocols/mrp/protobuf/
```

Then regenerate the known-answer vectors (`crates/pyatv-proto-mrp/tests/kat/gen_mrp_extension_kat.py`) from the same checkout and run the test suite: the vectors are produced by pyatv's own protobuf runtime, so a corpus change that alters the wire layout shows up as a test failure rather than as silent drift.
