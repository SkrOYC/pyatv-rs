//! Compiles the vendored pyatv MRP `.proto` corpus into Rust.
//!
//! Two artefacts land in `OUT_DIR`:
//!
//! - `mrp_protobuf.rs` — every message and enum, from `prost-build`. The corpus declares no
//!   `package`, so it is one flat module; `default_package_filename` just names the file.
//! - `mrp_extensions.rs` — the proto2 extension table, which `prost-build` does **not** generate.
//!   prost has no concept of `extend` at all: it drops those blocks silently and its decoder
//!   discards unknown fields, so nothing downstream could recover an extension field from a
//!   decoded `ProtocolMessage`. This script therefore emits a typed handle per extension, and
//!   `src/protobuf/extensions.rs` reads the field straight off the wire bytes. The whole story,
//!   with the evidence, is in `docs/research/mrp-protobuf-spike.md`.
//!
//! Compilation goes through `protox` rather than `protoc`: pure Rust, no external binary, no
//! network, so the crate builds offline from the vendored files alone. `protoc` 35.1 was verified
//! to produce byte-identical output during the spike.

use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use heck::{ToShoutySnakeCase, ToUpperCamelCase};
use prost_types::{FileDescriptorSet, field_descriptor_proto::Type};

/// Include root for `import` resolution. Every vendored file imports its siblings by their full
/// upstream path (`pyatv/protocols/mrp/protobuf/X.proto`), which is why the tree is nested.
const PROTO_ROOT: &str = "proto";

/// Directory actually holding the 77 files.
const PROTO_DIR: &str = "proto/pyatv/protocols/mrp/protobuf";

/// Message types that share another message's extension field.
///
/// Ported from `REUSED_MESSAGES` in pyatv's `scripts/protobuf.py`: a later `ProtocolMessage.Type`
/// constant reuses an existing inner message rather than defining a new one, so the name-derived
/// lookup below cannot find it.
const REUSED_TYPES: &[(&str, &str)] = &[("DEVICE_INFO_MESSAGE", "DEVICE_INFO_UPDATE_MESSAGE")];

/// The envelope every extension extends.
const ENVELOPE: &str = "ProtocolMessage";

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    let files = proto_files();
    assert!(
        !files.is_empty(),
        "no .proto files under {PROTO_DIR}; the vendored corpus is missing"
    );
    for file in &files {
        println!("cargo::rerun-if-changed={}", file.display());
    }

    let descriptors = protox::compile(&files, [PROTO_ROOT])
        .expect("protox failed to compile the vendored pyatv .proto corpus");

    let mut config = prost_build::Config::new();
    config.default_package_filename("mrp_protobuf");
    config
        .compile_fds(descriptors.clone())
        .expect("prost-build failed to generate Rust for the vendored .proto corpus");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo did not set OUT_DIR"));
    fs::write(
        out_dir.join("mrp_extensions.rs"),
        render_extensions(&descriptors),
    )
    .expect("could not write the generated extension table");
}

/// Every `.proto` under [`PROTO_DIR`], sorted so codegen is reproducible.
fn proto_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(PROTO_DIR)
        .expect("could not read the vendored proto directory")
        .map(|entry| entry.expect("could not stat a vendored proto file").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "proto"))
        .collect();
    files.sort();
    files
}

/// One `extend ProtocolMessage { … }` field.
struct Extension {
    /// Field name as written in the `.proto`, lower camel case (`sendCommandMessage`).
    accessor: String,
    /// Extension field number, which is *not* generally the `ProtocolMessage.Type` value.
    number: u32,
    /// Generated Rust type name, or `None` for the corpus' one scalar (string) extension.
    message: Option<String>,
    /// File the extension was declared in, for the generated doc comment.
    source: String,
}

impl Extension {
    /// Rust constant name: `sendCommandMessage` → `SEND_COMMAND_MESSAGE`.
    ///
    /// `heck` keeps acronyms together (`registerHIDDeviceMessage` → `REGISTER_HID_DEVICE_MESSAGE`),
    /// which is what makes these line up with the `ProtocolMessage.Type` constants.
    fn const_name(&self) -> String {
        self.accessor.to_shouty_snake_case()
    }
}

/// Collect every extension of [`ENVELOPE`] declared anywhere in the corpus.
fn collect_extensions(descriptors: &FileDescriptorSet) -> Vec<Extension> {
    let mut extensions: Vec<Extension> = descriptors
        .file
        .iter()
        .flat_map(|file| {
            let source = file.name().to_owned();
            file.extension.iter().map(move |field| {
                assert_eq!(
                    field.extendee().trim_start_matches('.'),
                    ENVELOPE,
                    "{source}: extension of an unexpected message"
                );
                let message = match field.r#type() {
                    Type::Message => {
                        let name = field.type_name().trim_start_matches('.');
                        assert!(
                            !name.contains('.'),
                            "{source}: nested extension payload {name} is not supported"
                        );
                        // prost-build upper-camel-cases every message name, which rewrites the
                        // corpus' acronyms: `RegisterHIDDeviceMessage` becomes
                        // `RegisterHidDeviceMessage`. Apply the same transform so the generated
                        // handles name types that actually exist.
                        Some(name.to_upper_camel_case())
                    }
                    Type::String => None,
                    other => panic!("{source}: unsupported extension type {other:?}"),
                };
                Extension {
                    accessor: field.name().to_owned(),
                    number: u32::try_from(field.number())
                        .expect("extension field number out of range"),
                    message,
                    source: source.clone(),
                }
            })
        })
        .collect();

    extensions.sort_by_key(|extension| extension.number);
    extensions
}

/// The `ProtocolMessage.Type` enum, as `(name, value)` pairs in declaration order.
fn message_types(descriptors: &FileDescriptorSet) -> Vec<(String, i32)> {
    descriptors
        .file
        .iter()
        .flat_map(|file| &file.message_type)
        .filter(|message| message.name() == ENVELOPE)
        .flat_map(|message| &message.enum_type)
        .filter(|enumeration| enumeration.name() == "Type")
        .flat_map(|enumeration| &enumeration.value)
        .map(|value| (value.name().to_owned(), value.number()))
        .collect()
}

/// pyatv's own name derivation, ported from `scripts/protobuf.py`:
/// `constant.title().replace("_", "").replace("Hid", "HID")`, then lower-case the first letter.
///
/// `SEND_HID_EVENT_MESSAGE` → `SendHidEventMessage` → `SendHIDEventMessage` → `sendHIDEventMessage`.
fn accessor_for_type(constant: &str) -> String {
    let title: String = constant
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<String>()
        .replace("Hid", "HID");

    let mut chars = title.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Map each `ProtocolMessage.Type` value to the extension field carrying its payload.
///
/// Same rule pyatv uses to build `_EXTENSION_LOOKUP`, minus one restriction: pyatv additionally
/// requires a `<MessageName>.proto` file to exist, which loses `UPDATE_PLAYER_MESSAGE` because
/// `updatePlayerMessage` is declared inside `UpdatePlayerPath.proto`. Keying off the extension
/// itself recovers that one entry and matches pyatv on all 55 others.
fn type_to_extension(types: &[(String, i32)], extensions: &[Extension]) -> Vec<(i32, u32)> {
    let mut table: Vec<(i32, u32)> = Vec::new();

    for (name, value) in types {
        let accessor = accessor_for_type(name);
        let Some(extension) = extensions
            .iter()
            .find(|extension| extension.accessor == accessor)
        else {
            continue;
        };
        table.push((*value, extension.number));

        for (original, alias) in REUSED_TYPES {
            if name != original {
                continue;
            }
            let alias_value = types
                .iter()
                .find(|(other, _)| other == alias)
                .map(|(_, value)| *value)
                .expect("REUSED_TYPES names a ProtocolMessage.Type constant that does not exist");
            table.push((alias_value, extension.number));
        }
    }

    table.sort_unstable();
    table
}

/// Render `mrp_extensions.rs`.
fn render_extensions(descriptors: &FileDescriptorSet) -> String {
    let extensions = collect_extensions(descriptors);
    let types = message_types(descriptors);
    let table = type_to_extension(&types, &extensions);

    let mut out = String::from(
        "// @generated by build.rs from the vendored pyatv .proto corpus. Do not edit.\n\n",
    );

    for extension in &extensions {
        let const_name = extension.const_name();
        let (accessor, number) = (&extension.accessor, extension.number);
        let file = Path::new(&extension.source)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(extension.source.as_str());

        writeln!(
            out,
            "/// `{accessor}`, extension field {number} of `ProtocolMessage` (`{file}`)."
        )
        .expect("writing to a String cannot fail");

        match &extension.message {
            Some(message) => writeln!(
                out,
                "pub const {const_name}: MessageExtension<super::{message}> = \
                 MessageExtension::new(\"{accessor}\", {number});"
            ),
            None => writeln!(
                out,
                "pub const {const_name}: StringExtension = \
                 StringExtension::new(\"{accessor}\", {number});"
            ),
        }
        .expect("writing to a String cannot fail");
    }

    out.push_str(
        "\n/// Every extension of `ProtocolMessage` in the corpus, ordered by field number.\n\
         pub const ALL: &[ExtensionInfo] = &[\n",
    );
    for extension in &extensions {
        writeln!(
            out,
            "    ExtensionInfo {{ name: \"{}\", number: {} }},",
            extension.accessor, extension.number
        )
        .expect("writing to a String cannot fail");
    }
    out.push_str("];\n");

    out.push_str(
        "\n/// `(ProtocolMessage.Type value, extension field number)`, sorted by type value.\n\
         pub(super) const TYPE_TO_NUMBER: &[(i32, u32)] = &[\n",
    );
    for (value, number) in &table {
        writeln!(out, "    ({value}, {number}),").expect("writing to a String cannot fail");
    }
    out.push_str("];\n");

    out
}
