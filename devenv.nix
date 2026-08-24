{ pkgs, lib, config, inputs, ... }:

let
  # Single source of truth for the quality gate so `check` and `ci` cannot drift.
  qualityGate = ''
    set -euo pipefail
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo nextest run
  '';
in
{
  # https://devenv.sh/basics/
  env = {
    RUST_BACKTRACE = "1";
    # prost-build / tonic-build look here before falling back to a $PATH lookup.
    PROTOC = "${pkgs.protobuf}/bin/protoc";
  };

  # https://devenv.sh/packages/
  packages = [
    pkgs.git
    pkgs.protobuf # protoc, for prost-build / protox descriptor tooling
    pkgs.cargo-nextest # test runner used by the quality gate
    pkgs.cargo-deny # license / advisory / dependency-ban auditing
    pkgs.gh
    pkgs.jq
    pkgs.eza
  ];

  # https://devenv.sh/languages/
  languages.rust = {
    enable = true;
    channel = "stable";
    components = [
      "rustc"
      "cargo"
      "clippy"
      "rustfmt"
      "rust-analyzer"
      "rust-src"
    ];
  };

  # https://devenv.sh/scripts/
  scripts = {
    check.exec = qualityGate;
    ci.exec = qualityGate;
  };

  # https://devenv.sh/git-hooks/
  # The Rust language module points these hooks at the toolchain selected above
  # via `git-hooks.tools`, so they never fall back to the nixpkgs rustc.
  git-hooks.hooks = {
    rustfmt.enable = true;
    clippy = {
      enable = true;
      settings.allFeatures = true;
    };
  };

  # https://devenv.sh/basics/
  enterShell = ''
    echo "canvas devenv | $(rustc --version) | $(cargo --version)"
  '';

  # https://devenv.sh/tests/
  enterTest = ''
    set -eu

    rustc --version
    cargo --version
    cargo nextest --version

    # Prove edition 2024 support by compiling against it rather than by
    # parsing a version string.
    probe_dir="$(mktemp -d)"
    trap 'rm -rf "$probe_dir"' EXIT
    printf 'pub fn canvas_edition_probe() {}\n' > "$probe_dir/probe.rs"
    rustc --edition 2024 --crate-type lib --emit=metadata \
      --out-dir "$probe_dir" "$probe_dir/probe.rs"
    echo "rustc accepts --edition 2024"

    cargo clippy --version
    cargo fmt --version
    cargo deny --version
    protoc --version
    gh --version
    jq --version
    eza --version
  '';

  # See full reference at https://devenv.sh/reference/options/
}
