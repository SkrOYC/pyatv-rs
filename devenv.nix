{ pkgs, lib, config, inputs, ... }:

let
  # Single source of truth for the quality gate so `check` and `ci` cannot drift.
  qualityGate = ''
    set -euo pipefail
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    # `--all-features` is kept deliberately, though the workspace run does not currently need it.
    # `pyatv-pairing`'s `test-server` feature gates its reference HAP accessory, and with it every
    # end-to-end pair-setup/pair-verify test and every negative path (wrong PIN, corrupted
    # signature, unknown pairing). A `-p pyatv-pairing` run without the flag silently drops all of
    # them; a `--workspace` run keeps them either way, because `pyatv-proto-companion` dev-depends
    # on the feature and Cargo unifies features across the workspace. The flag is what stops that
    # coincidence from being load-bearing.
    cargo nextest run --all-features
    # nextest does not run doctests; they need their own pass or every `///` example goes
    # unexecuted.
    cargo test --workspace --doc --all-features
    # Rustdoc warnings are build failures here for the same reason clippy warnings are: a broken
    # intra-doc link is a link that silently does not exist, and they accumulate invisibly unless
    # something fails on them. `--no-deps` keeps the check to code we own.
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
  '';

  # Feature-combination check. Kept out of `qualityGate` because it is a separate axis of
  # coverage — the gate proves the all-features build is clean, this proves no crate compiles
  # *only* because some other feature happened to be on.
  #
  # `--feature-powerset` rather than `--each-feature`: measured at 15 combinations across the
  # workspace (five crates have exactly one feature each, the rest have none), so the exhaustive
  # form costs nothing over the cheap one. Revisit if a crate grows several independent features
  # — the powerset is 2^n per crate.
  #
  # `check --all-targets` rather than plain `check`: every feature in this workspace
  # (`pyatv-pairing/test-server` and the `test-support` features that turn it on) exists to gate
  # test scaffolding, so the interactions worth catching are in the test and bench targets.
  featureGate = ''
    set -euo pipefail
    cargo hack --feature-powerset --workspace check --all-targets
  '';

  # MSRV verification against the floor declared in `[workspace.package] rust-version`.
  #
  # This deliberately drives rustup rather than `cargo msrv verify`: cargo-msrv 0.19.3 reads
  # `package.rust-version` and cannot see `[workspace.package] rust-version` in a virtual
  # manifest, so at the workspace root it fails with "unable to find key 'package.rust-version'".
  # It works per-member with `--path crates/<name>`, which is what `cargo msrv find` is for when
  # hunting a *new* floor; for verifying the declared one, a single pinned-toolchain build over
  # the whole workspace is both faster and exactly what the CI job does.
  msrvGate = ''
    set -euo pipefail
    msrv="$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)"
    if [ -z "$msrv" ]; then
      echo "could not read rust-version from Cargo.toml" >&2
      exit 1
    fi
    if ! command -v rustup > /dev/null 2>&1; then
      echo "check-msrv needs rustup to fetch the pinned $msrv toolchain, which this devenv does" >&2
      echo "not provide. The authoritative check is the 'msrv' job in .github/workflows/ci.yml." >&2
      exit 1
    fi
    rustup toolchain install "$msrv" --profile minimal --no-self-update
    # `rustup run`, not `cargo +$msrv`: inside this devenv `cargo` is the pinned Nix binary rather
    # than the rustup shim, and it rejects `+toolchain` directives outright.
    rustup run "$msrv" cargo check --workspace --all-features --locked
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
    pkgs.cargo-hack # feature-combination checks (`check-features`)
    # MSRV discovery. `check-msrv` does not use it — see the `msrvGate` comment — but
    # `cargo msrv find --path crates/<name>` is the tool for working out a *new* floor after a
    # dependency bump, and it needs rustup, which this brings along.
    pkgs.cargo-msrv
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
    check-features.exec = featureGate;
    check-msrv.exec = msrvGate;
    bench.exec = ''
      set -euo pipefail
      cargo bench --workspace --all-features "$@"
    '';
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
    cargo hack --version
    cargo msrv --version
    protoc --version
    gh --version
    jq --version
    eza --version
  '';

  # See full reference at https://devenv.sh/reference/options/
}
