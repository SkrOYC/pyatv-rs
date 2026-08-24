# Rust 2024 edition, toolchain, and workspace tooling — research for pyatv-rs

Status: research for step 0 planning. Grounded against official Rust docs, crates.io, and GitHub as of 2026-08-24. Local dev toolchain observed in this environment: `rustc 1.93.1 (01f6ddf75 2026-02-11)`, `cargo 1.93.1 (083ac5135 2025-12-15)`.

**Important discrepancy to flag up front:** the actual latest upstream stable release as of 2026-08-24 is **Rust 1.98.0**, published 2026-08-20 ([blog.rust-lang.org/releases/](https://blog.rust-lang.org/releases/)). The local sandbox toolchain (1.93.1, from January 2026) is roughly seven releases behind. Everything below is written to be correct for both 1.93.1 (the floor we can assume locally) and current stable — the edition-2024 language/tooling behavior described here has been stable since 1.85.0 and has not been walked back in any release between 1.85 and 1.98. Recommendation: do not hardcode "1.93" anywhere in project config; use `channel = "stable"` in CI and let `rust-toolchain.toml` pin whatever the team's dev machines actually have, per the MSRV section below.

## 1. Edition 2024 — what actually changed and what matters for new code

Rust 2024 was stabilized in **Rust 1.85.0**, released 2025-02-20 ([blog.rust-lang.org/2025/02/20/Rust-1.85.0](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/), RFC [3501-edition-2024](https://rust-lang.github.io/rfcs/3501-edition-2024.html)). The canonical reference is the Edition Guide's 2024 chapter tree, rooted at [doc.rust-lang.org/edition-guide/rust-2024/index.html](https://doc.rust-lang.org/edition-guide/rust-2024/index.html); the sub-pages below are all under that path.

For a greenfield project we write edition-2024 code from day one, so most of these "changes" are simply the rules we design against, not a migration concern. The ones an implementer needs to internalize:

- **RPIT lifetime capture rules** ([rpit-lifetime-capture.md](https://doc.rust-lang.org/edition-guide/rust-2024/rpit-lifetime-capture.html), RFC [3498](https://rust-lang.github.io/rfcs/3498-lifetime-capture-rules-2024.html)): `-> impl Trait` return types now capture **all** lifetime and type parameters in scope by default (matching how `async fn` already behaved in 2021). This matters a lot for a networking library returning `impl Stream<Item = ...>` or `impl Future` from methods that borrow `&self` — in 2021 you'd need `+ '_` or `+ 'a` bounds to opt in; in 2024 it's implicit. If we deliberately want a shorter-lived-only-in-generic-params capture (i.e. the pre-2024 behavior), use the `use<'a, T>` precise-capturing syntax (stabilized in 1.82, usable in any edition): `fn f<'a>(x: &'a str) -> impl Fn() + use<>` to capture nothing, or `use<'a>` to capture only `'a`. For async trait methods and RPITIT (return-position impl Trait in traits, stable since 1.75) this interacts with `Send`-bound futures — expect to write `use<...>` bounds on any RPITIT method that needs to stay `Send` without over-capturing generics from the trait.
- **`unsafe_op_in_unsafe_fn` is warn-by-default → effectively deny in edition 2024 idiom** ([unsafe-op-in-unsafe-fn.md](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html)): the body of an `unsafe fn` no longer acts as an implicit `unsafe {}` block; every unsafe operation inside needs its own explicit block. For this project we will have some unsafe surface only if we hand-roll a crypto primitive or FFI into a system keychain/mDNS library — plan to wrap each unsafe op individually and comment the safety invariant at the call site, not the function signature.
- **`unsafe extern` blocks** ([unsafe-extern.md](https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-extern.html)): `extern "C" { ... }` blocks must now be written `unsafe extern "C" { ... }`; individual items inside can be tagged `safe fn ...` if the binding author asserts they're safe to call without a wrapper. Only relevant if we bind to a system mDNS/DNS-SD library via FFI instead of a pure-Rust mDNS implementation (see the mDNS/DNS-SD research thread — pure Rust is the expected path, so this likely doesn't apply).
- **`static mut` references denied by default** ([static-mut-references.md](https://doc.rust-lang.org/edition-guide/rust-2024/static-mut-references.html)): `static_mut_refs` lint is now `deny`. Taking `&`/`&mut` to a `static mut` is instant UB under the aliasing model even if unused. Use `OnceLock`/`LazyLock` (both stable in std, `LazyLock` since 1.80), `Mutex`/`RwLock`, `Atomic*`, or `&raw const`/`&raw mut` (stable since 1.82) if raw-pointer access to a static is genuinely needed. We should have essentially zero `static mut` in this codebase — global registries, if any, belong in `LazyLock<Mutex<...>>` or an `OnceLock`.
- **`if let` temporary scope narrowing** ([temporary-if-let-scope.md](https://doc.rust-lang.org/edition-guide/rust-2024/temporary-if-let-scope.html)): temporaries created in the scrutinee of `if let` are now dropped before the `else` branch runs, not held until the end of the whole `if`/`else`. Classic footgun this fixes: `if let Ok(guard) = lock.try_read() { ... } else { lock.write() ... }` — pre-2024 this could deadlock because the read guard from the `if` branch's condition was still alive while evaluating `else`; in 2024 it's already dropped. Relevant to us if we wrap AirPlay/MRP connection state in `RwLock`/`Mutex` guards inspected via `if let`.
- **Tail-expression temporary scope narrowing** ([temporary-tail-expr-scope.md](https://doc.rust-lang.org/edition-guide/rust-2024/temporary-tail-expr-scope.html), RFC [3606](https://rust-lang.github.io/rfcs/3606-temporary-lifetimes-in-tail-expressions.html)): temporaries in a block's tail expression are now dropped immediately after that expression evaluates, before the block's local `let` bindings are dropped (previously they could outlive the block itself in some cases, extended to the *next* temporary scope boundary). Net effect: drop order becomes more predictable/local; existing code that (accidentally) relied on the old extended lifetime will fail to compile with a clear "temporary dropped while borrowed" error rather than silently changing behavior — the compiler catches conflicts at edition-migration time.
- **`let_chains` stabilized in the 2024 edition** ([let-chains.md](https://doc.rust-lang.org/edition-guide/rust-2024/let-chains.html), tracking issue [rust-lang/rust#139951](https://github.com/rust-lang/rust/issues/139951), stabilization PR [#132833](https://github.com/rust-lang/rust/pull/132833)): landed in **Rust 1.88.0** (~April 2025) but gated to edition ≥ 2024 because it required new MIR lowering that isn't backward-compatible with 2021/2018 drop semantics. Syntax: `if let Some(a) = x && let Some(b) = y && a.check(b) { ... }` — chain `let PAT = expr` with `&&` and boolean expressions inside `if`/`while` conditions, no more nested `if let { if let { ... } }` pyramids. Use this freely; it is fully stable, not a nightly feature, as of edition 2024 on any rustc ≥ 1.88 (so also on our 1.93.1 floor). Note there's ongoing follow-up work on `if let` guards in match arms tracked into 2026 ([kivooeo blog on if-let-guard stabilization](https://kivooeo.github.io/blog/if-let-guard/)) — that is a separate, still-in-flight feature, not required for day-1 code.
- **`gen` keyword reserved** ([gen-keyword.md](https://doc.rust-lang.org/edition-guide/rust-2024/gen-keyword.html)): reserved for future generator blocks (`gen { yield x; }`), not yet implemented/stable as of 1.93–1.98. If any identifier named `gen` exists (unlikely), it needs the `r#gen` raw-identifier escape. Just don't name anything `gen`.
- **Never-type fallback change** ([never-type-fallback.md](https://doc.rust-lang.org/edition-guide/rust-2024/never-type-fallback.html)): the fallback type for divergent expressions (`panic!()`, `todo!()`, etc. used where a type is inferred) changes from `()` towards `!` semantics becoming more consistent; mostly invisible to normal code, occasionally surfaces as a new inference ambiguity error in generic code that matched on the old `()` fallback. No action needed proactively; if the compiler flags it, follow its suggested type annotation.
- **Match ergonomics adjustments** ([match-ergonomics.md](https://doc.rust-lang.org/edition-guide/rust-2024/match-ergonomics.html)): refinements to binding modes with `&`/`&mut` patterns (RFC 3627 "match ergonomics 2024"), tightens some edge cases around mutability of bindings under reference patterns. Mostly transparent; write patterns as usual, the compiler is stricter about a few previously-inconsistent mutability inferences.
- **Cargo: resolver v3 is implied by `edition = "2024"`** — see §3 below for detail on the MSRV-aware resolver.
- **Cargo: stricter `default-features` inheritance for workspace deps** ([cargo-inherited-default-features.md](https://doc.rust-lang.org/edition-guide/rust-2024/cargo-inherited-default-features.html)): a member crate can no longer write `default-features = false` on a `{ workspace = true }` dependency unless the workspace-level declaration of that dependency also set `default-features = false`. If we want per-crate opt-out of default features on a shared dependency (e.g. `tokio` with different feature sets between the CLI binary and a `no_std`-friendly core crate), declare it `default-features = false` at the `[workspace.dependencies]` level and re-enable features per member instead.
- **Rustfmt style edition** ([rustfmt-style-edition.md](https://doc.rust-lang.org/edition-guide/rust-2024/rustfmt-style-edition.html)): `cargo fmt` automatically uses the Style Edition matching `edition = "2024"` in `Cargo.toml` — no `rustfmt.toml` setting is required to get 2024-edition formatting rules; it's implied by the crate edition. Only set `style_edition` explicitly in `rustfmt.toml` if you need to pin formatting rules independently of the compiler edition (not needed here).

None of the edition-2024 changes above are breaking for greenfield code — they only bite you during a 2021→2024 migration (which `cargo fix --edition` automates: it inserts `unsafe` blocks, raw-identifier-escapes `gen`, etc.). Starting fresh on 2024 from day one means we simply write to these rules; there's no migration tax.

## 2. rustc/cargo features worth using, current up to 1.93–1.98

Confirmed via [blog.rust-lang.org/releases/](https://blog.rust-lang.org/releases/) and the individual release posts. Recent release cadence observed: 1.93.0 (2026-01-22), 1.94.0 (2026-03-05), 1.95.0 (2026-04-16), 1.96.0 (2026-05-28) / 1.96.1 (2026-06-30), 1.97.0 (2026-07-09) / 1.97.1 (2026-07-16), 1.98.0 (2026-08-20) — the ~6-week train cadence is holding.

Notable stable-as-of-1.93 items relevant to a networking/protocol library ([blog.rust-lang.org/2026/01/22/Rust-1.93.0](https://blog.rust-lang.org/2026/01/22/Rust-1.93.0/)):

- musl targets bumped to musl 1.2.5, materially improving the bundled DNS resolver's handling of large/recursive DNS responses — directly relevant if we ship static `*-linux-musl` binaries for the CLI and rely on system DNS resolution anywhere (mDNS/DNS-SD implementation should be pure-Rust regardless, but this affects any incidental hostname resolution, e.g. connecting to a device by mDNS-resolved hostname via the OS resolver as a fallback).
- `cfg` attributes are now permitted inside `asm!` blocks — not relevant unless we hand-write architecture-specific crypto (unlikely; prefer audited crates).
- Global allocators written in Rust may now use `thread_local!`/`std::thread::current` internally — relevant only if we write a custom allocator, which we should not need to.
- `CARGO_CFG_DEBUG_ASSERTIONS` is now populated for build scripts based on the active profile; `cargo clean --workspace` now exists.
- 23 new API stabilizations in 1.93 alone (see the release post for the itemized list); no single one is architecturally significant for this project, but it's evidence of a healthy, fast-moving stable channel — don't assume "training data circa 2024" API surfaces are current when generating code; check docs.rs for the actual std/library version resolved in the lockfile.

Given the pace of releases, the concrete recommendation is: **do not pin exact rustc versions in prose or in CI matrices beyond MSRV and "stable"**. Treat "stable" as a moving target verified at CI-run-time, and treat MSRV as the only fixed floor (see §5).

## 3. Cargo workspace structure for a multi-crate library + one CLI binary

### 3.1 Virtual manifest layout

Recommended top-level layout for pyatv-rs (protocol/discovery/pairing logic as libraries, one thin CLI binary):

```
pyatv-rs/
├── Cargo.toml                # virtual manifest — no [package], only [workspace]
├── rust-toolchain.toml
├── rustfmt.toml
├── deny.toml
├── .github/workflows/ci.yml
├── crates/
│   ├── pyatv-core/           # protocol state machines, device models, errors
│   ├── pyatv-discovery/      # mDNS/DNS-SD, Bonjour-compatible discovery
│   ├── pyatv-pair/           # pairing/encryption (HAP SRP, MRP pairing, AirPlay)
│   ├── pyatv-proto-mrp/      # MediaRemoteProtocol (protobuf-based) transport
│   ├── pyatv-proto-airplay/  # AirPlay/RAOP transport
│   ├── pyatv-proto-dmap/     # legacy DMAP (older Apple TV gen 1-3) — if in scope
│   └── pyatv-net/            # shared async I/O, TLS/HAP-crypto session wrapping
└── cli/
    └── pyatv-cli/             # bin crate: argument parsing, output formatting
```

A **virtual workspace** (`Cargo.toml` with `[workspace]` and no `[package]`) is the correct choice here rather than making one library crate "primary" and nesting the rest — it keeps `cargo build`/`cargo test` at the root operating over every member uniformly and avoids an arbitrary crate owning the workspace root. Confirmed syntax ([doc.rust-lang.org/cargo/reference/workspaces.html](https://doc.rust-lang.org/cargo/reference/workspaces.html)):

```toml
# /Cargo.toml — virtual manifest
[workspace]
resolver = "3"                      # required explicitly in a virtual manifest (no package.edition to infer it from)
members = ["crates/*", "cli/pyatv-cli"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.93"               # MSRV floor — see §5
license = "MIT OR Apache-2.0"       # or whatever pyatv's own license terms require attribution-wise; verify against pyatv's actual LICENSE before publishing
repository = "https://github.com/<org>/pyatv-rs"
authors = ["..."]

[workspace.dependencies]
tokio = { version = "1", default-features = false, features = ["rt-multi-thread", "net", "macros", "time", "sync"] }
serde = { version = "1", features = ["derive"] }
thiserror = "2"
tracing = "0.1"
bytes = "1"
# ... every cross-crate dependency pinned once, here

[workspace.lints.rust]
unsafe_op_in_unsafe_fn = "deny"    # already deny-by-default in edition 2024, but explicit is better than implicit
missing_debug_implementations = "warn"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
cargo = { level = "warn", priority = -1 }
# nursery is experimental/unstable-lint-set; opt in selectively rather than as a group if used at all
```

Note: `[workspace]` must set `resolver` explicitly in a virtual manifest since there's no `package.edition` for Cargo to infer the resolver version from ([doc.rust-lang.org/edition-guide/rust-2024/cargo-resolver.html](https://doc.rust-lang.org/edition-guide/rust-2024/cargo-resolver.html)); every member's `Cargo.toml` still declares its own `edition = "2024"` (inherited via `edition.workspace = true`), and it's that per-member edition that governs 2024 language semantics for that crate. `resolver` itself is workspace-global and member-level `resolver` keys are ignored.

### 3.2 Member manifest pattern

```toml
# crates/pyatv-core/Cargo.toml
[package]
name = "pyatv-core"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true

[dependencies]
thiserror.workspace = true
serde.workspace = true
tokio = { workspace = true, features = ["sync"] }   # additive on top of workspace-declared features
```

Every field with a `.workspace = true` suffix pulls from `[workspace.package]`/`[workspace.dependencies]`; the supported inheritable package keys are `authors, categories, description, documentation, edition, exclude, homepage, include, keywords, license, license-file, publish, readme, repository, rust-version, version` ([cargo book, workspaces reference](https://doc.rust-lang.org/cargo/reference/workspaces.html)). Workspace-declared dependency `features` are additive with what a member adds locally, and a workspace dependency cannot be marked `optional` at the workspace level — only in the member consuming it. This has been supported since Cargo 1.64 (well below our floor), so it's safe to use unconditionally.

`[lints] workspace = true` at each member pulls the entire `[workspace.lints]` table down — this has been stable since **Rust 1.74** ([RFC 3389](https://rust-lang.github.io/rfcs/3389-manifest-lint.html)), so it predates our MSRV floor comfortably. Caveat: `[lints]` applies uniformly to lib, tests, benches, and examples in that crate — if a particular integration test needs `unwrap()` liberally, use a targeted `#[allow(clippy::unwrap_used)]` at the test-module level rather than weakening the workspace-wide lint.

### 3.3 CLI binary crate

The CLI binary depends on the library crates as ordinary path dependencies (`pyatv-core = { path = "../../crates/pyatv-core" }`, or via workspace-declared paths) and stays thin: argument parsing (`clap` with derive), formatting output, wiring async runtime setup, and translating library errors to exit codes/user messages. Keep all protocol/device logic in the library crates so they remain independently embeddable (e.g. for a future GUI, Home Assistant integration, etc. — mirroring how pyatv itself is a library with a `atvremote` CLI on top, per [pyatv.dev](https://pyatv.dev)).

## 4. `rust-toolchain.toml`

Format, confirmed from [rust-lang.github.io/rustup/overrides.html](https://rust-lang.github.io/rustup/overrides.html):

```toml
# /rust-toolchain.toml
[toolchain]
channel = "1.93.1"          # pin to a specific patch release for reproducible builds; bump deliberately in a PR
components = ["rustfmt", "clippy"]
# targets = ["x86_64-unknown-linux-musl"]   # add if the CLI ships static musl binaries
profile = "minimal"
```

Notes:
- `channel` accepts `stable`, `beta`, `nightly[-YYYY-MM-DD]`, or an exact version like `"1.93.1"`. Pinning an exact version gives every contributor and CI runner byte-identical toolchain behavior; `rustup` auto-installs it on first `cargo`/`rustc` invocation in the directory tree if missing.
- Prefer the TOML form (`rust-toolchain.toml`) over the legacy plain-text `rust-toolchain` file — the plain-text form only holds a bare channel string and can't declare `components`/`targets`/`profile`. If both files exist, the legacy plain-text one wins for backward compatibility, so don't keep both.
- `profile = "minimal"` avoids installing docs/other components rustup would otherwise pull by default, keeping CI container installs fast; add exactly the components you use (`rustfmt`, `clippy`) explicitly.
- Recommendation for this project: pin `channel` to the exact patch version matching whatever the team standardizes on (bump it periodically, e.g. monthly or when a needed stable feature ships), and let CI separately run an additional job against `channel = "stable"` (floating) to catch upstream breakage early — see §7.

## 5. MSRV policy

There is no single universal crates.io-enforced MSRV convention, but the ecosystem in 2026 converges on a few well-documented patterns:

- **Declare it explicitly.** `rust-version = "1.93"` (or `rust-version.workspace = true` at member level, `[workspace.package] rust-version = "1.93"` at the root) makes the MSRV machine-readable to Cargo's resolver v3, which uses it to prefer MSRV-compatible dependency versions during `cargo update`/`cargo add` instead of silently resolving to a dependency version that requires a newer compiler ([doc.rust-lang.org/edition-guide/rust-2024/cargo-resolver.html](https://doc.rust-lang.org/edition-guide/rust-2024/cargo-resolver.html)).
- **Bumping MSRV is not a semver break for a library**, per the (unofficial but widely-followed) Rust API guidelines discussion: crates past 1.0 should bump the *minor* version on an MSRV increase (e.g. 1.1.x → 1.2.0); pre-1.0 crates bump *patch* (0.1.x → 0.1.(x+1)) ([github.com/rust-lang/api-guidelines/discussions/231](https://github.com/rust-lang/api-guidelines/discussions/231)). Document this explicitly in a `CONTRIBUTING.md`/README MSRV section so downstream consumers know what to expect from a version bump.
- **Common concrete policies observed in maintained crates**: "N months behind latest stable" (hyper's stated policy is roughly 6 months, [hyper.rs/contrib/msrv](https://hyper.rs/contrib/msrv/)) or "current stable minus 2 releases" — both amount to roughly the same ~2-4 release window given the 6-week cadence. Given this project's local floor is 1.93.1 and upstream is already at 1.98.0, a reasonable starting MSRV policy is: **MSRV = whatever stable release is current when the workspace is initialized, reviewed and bumped opportunistically whenever a needed feature requires it, verified in CI on every PR.**
- **Automate verification** with `cargo-msrv` (confirmed on crates.io: **cargo-msrv 0.19.3**, [crates.io/crates/cargo-msrv](https://crates.io/crates/cargo-msrv)) — run `cargo msrv find` after dependency bumps, and `cargo msrv verify` in CI against the declared `rust-version` to catch silent MSRV drift from a transitive dependency bump.
- Since `edition = "2024"` implies resolver v3, and resolver v3 changes `resolver.incompatible-rust-versions` from `allow` to `fallback` by default, `cargo update` will already try to avoid picking a dependency version that violates the declared `rust-version` — this is a meaningful safety net but not a substitute for explicit `cargo msrv verify` in CI, since it only affects *resolution*, not compilation correctness against old compilers.

## 6. `rustfmt.toml` — stock vs. custom

Recommendation: **start with an empty or near-empty `rustfmt.toml`** and rely on stable defaults; only add settings that are stable (not gated behind `unstable_features = true`), since `cargo fmt` on the stable channel will warn-and-ignore any nightly-only option and CI would silently diverge from a contributor's local nightly-enabled setup if unstable options were relied upon ([rust-lang/rustfmt Configurations.md](https://github.com/rust-lang/rustfmt/blob/main/Configurations.md)).

```toml
# /rustfmt.toml
edition = "2024"       # kept in sync with workspace edition; also drives the implicit style_edition
# Add only stable, deliberate deviations from default below, e.g.:
# imports_granularity = "Crate"        # stable — groups all imports from one crate into one `use` block
# group_imports = "StdExternalCrate"   # stable — std, then external, then crate-local, blank-line separated
```

Key facts:
- Stable options can be used on any stable `rustc`/`cargo fmt`; unstable options require the nightly channel and `unstable_features = true` in `rustfmt.toml` (or `--unstable-features` on the CLI) — do not adopt unstable formatting options for a project that wants reproducible stable-channel CI ([rust-lang/rustfmt#5511](https://github.com/rust-lang/rustfmt/issues/5511)).
- `style_edition` is implied by `edition = "2024"` in `Cargo.toml`/`rustfmt.toml` automatically since 1.85 — no separate setting is needed to get 2024-edition formatting conventions.
- File can be named `rustfmt.toml` or `.rustfmt.toml`, resolved by walking up from the current crate to any ancestor directory — one copy at the workspace root is sufficient; per-member `rustfmt.toml` files are unnecessary unless a specific crate legitimately needs different formatting (avoid this).

## 7. Dependency/license/security auditing: `cargo-deny`

Confirmed current version on crates.io: **cargo-deny 0.20.2** ([crates.io/crates/cargo-deny](https://crates.io/crates/cargo-deny)). Config file is `deny.toml` at the workspace root, checked via `cargo deny check`. Four check categories: `advisories` (RustSec DB), `bans` (duplicate/banned crates), `licenses` (SPDX allow-list), `sources` (registry/git source restrictions) — ([embarkstudios.github.io/cargo-deny](https://embarkstudios.github.io/cargo-deny/), template: [github.com/EmbarkStudios/cargo-deny/blob/main/deny.template.toml](https://github.com/EmbarkStudios/cargo-deny/blob/main/deny.template.toml)).

```toml
# /deny.toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
yanked = "deny"
ignore = []          # RUSTSEC-YYYY-NNNN IDs go here with a comment explaining why, only as a last resort

[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Unicode-3.0",
]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"   # tighten to "deny" once the dependency graph stabilizes
wildcards = "deny"
deny = [
    { crate = "openssl", use-instead = "rustls" },
    { crate = "openssl-sys", use-instead = "rustls" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

CI integration via the official action, confirmed **v2** major tag ([github.com/EmbarkStudios/cargo-deny-action](https://github.com/EmbarkStudios/cargo-deny-action)):

```yaml
- uses: EmbarkStudios/cargo-deny-action@v2
  with:
    command: check
    arguments: --all-features
```

Prefer `rustls` over `openssl` bindings for any TLS/HAP-crypto layer given this is a from-scratch reimplementation targeting cross-compilation to embedded/CLI targets — avoids the OpenSSL system-linking/cross-compile pain entirely, which is the reasoning behind the `deny openssl, use-instead rustls` pattern shown in cargo-deny's own self-check config.

## 8. Test runner: `cargo-nextest`

Confirmed current version on crates.io: **cargo-nextest 0.9.143** ([crates.io/crates/cargo-nextest](https://crates.io/crates/cargo-nextest)). Runs each test as its own process (rather than cargo-test's single-process-per-binary model), giving real parallelism across tests within a binary, per-test timeout/retry support, and structured JUnit XML output that GitHub Actions consumes natively for inline failure annotations ([nexte.st](https://nexte.st/)).

Recommended CI install path: `taiki-e/install-action` (confirmed v2 line, e.g. **v2.69.1** as of 2026-03-19, [github.com/taiki-e/install-action](https://github.com/taiki-e/install-action)) rather than `cargo install cargo-nextest` from source, since it fetches prebuilt binaries and is dramatically faster in CI:

```yaml
- uses: taiki-e/install-action@v2
  with:
    tool: nextest
```

Add a `.config/nextest.toml` with a CI-specific profile:

```toml
[profile.ci]
retries = 2
failure-output = "immediate-final"
fail-fast = false
```

Run with `cargo nextest run --profile ci`. Note: `cargo nextest run` does not run doctests (a known nextest limitation) — keep a separate `cargo test --doc` step in CI for doctest coverage on the library crates.

## 9. GitHub Actions CI conventions for Rust, 2026

Two composite actions are the de-facto standard:

- **`actions-rust-lang/setup-rust-toolchain`** (confirmed `@v1` major tag current, [github.com/actions-rust-lang/setup-rust-toolchain](https://github.com/actions-rust-lang/setup-rust-toolchain)) — installs via rustup, wraps `Swatinem/rust-cache` internally (so you usually don't need to call rust-cache separately unless you want finer control), and installs GitHub Actions "problem matchers" that turn `cargo build`/`clippy`/`rustfmt` diagnostics into inline PR annotations. Key inputs: `toolchain` (default `stable`), `components`, `target`, `cache` (default `true`), `rustflags` (default `-D warnings` — i.e. it treats warnings as errors by default, which is desirable for CI but should be a deliberate, known default, not a surprise), `matcher` (default `true`).
- **`Swatinem/rust-cache`** (confirmed `@v2` major tag current, [github.com/Swatinem/rust-cache](https://github.com/Swatinem/rust-cache)) — smart caching of `~/.cargo` registry/git plus `./target`, automatically scoped per-workspace and per-job, with automatic pruning of stale/unused cache entries (unlike a naive `actions/cache` on `target/` which grows unbounded). Useful standalone inputs when not relying on setup-rust-toolchain's built-in wiring: `workspaces` (multi-workspace repos), `cache-targets`, `save-if` (e.g. only save from `main` branch pushes to avoid cache thrashing from PR branches).

Example workflow, synthesizing the confirmed patterns above:

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always

jobs:
  fmt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          components: rustfmt
      - uses: actions-rust-lang/rustfmt@v1

  clippy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          components: clippy
      - run: cargo clippy --workspace --all-targets --all-features -- -D warnings

  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        toolchain: [stable]
        include:
          - os: ubuntu-latest
            toolchain: "1.93.1"   # pinned MSRV job, keep in sync with rust-toolchain.toml / rust-version
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v6
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: ${{ matrix.toolchain }}
      - uses: taiki-e/install-action@v2
        with:
          tool: nextest
      - run: cargo nextest run --workspace --profile ci
      - run: cargo test --workspace --doc

  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: EmbarkStudios/cargo-deny-action@v2

  msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - uses: taiki-e/install-action@v2
        with:
          tool: cargo-msrv
      - run: cargo msrv verify --workspace
```

Matrix design notes: separate `fmt`/`clippy`/`test`/`deny`/`msrv` into distinct jobs (not one monolithic job) so failures are attributable at a glance in the PR checks list and jobs can run in parallel; `fail-fast: false` on the test matrix so an OS-specific failure doesn't hide failures on other OSes in the same run; pin `actions/checkout` to a specific major (`@v6` confirmed current, per [github.com/actions/checkout/releases](https://github.com/actions/checkout/releases) — v6.1.0 was the latest full release found during this research, with an early v7 marketplace listing also observed, so re-verify at implementation time) rather than `@main`, for supply-chain hygiene; consider Dependabot or Renovate configured specifically to bump `.github/workflows/*.yml` action pins (`uses: foo@vN`) on a schedule, since GitHub Actions supply-chain pinning is a distinct maintenance surface from `Cargo.lock`.

## 10. Additional recommended tooling (grounded, current versions)

All versions below confirmed directly against the crates.io API (`https://crates.io/api/v1/crates/<name>`, field `max_version`) on 2026-08-24:

| Tool | Purpose | crates.io version confirmed |
|---|---|---|
| `cargo-nextest` | parallel test runner, JUnit output | 0.9.143 |
| `cargo-deny` | license/advisory/duplicate-dependency policy | 0.20.2 |
| `cargo-msrv` | MSRV discovery/verification | 0.19.3 |
| `cargo-hack` | run checks across feature-flag powersets (`cargo hack check --feature-powerset`) — valuable given this workspace will have per-protocol optional features (mrp/airplay/dmap) | 0.6.45 |
| `cargo-audit` | standalone RustSec advisory scan (cargo-deny's `advisories` check overlaps this; keep one, not both, to avoid duplicate signal — cargo-deny is the more complete tool since it also does licenses/bans) | 0.22.2 |
| `cargo-machete` | detect unused dependencies in `Cargo.toml` | 0.9.2 |

`cargo-hack` is worth calling out specifically for this project: since pyatv-rs will likely gate `mrp`/`airplay`/`dmap`/`tls-rustls` behind Cargo features so consumers can build a slim binary supporting only the protocols they need, `cargo hack check --each-feature` (or `--feature-powerset` for exhaustive but combinatorially expensive coverage) in CI is the standard way to catch "this only compiles because some other feature happened to be on" bugs that a single `--all-features` build would hide.

## Open questions

- Confirm whether pyatv-rs should target `rust-version = "1.93"` matching the sandboxed dev environment exactly, or adopt a rolling "N releases behind current stable" MSRV policy from day one — this is a project-governance decision, not something derivable from Rust docs alone, and should be settled before `[workspace.package] rust-version` is committed.
- Confirm final crate/module boundary names (`pyatv-core`, `pyatv-discovery`, etc. above are illustrative, not verified against a separate architecture decision) once the architecture-stage research on pyatv's actual protocol boundaries (MRP/AirPlay/DMAP/Companion) is complete — the workspace layout in §3.1 should be reconciled with that document rather than treated as final.
- Verify at implementation time whether `actions/checkout@v7` has fully superseded `@v6` as the marketplace-recommended tag (both were observed live during this research on 2026-08-24; v6.1.0 was confirmed released, v7 appeared in some marketplace listings but wasn't independently confirmed via a dedicated release-notes fetch) — re-check `github.com/actions/checkout/releases` before locking the CI workflow.
- Decide the `clippy::pedantic`/`clippy::nursery` posture concretely: `pedantic` is stable-quality but noisy (expect per-file `#[allow]`s); `nursery` lints are explicitly unstable/experimental and can change or disappear between clippy releases — recommend starting with `all` + `pedantic` as `warn` (not `deny`) in `[workspace.lints.clippy]`, and deciding per-lint whether to promote to `deny` in CI (`-D warnings`) only after the initial codebase is written and the pedantic-lint noise has been triaged once, rather than blocking day-one commits on a lint set nobody has tuned yet.
- Decide whether `cargo-audit` should be dropped entirely in favor of `cargo-deny`'s `advisories` check (recommended above) or kept as a secondary/faster CI gate — both pull from the same RustSec advisory database, so running both is redundant signal, not redundant safety.
- Determine whether any FFI to system frameworks (e.g. macOS Keychain for HAP pairing credential storage, or a system mDNS resolver as a fallback) will be needed — if so, the `unsafe extern` edition-2024 syntax in §1 becomes directly relevant and should be revisited with concrete signatures once that architecture decision is made.
