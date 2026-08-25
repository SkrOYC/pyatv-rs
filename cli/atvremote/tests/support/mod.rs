//! Running the real `atvremote` binary against a hermetic Companion device.
//!
//! The binary is invoked as a subprocess — `env!("CARGO_BIN_EXE_atvremote")` is the path Cargo
//! builds it to — because that is the only way to test what a user actually runs: argument parsing,
//! dispatch, formatting and the exit code, all at once.
//!
//! Every invocation goes through `--manual`, which is what makes this hermetic. A scan would need
//! multicast mDNS and would find whatever real devices are on the tester's network; `--manual`
//! skips discovery entirely and dials `127.0.0.1:<port>` directly, so the test is deterministic on
//! a laptop and in CI alike.
//!
//! Storage is `--storage none` unless a test says otherwise, so nothing here can read or write the
//! developer's own `~/.pyatv.conf`.

#![allow(
    dead_code,
    reason = "each test binary uses a different subset of this harness"
)]

use std::process::Output;
use std::sync::Arc;

use pyatv_core::consts::Protocol;
use pyatv_core::interface::PairingHandler as _;
use pyatv_core::models::BaseService;
use pyatv_core::storage::MemoryStorage;
use pyatv_pairing::server::PIN_CODE;
use pyatv_proto_companion::auth::PairSetupOptionsCompanion;
use pyatv_proto_companion::pairing::{CompanionPairingHandler, CompanionPairingOptions};
use pyatv_proto_companion::test_support::fake_companion::FakeCompanionDevice;
use pyatv_proto_companion::test_support::fake_state::DeviceState;

/// The identifier the fake device is filed under.
pub const DEVICE_IDENTIFIER: &str = "AA:BB:CC:DD:EE:FF";

/// The PIN the fake device expects, re-exported so tests do not import the pairing crate too.
pub const DEVICE_PIN: u32 = PIN_CODE;

/// A running fake device plus the credentials needed to talk to it.
#[derive(Debug)]
pub struct Harness {
    device: FakeCompanionDevice,
    credentials: String,
}

impl Harness {
    /// Start the device and pair with it, so commands can connect straight away.
    pub async fn start() -> Self {
        let device = FakeCompanionDevice::start(PIN_CODE).await;
        let credentials = pair(&device).await;
        Self {
            device,
            credentials,
        }
    }

    /// Start the device without pairing, for the tests that drive `atvremote pair` themselves.
    pub async fn unpaired() -> Self {
        Self {
            device: FakeCompanionDevice::start(PIN_CODE).await,
            credentials: String::new(),
        }
    }

    /// Change what the device believes before a command runs.
    pub async fn arrange(&self, arrange: impl FnOnce(&mut DeviceState)) {
        arrange(&mut *self.device.state().lock().await);
    }

    /// Read what the device believes after a command ran.
    pub async fn inspect<T>(&self, inspect: impl FnOnce(&DeviceState) -> T) -> T {
        let state = self.device.state();
        let guard = state.lock().await;
        inspect(&guard)
    }

    /// The `--manual` flags that point `atvremote` at this device, credentials included.
    pub fn target(&self) -> Vec<String> {
        let mut flags = self.address_flags();
        if !self.credentials.is_empty() {
            flags.push("--companion-credentials".to_owned());
            flags.push(self.credentials.clone());
        }
        flags
    }

    /// The same, without credentials — for `pair`, which is what produces them.
    pub fn address_flags(&self) -> Vec<String> {
        [
            "--manual",
            "--address",
            "127.0.0.1",
            "--port",
            &self.device.address().port().to_string(),
            "--protocol",
            "companion",
            "--id",
            DEVICE_IDENTIFIER,
            "--storage",
            "none",
        ]
        .iter()
        .map(|flag| (*flag).to_owned())
        .collect()
    }

    /// Run `atvremote` against this device with `args` appended to the target flags.
    pub async fn run(&self, args: &[&str]) -> Run {
        let mut all = self.target();
        all.extend(args.iter().map(|arg| (*arg).to_owned()));
        spawn(&all, None).await
    }

    /// The same, with `stdin` fed to the process.
    pub async fn run_with_input(&self, args: &[&str], stdin: &str) -> Run {
        let mut all = self.target();
        all.extend(args.iter().map(|arg| (*arg).to_owned()));
        spawn(&all, Some(stdin.to_owned())).await
    }
}

/// One completed run of the binary.
#[derive(Debug)]
pub struct Run {
    /// Everything written to standard output.
    pub stdout: String,
    /// Everything written to standard error, which is where logs and notices go.
    pub stderr: String,
    /// The process exit code.
    pub code: i32,
}

impl Run {
    /// Assert the run succeeded, showing both streams when it did not.
    #[track_caller]
    pub fn expect_success(&self) -> &Self {
        assert_eq!(
            self.code, 0,
            "expected success\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout, self.stderr
        );
        self
    }

    /// Assert the run failed with the exit code every pyatv failure path uses
    /// (`pyatv/scripts/atvremote.py:975-979`).
    #[track_caller]
    pub fn expect_failure(&self) -> &Self {
        assert_eq!(
            self.code, 1,
            "expected failure\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout, self.stderr
        );
        self
    }

    /// Standard output parsed as one JSON object.
    #[track_caller]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "stdout must be one JSON object ({error}): {:?}",
                self.stdout
            )
        })
    }

    /// Standard output parsed as one JSON object per line, which is what `push_updates` emits.
    #[track_caller]
    pub fn json_lines(&self) -> Vec<serde_json::Value> {
        self.stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|error| panic!("every line must be JSON ({error}): {line:?}"))
            })
            .collect()
    }

    /// pyatv's own `all_in` assertion (`tests/utils.py`): every needle appears somewhere.
    #[track_caller]
    pub fn assert_contains(&self, needles: &[&str]) -> &Self {
        for needle in needles {
            assert!(
                self.stdout.contains(needle),
                "{needle:?} is missing from stdout:\n{}",
                self.stdout
            );
        }
        self
    }
}

/// Run the binary with `args`, optionally feeding it `stdin`.
///
/// Public so the tests that build their own argument list — `pair`, `commands`, and the ones that
/// deliberately point at nothing — can reach it without a [`Harness`].
pub async fn run_binary(args: &[String], stdin: Option<String>) -> Run {
    spawn(args, stdin).await
}

/// Run the binary with `args`, optionally feeding it `stdin`.
async fn spawn(args: &[String], stdin: Option<String>) -> Run {
    use tokio::io::AsyncWriteExt as _;

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_atvremote"));
    command
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        });

    let mut child = command.spawn().expect("the binary must start");

    if let Some(stdin) = stdin {
        let mut handle = child.stdin.take().expect("stdin was piped");
        handle
            .write_all(stdin.as_bytes())
            .await
            .expect("stdin must be writable");
        handle.shutdown().await.expect("stdin must close");
    }

    let Output {
        status,
        stdout,
        stderr,
    } = child
        .wait_with_output()
        .await
        .expect("the binary must finish");

    Run {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        code: status.code().unwrap_or(-1),
    }
}

/// Run Companion pair-setup and return the credential string.
///
/// The same exchange `atvremote --protocol companion pair` drives; done in-process here so that the
/// tests which are *not* about pairing do not pay for it twice.
async fn pair(device: &FakeCompanionDevice) -> String {
    let mut service = BaseService::new(Protocol::Companion, device.address().port());
    service.identifier = Some(DEVICE_IDENTIFIER.to_owned());

    let handler = CompanionPairingHandler::new(
        CompanionPairingOptions {
            address: device.address().ip(),
            service,
            device_identifier: DEVICE_IDENTIFIER.to_owned(),
            setup: PairSetupOptionsCompanion::default(),
        },
        Arc::new(MemoryStorage::new()),
    );

    handler.begin().await.expect("pairing must begin");
    handler.pin(PIN_CODE).expect("the PIN must be accepted");
    handler.finish().await.expect("pairing must finish");
    handler
        .service()
        .credentials
        .expect("pairing must produce credentials")
}
