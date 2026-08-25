//! Subcommand dispatch, device resolution and storage.
//!
//! Three routes out of [`run`], matching the three upstream keeps apart: the global commands that
//! never touch a device (`atvremote.py:719-721`), the settings commands that read and write storage
//! (`atvremote.py:473-501`), and everything else, which connects first
//! (`atvremote.py:862-884`).
//!
//! Output formatting lives in [`crate::report`](mod@crate::report), not here and not in the library: `pyatv` returns
//! typed values and only the CLI should decide how they look on a terminal.

mod apps;
mod audio;
mod buttons;
mod device;
mod media;
mod pair;
mod repl;
mod settings;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use pyatv::{BaseConfig, BaseService, Protocol, ScanOptions, Storage};

use crate::cli::{Cli, Command, StorageKind};
use crate::report::Reporter;

/// Run whichever subcommand was requested.
///
/// # Errors
///
/// Propagates any library error, plus "no matching device found" when the selectors do not resolve
/// to exactly one device.
pub async fn run(cli: &Cli) -> Result<()> {
    let reporter = Reporter::new(cli.is_json());

    match &cli.command {
        Command::Scan => scan(cli, reporter).await,
        Command::Pair => pair::run(cli, reporter).await,
        Command::Commands => {
            buttons::print_vocabulary(reporter);
            Ok(())
        }
        command if command.needs_connection() => device::run(cli, reporter).await,
        _ => settings::run(cli, reporter).await,
    }
}

/// Scan options built from the global flags, shared by every subcommand that needs a device.
///
/// `--name` suppresses the identifier filter, because upstream's `_scan_for_device` only passes
/// `identifier` when no name was given and then filters the results by name itself
/// (`atvremote.py:61-71`).
fn scan_options(cli: &Cli) -> ScanOptions {
    let identifiers = if cli.name.is_some() {
        HashSet::new()
    } else {
        cli.id.iter().cloned().collect()
    };

    ScanOptions {
        timeout: Duration::from_secs(cli.scan_timeout),
        identifiers,
        protocols: cli
            .scan_protocols
            .iter()
            .map(|protocol| Protocol::from(*protocol))
            .collect(),
        hosts: cli.scan_hosts.clone(),
    }
}

/// Discover devices and print each one.
async fn scan(cli: &Cli, reporter: Reporter) -> Result<()> {
    let storage = open_storage(cli)?;
    let devices = discover(cli, storage.as_ref()).await?;
    reporter.devices(&devices);

    // Discovery may have filed identifiers for devices the settings file had not seen, which
    // upstream persists on the way out (`pyatv/scripts/atvremote.py:736`). A scan that learned
    // nothing new writes nothing.
    storage.save()?;
    Ok(())
}

/// Scan, apply stored settings, and apply the `--name` filter.
async fn discover(cli: &Cli, storage: &dyn Storage) -> Result<Vec<BaseConfig>> {
    let mut devices = pyatv::scan(scan_options(cli)).await?;
    apply_settings(storage, &mut devices)?;

    if let Some(name) = &cli.name {
        devices.retain(|device| device.name == *name);
    }
    Ok(devices)
}

/// Apply stored credentials to freshly discovered devices.
///
/// `pyatv.scan()` does this itself (`pyatv/__init__.py:94-97`); this port's `scan()` takes no
/// storage argument, so the CLI does it instead. Devices without an identifier are skipped rather
/// than failing the whole scan — upstream never reaches them because it filters on `ready` first.
fn apply_settings(storage: &dyn Storage, devices: &mut [BaseConfig]) -> Result<()> {
    for device in devices.iter_mut().filter(|device| device.ready()) {
        let settings = storage
            .get_settings(device)
            .with_context(|| format!("could not read the settings for {}", device.name))?;
        device.apply(&settings);
    }

    Ok(())
}

/// Find the one device a command should act on.
///
/// Mirrors `_scan_for_device` (`atvremote.py:58-82`): scan, filter, then require exactly one match.
/// Upstream errors out when more than one device answered rather than picking arbitrarily, and so
/// does this. `--manual` skips the scan entirely (`atvremote.py:722-734`).
///
/// # Errors
///
/// Fails when `--manual` is missing one of its three required flags, when nothing answered, or when
/// more than one device did.
pub async fn resolve_device(cli: &Cli, storage: &dyn Storage) -> Result<BaseConfig> {
    if cli.manual {
        return manual_config(cli);
    }

    let mut devices = discover(cli, storage).await?;

    match devices.len() {
        0 => bail!("no device found"),
        1 => Ok(devices.remove(0)),
        _ => {
            let identifiers: Vec<&str> = devices
                .iter()
                .filter_map(pyatv::BaseConfig::identifier)
                .collect();
            bail!(
                "found {} devices, use --id to pick one: {}",
                devices.len(),
                identifiers.join(", ")
            )
        }
    }
}

/// Build a config from the command line alone, for `--manual`.
///
/// `_manual_device` (`atvremote.py:786-807`) minus `--service-properties`, whose ad-hoc
/// `Xkey=valXkey=val` encoding exists to feed mDNS TXT records to a protocol that would otherwise
/// have scanned for them; nothing in this port reads TXT records off a manual service yet, so the
/// flag would be inert.
///
/// The identifier is required here where upstream lets it be `None`: `pyatv::connect` refuses a
/// config without one (`crates/pyatv/src/connect.rs`), since storage is keyed by it.
fn manual_config(cli: &Cli) -> Result<BaseConfig> {
    let (Some(address), Some(port), Some(protocol)) = (cli.address, cli.port, cli.protocol) else {
        // `_LOGGER.error("You must specify address, port and protocol in manual mode")`
        // (`atvremote.py:729-731`).
        bail!("you must specify --address, --port and --protocol in manual mode");
    };
    let protocol = Protocol::from(protocol);

    let identifier = match cli.id.as_slice() {
        [identifier] => identifier.clone(),
        [] => bail!("--manual needs --id, which is what settings are stored under"),
        // `parser.error("--manual only supports one identifier to --id")` (`atvremote.py:686-687`).
        _ => bail!("--manual only supports one identifier to --id"),
    };

    let name = cli.name.clone().unwrap_or_else(|| address.to_string());
    let mut config = BaseConfig::new(name, address);

    let mut service = BaseService::new(protocol, port);
    service.identifier = Some(identifier);
    service.credentials = cli
        .credentials
        .for_protocol(protocol)
        .map(ToOwned::to_owned);
    service.password = cli.passwords.for_protocol(protocol).map(ToOwned::to_owned);
    config.add_service(service);

    Ok(config)
}

/// Apply the `--<protocol>-credentials` and `--<protocol>-password` flags over whatever storage
/// supplied.
///
/// `_set_credentials` / `_set_password` (`atvremote.py:753-779`): a command-line value wins over the
/// stored one, and an explicitly empty string *unsets* the stored value rather than being treated
/// as absent.
pub fn apply_overrides(cli: &Cli, config: &mut BaseConfig) {
    for (protocol, credentials) in cli.credentials.iter() {
        let Some(credentials) = credentials else {
            continue;
        };
        let Some(service) = config.get_service_mut(protocol) else {
            tracing::debug!(
                ?protocol,
                "ignoring a credential override for an absent service"
            );
            continue;
        };
        service.credentials = (!credentials.is_empty()).then(|| credentials.to_owned());
    }

    for (protocol, password) in cli.passwords.iter() {
        let Some(password) = password else { continue };
        let Some(service) = config.get_service_mut(protocol) else {
            tracing::debug!(
                ?protocol,
                "ignoring a password override for an absent service"
            );
            continue;
        };
        service.password = (!password.is_empty()).then(|| password.to_owned());
    }
}

/// Open the credential store the global flags point at, already loaded.
///
/// `get_storage` (`pyatv/scripts/__init__.py:116-122`): `--storage none` is in-memory and touches
/// no disk, `--storage file` defaults to `$HOME/.pyatv.conf` — the same path pyatv's own
/// `FileStorage` uses, and the same bytes, so a file written by either implementation is readable
/// by the other.
///
/// The load happens here rather than at the call site because it is not optional: a `FileStorage`
/// that is saved without having been loaded writes an empty document over the user's credentials.
/// Upstream loads at the same point (`atvremote.py:715-716`).
///
/// # Blocking
///
/// [`pyatv::Storage`] is a synchronous trait, so this reads the file on the calling thread — and
/// its callers are `async fn`s, so that is a Tokio worker. This is deliberate rather than
/// overlooked: `atvremote` is a one-shot process that loads once at the top of a command and saves
/// once at the bottom, the file is a few kilobytes of local JSON, and there is no other task on the
/// runtime whose latency the read could affect. A long-lived application embedding this workspace
/// should wrap these calls in [`tokio::task::spawn_blocking`], which is what the library itself
/// does at the one point it writes to storage without the caller asking
/// (`pyatv_proto_companion::pairing`).
///
/// # Errors
///
/// Fails if no settings path could be determined, or if the file exists but could not be read or
/// parsed.
pub fn open_storage(cli: &Cli) -> Result<Arc<dyn Storage>> {
    if cli.storage == StorageKind::None {
        return Ok(Arc::new(pyatv::MemoryStorage::new()));
    }

    let path = match &cli.storage_filename {
        Some(path) => path.clone(),
        None => pyatv::FileStorage::default_path()
            .context("could not determine the default settings file path")?,
    };

    let storage = pyatv::FileStorage::new(path);
    storage
        .load()
        .with_context(|| format!("could not read {}", storage.path().display()))?;

    Ok(Arc::new(storage))
}

#[cfg(test)]
mod tests {
    use super::{apply_overrides, manual_config, scan_options};
    use crate::cli::Cli;
    use clap::Parser as _;
    use pyatv::{BaseConfig, BaseService, Protocol};

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("these arguments must parse")
    }

    #[test]
    fn scan_options_carry_every_selector() {
        let options = parse(&[
            "atvremote",
            "--id",
            "aa,bb",
            "--scan-hosts",
            "10.0.0.1",
            "--scan-protocols",
            "mrp",
            "-t",
            "9",
            "scan",
        ]);
        let options = scan_options(&options);

        assert_eq!(options.timeout.as_secs(), 9);
        assert_eq!(options.identifiers.len(), 2);
        assert!(options.protocols.contains(&Protocol::Mrp));
        assert_eq!(options.hosts.len(), 1);
    }

    /// `_scan_for_device` passes `identifier` only when `--name` is absent (`atvremote.py:61-62`).
    #[test]
    fn a_name_filter_suppresses_the_identifier_filter() {
        let options = scan_options(&parse(&[
            "atvremote",
            "--id",
            "aa",
            "--name",
            "Living Room",
            "scan",
        ]));
        assert!(options.identifiers.is_empty());
    }

    #[test]
    fn manual_mode_builds_a_config_from_the_command_line() {
        let config = manual_config(&parse(&[
            "atvremote",
            "--manual",
            "--address",
            "10.0.0.5",
            "--port",
            "49152",
            "--protocol",
            "companion",
            "--id",
            "abc",
            "--companion-credentials",
            "secret",
            "playing",
        ]))
        .expect("a complete manual config must build");

        assert_eq!(config.address.to_string(), "10.0.0.5");
        assert_eq!(config.identifier(), Some("abc"));

        let service = config
            .get_service(Protocol::Companion)
            .expect("the named protocol must be present");
        assert_eq!(service.port, 49152);
        assert_eq!(service.credentials.as_deref(), Some("secret"));
    }

    #[test]
    fn manual_mode_requires_address_port_and_protocol() {
        for args in [
            vec!["atvremote", "--manual", "--id", "a", "playing"],
            vec![
                "atvremote",
                "--manual",
                "--address",
                "10.0.0.5",
                "--id",
                "a",
                "playing",
            ],
            vec![
                "atvremote",
                "--manual",
                "--address",
                "10.0.0.5",
                "--port",
                "1",
                "--id",
                "a",
                "playing",
            ],
        ] {
            assert!(
                manual_config(&parse(&args)).is_err(),
                "{args:?} must be rejected"
            );
        }
    }

    /// `parser.error("--manual only supports one identifier to --id")` (`atvremote.py:686-687`).
    #[test]
    fn manual_mode_refuses_more_than_one_identifier() {
        let error = manual_config(&parse(&[
            "atvremote",
            "--manual",
            "--address",
            "10.0.0.5",
            "--port",
            "1",
            "--protocol",
            "mrp",
            "--id",
            "a,b",
            "playing",
        ]))
        .expect_err("two identifiers must be rejected");

        assert!(error.to_string().contains("only supports one identifier"));
    }

    fn config_with_companion() -> BaseConfig {
        let mut config = BaseConfig::new("Fake", "10.0.0.5".parse().expect("a literal address"));
        let mut service = BaseService::new(Protocol::Companion, 49153);
        service.identifier = Some("abc".to_owned());
        service.credentials = Some("stored".to_owned());
        config.add_service(service);
        config
    }

    #[test]
    fn a_credential_flag_wins_over_storage() {
        let mut config = config_with_companion();
        apply_overrides(
            &parse(&[
                "atvremote",
                "--companion-credentials",
                "from-the-command-line",
                "playing",
            ]),
            &mut config,
        );

        assert_eq!(
            config
                .get_service(Protocol::Companion)
                .and_then(|it| it.credentials.as_deref()),
            Some("from-the-command-line")
        );
    }

    /// `if arg_value == "": value = None` (`atvremote.py:757-760`).
    #[test]
    fn an_empty_credential_flag_unsets_the_stored_value() {
        let mut config = config_with_companion();
        apply_overrides(
            &parse(&["atvremote", "--companion-credentials", "", "playing"]),
            &mut config,
        );

        assert_eq!(
            config
                .get_service(Protocol::Companion)
                .and_then(|it| it.credentials.as_deref()),
            None
        );
    }

    #[test]
    fn an_absent_flag_leaves_storage_alone() {
        let mut config = config_with_companion();
        apply_overrides(&parse(&["atvremote", "playing"]), &mut config);

        assert_eq!(
            config
                .get_service(Protocol::Companion)
                .and_then(|it| it.credentials.as_deref()),
            Some("stored")
        );
    }
}
