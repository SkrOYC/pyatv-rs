//! The settings subcommands.
//!
//! `SettingsCommands` (`pyatv/scripts/atvremote.py:473-501`): `print_settings`,
//! `change_setting`, `unset_setting` and `remove_settings`.
//!
//! # Two divergences, both deliberate
//!
//! **These do not connect.** Upstream reaches the model through `atv.settings`, which only exists
//! once `connect()` has returned (`atvremote.py:485`), so `atvremote print_settings` on an unpaired
//! device fails before it prints anything. `pyatv_core::interface::AppleTV` has no `settings()`
//! accessor, and adding one is a library change this CLI has no business making — so the record is
//! read straight out of [`pyatv::Storage`] instead, which is where `atv.settings` points anyway.
//! The output is identical and it works on a device you have not paired with.
//!
//! **The `(type)` suffix is dropped.** `stringify_model` prints `path = value (str, NoneType)`
//! (`pyatv/support/__init__.py:173-200`), reading the annotation off the pydantic field. Rust has
//! no runtime field annotations, so [`entries`] enumerates the model by hand and prints
//! `path = value`. pyatv's own smoke test asserts on the substring `protocols.raop.password = None`
//! (`tests/scripts/test_atvremote.py:141`), which this satisfies.

use anyhow::{Result, bail};
use pyatv::{MrpTunnel, Protocol, Settings, Storage};

use crate::cli::{Cli, Command};
use crate::report::Reporter;

/// Run a settings command, resolving the device first.
///
/// # Errors
///
/// Fails when the device cannot be resolved, when the setting path is unknown, or when the store
/// could not be written.
pub async fn run(cli: &Cli, reporter: Reporter) -> Result<()> {
    let storage = super::open_storage(cli)?;
    let config = super::resolve_device(cli, storage.as_ref()).await?;
    let settings = storage.get_settings(&config)?;

    apply(storage.as_ref(), settings, &cli.command, reporter)?;
    storage.save()?;
    Ok(())
}

/// The same, for a session that is already connected — the `cli` REPL's route in.
///
/// # Errors
///
/// As [`run`], minus the resolution failures.
pub fn run_connected(cli: &Cli, command: &Command, reporter: Reporter) -> Result<()> {
    let storage = super::open_storage(cli)?;
    let Some(identifier) = cli.id.first() else {
        bail!("settings commands need --id to say which device they are about");
    };
    let Some(settings) = storage.find_settings(identifier)? else {
        bail!("no settings are stored for {identifier}");
    };

    apply(storage.as_ref(), settings, command, reporter)?;
    storage.save()?;
    Ok(())
}

/// Read or write one record.
fn apply(
    storage: &dyn Storage,
    mut settings: Settings,
    command: &Command,
    reporter: Reporter,
) -> Result<()> {
    match command {
        Command::PrintSettings => reporter.settings(&entries(&settings)),

        Command::ChangeSetting { setting, value } => {
            set(&mut settings, setting, Some(value.as_str()))?;
            storage.set_settings(settings)?;
            reporter.acknowledge("change_setting");
        }
        Command::UnsetSetting { setting } => {
            set(&mut settings, setting, None)?;
            storage.set_settings(settings)?;
            reporter.acknowledge("unset_setting");
        }
        Command::RemoveSettings => {
            storage.remove_settings(&settings)?;
            reporter.acknowledge("remove_settings");
        }

        other => unreachable!("{other:?} is not a settings command"),
    }

    Ok(())
}

/// Every field of the model as a dotted path and its current value.
///
/// `stringify_model`'s recursive walk (`pyatv/support/__init__.py:189-198`), written out because
/// Rust has no `dict(model).items()`. The order is the declaration order of
/// [`pyatv::Settings`], which is the order upstream prints in.
#[must_use]
pub fn entries(settings: &Settings) -> Vec<(String, Option<String>)> {
    let info = &settings.info;
    let mut entries = vec![
        ("info.name".to_owned(), Some(info.name.clone())),
        ("info.mac".to_owned(), Some(info.mac.clone())),
        ("info.model".to_owned(), Some(info.model.clone())),
        ("info.device_id".to_owned(), Some(info.device_id.clone())),
        ("info.rp_id".to_owned(), Some(info.rp_id.clone())),
        ("info.os_name".to_owned(), Some(info.os_name.clone())),
        ("info.os_build".to_owned(), Some(info.os_build.clone())),
        ("info.os_version".to_owned(), Some(info.os_version.clone())),
    ];

    let protocols = &settings.protocols;
    for protocol in [
        Protocol::AirPlay,
        Protocol::Companion,
        Protocol::Dmap,
        Protocol::Mrp,
        Protocol::Raop,
    ] {
        let prefix = format!("protocols.{}", protocol.as_str().to_ascii_lowercase());
        entries.push((
            format!("{prefix}.identifier"),
            protocols.identifier(protocol).map(ToOwned::to_owned),
        ));
        entries.push((
            format!("{prefix}.credentials"),
            protocols.credentials(protocol).map(ToOwned::to_owned),
        ));
        if matches!(protocol, Protocol::AirPlay | Protocol::Raop) {
            entries.push((
                format!("{prefix}.password"),
                protocols.password(protocol).map(ToOwned::to_owned),
            ));
        }
    }

    entries.push((
        "protocols.airplay.mrp_tunnel".to_owned(),
        Some(tunnel_name(protocols.airplay.mrp_tunnel).to_owned()),
    ));

    entries
}

/// Write one field by dotted path.
///
/// `update_model_field` (`pyatv/support/__init__.py:203-217`), which raises `AttributeError` for an
/// unknown path — reproduced here as a plain error naming the path.
///
/// Only the fields a user has any reason to change are writable: credentials, passwords and the
/// `info` block that describes this client. Identifiers are excluded because they are what storage
/// is keyed by and editing one orphans the record.
fn set(settings: &mut Settings, path: &str, value: Option<&str>) -> Result<()> {
    if let Some(field) = path.strip_prefix("info.") {
        let owned = || value.unwrap_or_default().to_owned();
        let info = &mut settings.info;
        match field {
            "name" => info.name = owned(),
            "mac" => info.mac = owned(),
            "model" => info.model = owned(),
            "device_id" => info.device_id = owned(),
            "rp_id" => info.rp_id = owned(),
            "os_name" => info.os_name = owned(),
            "os_build" => info.os_build = owned(),
            "os_version" => info.os_version = owned(),
            other => bail!("no such setting: info.{other}"),
        }
        return Ok(());
    }

    let Some(rest) = path.strip_prefix("protocols.") else {
        bail!("no such setting: {path}");
    };
    let Some((protocol, field)) = rest.split_once('.') else {
        bail!("no such setting: {path}");
    };
    let protocol = match protocol {
        "airplay" => Protocol::AirPlay,
        "companion" => Protocol::Companion,
        "dmap" => Protocol::Dmap,
        "mrp" => Protocol::Mrp,
        "raop" => Protocol::Raop,
        other => bail!("no such protocol: {other}"),
    };

    let owned = value.map(ToOwned::to_owned);
    match field {
        "credentials" => settings.protocols.set_credentials(protocol, owned),
        "password" if matches!(protocol, Protocol::AirPlay | Protocol::Raop) => {
            settings.protocols.set_password(protocol, owned);
        }
        "mrp_tunnel" if protocol == Protocol::AirPlay => {
            settings.protocols.airplay.mrp_tunnel = tunnel_from(value)?;
        }
        other => bail!("no such setting: {path} ({other} is not writable)"),
    }

    Ok(())
}

/// `MrpTunnel` as its Python member name, which is what a pydantic enum field stringifies to.
fn tunnel_name(tunnel: MrpTunnel) -> &'static str {
    match tunnel {
        MrpTunnel::Auto => "Auto",
        MrpTunnel::Force => "Force",
        MrpTunnel::Disable => "Disable",
    }
}

/// The inverse, case-insensitively, so `change_setting protocols.airplay.mrp_tunnel force` works.
fn tunnel_from(value: Option<&str>) -> Result<MrpTunnel> {
    match value.map(str::to_ascii_lowercase).as_deref() {
        // Unsetting a non-optional field puts the default back, which is what pydantic does when
        // `None` is validated against a field with a default.
        None | Some("auto") => Ok(MrpTunnel::Auto),
        Some("force") => Ok(MrpTunnel::Force),
        Some("disable") => Ok(MrpTunnel::Disable),
        Some(other) => bail!("mrp_tunnel must be auto, force or disable, not {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{entries, set, tunnel_from, tunnel_name};
    use pyatv::{MrpTunnel, Protocol, Settings};

    fn value_of(settings: &Settings, path: &str) -> Option<String> {
        entries(settings)
            .into_iter()
            .find(|(key, _)| key == path)
            .unwrap_or_else(|| panic!("{path} must be listed"))
            .1
    }

    /// The line pyatv's own smoke test asserts on
    /// (`tests/scripts/test_atvremote.py:141`).
    #[test]
    fn an_untouched_record_reports_a_null_raop_password() {
        let settings = Settings::default();
        assert_eq!(value_of(&settings, "protocols.raop.password"), None);
    }

    #[test]
    fn every_protocol_contributes_an_identifier_and_credentials() {
        let listed: Vec<String> = entries(&Settings::default())
            .into_iter()
            .map(|(path, _)| path)
            .collect();

        for protocol in ["airplay", "companion", "dmap", "mrp", "raop"] {
            assert!(listed.contains(&format!("protocols.{protocol}.identifier")));
            assert!(listed.contains(&format!("protocols.{protocol}.credentials")));
        }
        // Only these two take a password upstream (`atvremote.py:658-665`).
        assert!(listed.contains(&"protocols.airplay.password".to_owned()));
        assert!(listed.contains(&"protocols.raop.password".to_owned()));
        assert!(!listed.contains(&"protocols.mrp.password".to_owned()));

        assert!(listed.contains(&"info.name".to_owned()));
        assert!(listed.contains(&"info.rp_id".to_owned()));
    }

    /// The exact sequence `test_atvremote.py:136-177` walks: read `None`, set, read back, unset,
    /// read `None` again.
    #[test]
    fn a_password_round_trips_through_change_and_unset() {
        let mut settings = Settings::default();
        assert_eq!(value_of(&settings, "protocols.raop.password"), None);

        set(&mut settings, "protocols.raop.password", Some("foo")).expect("the path must exist");
        assert_eq!(
            value_of(&settings, "protocols.raop.password"),
            Some("foo".to_owned())
        );
        assert_eq!(settings.protocols.password(Protocol::Raop), Some("foo"));

        set(&mut settings, "protocols.raop.password", None).expect("unsetting must work");
        assert_eq!(value_of(&settings, "protocols.raop.password"), None);
    }

    #[test]
    fn credentials_are_writable_for_every_protocol() {
        for (path, protocol) in [
            ("protocols.airplay.credentials", Protocol::AirPlay),
            ("protocols.companion.credentials", Protocol::Companion),
            ("protocols.dmap.credentials", Protocol::Dmap),
            ("protocols.mrp.credentials", Protocol::Mrp),
            ("protocols.raop.credentials", Protocol::Raop),
        ] {
            let mut settings = Settings::default();
            set(&mut settings, path, Some("abc")).expect("the path must exist");
            assert_eq!(settings.protocols.credentials(protocol), Some("abc"));
        }
    }

    #[test]
    fn info_fields_are_writable() {
        let mut settings = Settings::default();
        set(&mut settings, "info.name", Some("Living Room")).expect("the path must exist");
        assert_eq!(settings.info.name, "Living Room");
    }

    /// `raise AttributeError(f"{model} has no field {next_field}")`
    /// (`pyatv/support/__init__.py:210-211`).
    #[test]
    fn an_unknown_path_is_refused() {
        let mut settings = Settings::default();
        for path in [
            "nonsense",
            "info.nonsense",
            "protocols.nonsense.credentials",
            "protocols.mrp.password",
            // Identifiers key the record and are deliberately read-only.
            "protocols.mrp.identifier",
        ] {
            assert!(
                set(&mut settings, path, Some("x")).is_err(),
                "{path} must be refused"
            );
        }
    }

    #[test]
    fn the_mrp_tunnel_setting_round_trips_by_name() {
        let mut settings = Settings::default();
        assert_eq!(
            value_of(&settings, "protocols.airplay.mrp_tunnel"),
            Some("Auto".to_owned())
        );

        set(&mut settings, "protocols.airplay.mrp_tunnel", Some("force"))
            .expect("the path must exist");
        assert_eq!(settings.protocols.airplay.mrp_tunnel, MrpTunnel::Force);
        assert_eq!(
            value_of(&settings, "protocols.airplay.mrp_tunnel"),
            Some("Force".to_owned())
        );

        set(&mut settings, "protocols.airplay.mrp_tunnel", None).expect("unsetting must work");
        assert_eq!(settings.protocols.airplay.mrp_tunnel, MrpTunnel::Auto);

        assert!(tunnel_from(Some("sideways")).is_err());
        assert_eq!(tunnel_name(MrpTunnel::Disable), "Disable");
    }
}
