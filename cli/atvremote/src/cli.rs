//! Argument parsing.
//!
//! The flag set mirrors pyatv's `atvremote` (`pyatv/scripts/atvremote.py:551-684` and the common
//! parser at `pyatv/scripts/__init__.py:91-113`), documented at
//! <https://pyatv.dev/documentation/atvremote/>. The subcommand set is [`Command`].

pub mod command;
pub mod groups;

use std::net::IpAddr;
use std::path::PathBuf;

use clap::Parser;

pub use command::{Command, ProtocolArg};
pub use groups::{Credentials, Debugging, Passwords, StorageKind};

/// Control Apple TV and AirPlay devices from the command line.
#[derive(Debug, Parser)]
#[command(name = "atvremote", version, about, long_about = None)]
pub struct Cli {
    // `TransformIdentifiers` (`pyatv/scripts/__init__.py:78-89`) splits on commas and matches a
    // device carrying any of them, because a device answers under a different identifier on each
    // protocol.
    /// Device identifiers, comma-separated; any one may match
    #[arg(short, long, global = true, value_delimiter = ',')]
    pub id: Vec<String>,

    // `-n/--name` (`atvremote.py:564`), applied by `_scan_for_device` as a post-scan filter rather
    // than a scan option (`atvremote.py:61-71`) — and it suppresses the identifier filter, which
    // this reproduces.
    /// Advertised device name, as an alternative to --id
    #[arg(short, long, global = true)]
    pub name: Option<String>,

    /// Device address, for --manual
    #[arg(long, global = true)]
    pub address: Option<IpAddr>,

    /// Port, for --manual
    #[arg(long, global = true)]
    pub port: Option<u16>,

    // One global flag serving all three uses, as upstream's does (`atvremote.py:568-574`): `pair`
    // reads it (`atvremote.py:164`), `connect` is restricted to it (`atvremote.py:866`), and
    // `--manual` requires it (`atvremote.py:729-731`).
    /// Protocol to pair, to connect over, or to declare in --manual mode
    #[arg(long, global = true)]
    pub protocol: Option<ProtocolArg>,

    // `-m/--manual` (`atvremote.py:633-640`). All three of address, port and protocol are required,
    // which `atvremote.py:729-731` checks and `crate::commands::manual_config` reproduces.
    /// Skip scanning and talk to --address:--port over --protocol
    #[arg(short, long, global = true)]
    pub manual: bool,

    /// Scan these hosts directly instead of browsing the network
    #[arg(short, long, global = true, value_delimiter = ',')]
    pub scan_hosts: Vec<IpAddr>,

    /// Only scan for these protocols, comma-separated
    #[arg(long, global = true, value_delimiter = ',')]
    pub scan_protocols: Vec<ProtocolArg>,

    // Three, not the library default of five: `atvremote.py:589` overrides it.
    /// Seconds to spend scanning
    #[arg(short = 't', long, global = true, default_value_t = 3)]
    pub scan_timeout: u64,

    /// Where settings and credentials live
    #[arg(long, global = true, value_enum, default_value_t = StorageKind::File)]
    pub storage: StorageKind,

    /// Path to the credentials and settings file, when --storage file
    #[arg(long, global = true)]
    pub storage_filename: Option<PathBuf>,

    // `-p/--pin` (`atvremote.py:617-625`). Upstream defaults it to `1234` and only uses it for the
    // protocols where the *controller* picks the PIN; here it stays unset by default so the
    // interactive prompt is still what a user gets, and supplying it is what makes `pair`
    // scriptable.
    /// PIN to use instead of prompting, for pair
    #[arg(short, long, global = true, value_name = "PIN")]
    pub pin: Option<u32>,

    // The schema is pyatv's `atvscript` (`pyatv/scripts/atvscript.py:192-226`); see `crate::json`
    // for the mapping and the places it necessarily diverges.
    /// Emit one JSON object per result instead of human-readable text
    #[arg(long, global = true)]
    pub json: bool,

    /// How much to log, and where from.
    #[command(flatten)]
    pub debugging: Debugging,

    /// Credential overrides, one flag per protocol.
    #[command(flatten)]
    pub credentials: Credentials,

    /// Password overrides for the two protocols that take one.
    #[command(flatten)]
    pub passwords: Passwords,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// The tracing filter implied by the verbosity flags, used when `RUST_LOG` is unset.
    ///
    /// `--debug` outranks `-v` exactly as it does upstream (`atvremote.py:691-695`), where the two
    /// are independent booleans and `debug` is applied second.
    #[must_use]
    pub fn log_level(&self) -> String {
        let base = if self.debugging.debug {
            "debug"
        } else {
            match self.debugging.verbose {
                0 => "warn",
                1 => "info",
                2 => "debug",
                _ => "trace",
            }
        };

        if self.debugging.mdns_debug {
            format!("{base},pyatv_mdns=trace")
        } else {
            base.to_owned()
        }
    }

    /// Whether output should be JSON rather than text.
    #[must_use]
    pub const fn is_json(&self) -> bool {
        self.json
    }

    /// Whether the user asked for more than the default amount of logging.
    ///
    /// The condition upstream's `pair` uses to decide whether to mention that credentials were
    /// saved (`-v` or `--debug`, `atvremote.py:691-695`).
    #[must_use]
    pub const fn is_verbose(&self) -> bool {
        self.debugging.verbose > 0 || self.debugging.debug
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, ProtocolArg, StorageKind};
    use clap::Parser as _;

    /// Parse an argument vector the way `main` would, panicking on a usage error.
    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("these arguments must parse")
    }

    #[test]
    fn identifiers_split_on_commas() {
        let cli = parse(&["atvremote", "--id", "aa,bb,cc", "scan"]);
        assert_eq!(cli.id, ["aa", "bb", "cc"]);
    }

    #[test]
    fn a_single_identifier_is_still_a_list_of_one() {
        let cli = parse(&["atvremote", "-i", "aa", "scan"]);
        assert_eq!(cli.id, ["aa"]);
    }

    #[test]
    fn scan_protocols_split_on_commas() {
        let cli = parse(&["atvremote", "--scan-protocols", "mrp,airplay", "scan"]);
        assert_eq!(cli.scan_protocols, [ProtocolArg::Mrp, ProtocolArg::Airplay]);
    }

    /// `atvremote.py:589` overrides the library's five-second default with three.
    #[test]
    fn scan_timeout_defaults_to_pyatvs_three_seconds() {
        assert_eq!(parse(&["atvremote", "scan"]).scan_timeout, 3);
        assert_eq!(parse(&["atvremote", "-t", "12", "scan"]).scan_timeout, 12);
    }

    #[test]
    fn every_protocol_has_a_credentials_flag() {
        let cli = parse(&[
            "atvremote",
            "--dmap-credentials",
            "d",
            "--mrp-credentials",
            "m",
            "--airplay-credentials",
            "a",
            "--companion-credentials",
            "c",
            "--raop-credentials",
            "r",
            "scan",
        ]);

        assert_eq!(
            cli.credentials.for_protocol(pyatv::Protocol::Dmap),
            Some("d")
        );
        assert_eq!(
            cli.credentials.for_protocol(pyatv::Protocol::Mrp),
            Some("m")
        );
        assert_eq!(
            cli.credentials.for_protocol(pyatv::Protocol::AirPlay),
            Some("a")
        );
        assert_eq!(
            cli.credentials.for_protocol(pyatv::Protocol::Companion),
            Some("c")
        );
        assert_eq!(
            cli.credentials.for_protocol(pyatv::Protocol::Raop),
            Some("r")
        );
    }

    #[test]
    fn passwords_exist_for_airplay_and_raop_only() {
        let cli = parse(&[
            "atvremote",
            "--airplay-password",
            "a",
            "--raop-password",
            "r",
            "scan",
        ]);
        assert_eq!(
            cli.passwords.for_protocol(pyatv::Protocol::AirPlay),
            Some("a")
        );
        assert_eq!(cli.passwords.for_protocol(pyatv::Protocol::Raop), Some("r"));
        assert_eq!(cli.passwords.for_protocol(pyatv::Protocol::Mrp), None);

        assert!(
            Cli::try_parse_from(["atvremote", "--mrp-password", "x", "scan"]).is_err(),
            "MRP takes no password upstream (atvremote.py:658-665)"
        );
    }

    #[test]
    fn manual_mode_collects_address_port_and_protocol() {
        let cli = parse(&[
            "atvremote",
            "--manual",
            "--address",
            "10.0.0.5",
            "--port",
            "49152",
            "--protocol",
            "mrp",
            "--id",
            "abc",
            "playing",
        ]);

        assert!(cli.manual);
        assert_eq!(
            cli.address.map(|it| it.to_string()).as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(cli.port, Some(49152));
        assert_eq!(cli.protocol, Some(ProtocolArg::Mrp));
    }

    #[test]
    fn storage_defaults_to_file_and_accepts_none() {
        assert_eq!(parse(&["atvremote", "scan"]).storage, StorageKind::File);
        assert_eq!(
            parse(&["atvremote", "--storage", "none", "scan"]).storage,
            StorageKind::None
        );
    }

    #[test]
    fn debug_outranks_verbosity_and_mdns_debug_is_additive() {
        assert_eq!(parse(&["atvremote", "scan"]).log_level(), "warn");
        assert_eq!(parse(&["atvremote", "-v", "scan"]).log_level(), "info");
        assert_eq!(parse(&["atvremote", "-vvv", "scan"]).log_level(), "trace");
        assert_eq!(
            parse(&["atvremote", "--debug", "scan"]).log_level(),
            "debug"
        );
        assert_eq!(
            parse(&["atvremote", "--mdns-debug", "scan"]).log_level(),
            "warn,pyatv_mdns=trace"
        );
    }

    #[test]
    fn json_is_global_so_it_may_follow_the_subcommand() {
        assert!(parse(&["atvremote", "playing", "--json"]).is_json());
        assert!(parse(&["atvremote", "--json", "playing"]).is_json());
        assert!(!parse(&["atvremote", "playing"]).is_json());
    }

    /// `--help` is user-facing; the doc comments around it are not.
    ///
    /// clap renders a doc comment verbatim when no `help` is set, so a rustdoc citation like
    /// ``(`atvremote.py:589`)`` — which the project requires on the *code* — would otherwise be
    /// printed to whoever runs `atvremote --help`, backticks and all. The convention is that
    /// citations go in `//` comments and the `///` line is the help text; this walks the tree to
    /// make sure neither a backtick nor a `.py:` citation escapes.
    #[test]
    fn help_text_carries_no_rustdoc_markup() {
        fn check(command: &clap::Command) {
            let mut texts: Vec<String> = command
                .get_arguments()
                .flat_map(|argument| {
                    [argument.get_help(), argument.get_long_help()]
                        .into_iter()
                        .flatten()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .collect();
            texts.extend(
                [command.get_about(), command.get_long_about()]
                    .into_iter()
                    .flatten()
                    .map(ToString::to_string),
            );

            for text in texts {
                assert!(
                    !text.contains('`'),
                    "`{}` shows a backtick to the user: {text:?}",
                    command.get_name()
                );
                assert!(
                    !text.contains(".py:"),
                    "`{}` shows a pyatv source citation to the user: {text:?}",
                    command.get_name()
                );
                assert!(
                    !text.contains("[`"),
                    "`{}` shows an intra-doc link to the user: {text:?}",
                    command.get_name()
                );
            }

            for subcommand in command.get_subcommands() {
                check(subcommand);
            }
        }

        check(&<Cli as clap::CommandFactory>::command());
    }

    /// Subcommand *names* are `snake_case` because upstream's are, but flags are `kebab-case`
    /// because every other flag on the tool is.
    ///
    /// clap's `rename_all` reaches both, so a new multi-word subcommand flag silently comes out as
    /// `--like_this` unless its `long` is spelled out. This walks the whole tree so that mistake
    /// cannot ship.
    #[test]
    fn every_long_flag_is_kebab_case() {
        fn check(command: &clap::Command) {
            for argument in command.get_arguments() {
                for long in argument.get_long_and_visible_aliases().unwrap_or_default() {
                    assert!(
                        !long.contains('_'),
                        "--{long} on `{}` must be kebab-case",
                        command.get_name()
                    );
                }
            }
            for subcommand in command.get_subcommands() {
                check(subcommand);
            }
        }

        check(&<Cli as clap::CommandFactory>::command());
    }

    /// The other half of the same rule: subcommand names keep pyatv's spelling.
    #[test]
    fn every_subcommand_name_is_snake_case() {
        let command = <Cli as clap::CommandFactory>::command();
        for subcommand in command.get_subcommands() {
            let name = subcommand.get_name();
            assert!(!name.contains('-'), "`{name}` must be snake_case");
        }

        let names: Vec<&str> = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();
        for expected in [
            "scan",
            "pair",
            "playing",
            "device_info",
            "app_list",
            "launch_app",
            "power_state",
            "account_list",
            "switch_account",
            "set_volume",
            "output_devices",
            "add_output_devices",
            "remove_output_devices",
            "set_output_devices",
            "text_focus_state",
            "text_get",
            "text_set",
            "text_append",
            "text_clear",
            "play_url",
            "stream_file",
            "push_updates",
            "artwork_id",
            "device_id",
            "print_settings",
            "change_setting",
            "unset_setting",
            "remove_settings",
            "delay",
            "cli",
        ] {
            assert!(names.contains(&expected), "`{expected}` is missing");
        }
    }

    /// Upstream's `pair` reads the *global* `--protocol` (`atvremote.py:164`), so it must not be a
    /// subcommand-local flag here either.
    #[test]
    fn pair_reads_the_global_protocol_flag() {
        let cli = parse(&["atvremote", "--protocol", "companion", "pair"]);
        assert!(matches!(cli.command, Command::Pair));
        assert_eq!(cli.protocol, Some(ProtocolArg::Companion));
    }
}
