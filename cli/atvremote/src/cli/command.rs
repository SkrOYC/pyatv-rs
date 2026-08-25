//! The subcommand set.
//!
//! Named in `snake_case` rather than clap's default `kebab-case` because upstream's command names
//! are its interface method names verbatim (`retrieve_commands`, `pyatv/scripts/atvremote.py:890`)
//! — `app_list`, `device_info`, `power_state`. Someone moving between the two tools types the same
//! thing.
//!
//! # Shape divergence from upstream
//!
//! pyatv takes a `nargs="+"` list of bare strings and dispatches each against
//! `retrieve_commands()` on thirteen interface classes in priority order
//! (`atvremote.py:889-951`), with arguments carried as a `cmd=arg1,arg2` suffix
//! (`_extract_command_with_args`, `atvremote.py:810-859`). clap runs exactly one subcommand per
//! invocation and types its arguments, so each upstream command becomes a subcommand and the
//! `=`-suffix becomes positional arguments. The one place the flat vocabulary survives is
//! [`Command::Remote`], where the button name stays a string: there are twenty-odd of them, they
//! take no options, and making each a subcommand would bury the rest of the tool.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

/// Which protocol to act on, where a command needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
pub enum ProtocolArg {
    /// Legacy DMAP.
    Dmap,
    /// MediaRemote.
    Mrp,
    /// AirPlay.
    Airplay,
    /// Companion link.
    Companion,
    /// RAOP audio.
    Raop,
}

impl From<ProtocolArg> for pyatv::Protocol {
    fn from(value: ProtocolArg) -> Self {
        match value {
            ProtocolArg::Dmap => Self::Dmap,
            ProtocolArg::Mrp => Self::Mrp,
            ProtocolArg::Airplay => Self::AirPlay,
            ProtocolArg::Companion => Self::Companion,
            ProtocolArg::Raop => Self::Raop,
        }
    }
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
#[command(rename_all = "snake_case")]
pub enum Command {
    // ---- Global: no device connection required ----
    /// Find devices on the local network.
    Scan,

    /// Pair with a device over --protocol
    Pair,

    // `GlobalCommands.commands` (`atvremote.py:94-111`), which upstream builds by reflecting over
    // the interface classes. Here the list is written out, because Rust has no `__dict__`.
    /// Print every button and command name this tool understands
    Commands,

    // ---- Device: these connect ----
    /// Show what is currently playing.
    Playing,

    /// Send a remote control button press.
    ///
    /// `BUTTON` is any name `atvremote commands` lists. Arguments follow it positionally, and
    /// upstream's `button=arg1,arg2` spelling is accepted as a single word too: `remote up 1` and
    /// `remote up=1` both send a double tap.
    #[command(
        about = "Send a remote control button press",
        long_about = "Send a remote control button press.\n\n\
                      BUTTON is any name 'atvremote commands' lists. Arguments follow it \
                      positionally, and pyatv's button=arg1,arg2 spelling is accepted as a single \
                      word too: 'remote up 1' and 'remote up=1' both send a double tap."
    )]
    Remote {
        // `help` rather than a doc comment: clippy's `doc_markdown` requires backticks around
        // `play_pause` and `set_position` in rustdoc, and clap would print those backticks verbatim
        // to the user. The doc comment below is for readers of the code; `help` is for readers of
        // `--help`. The same split applies wherever else the two rules collide.
        /// Button to press, e.g. `up`, `select`, `menu`, `play_pause`, `set_position`.
        #[arg(help = "Button to press, e.g. up, select, menu, play_pause, set_position")]
        button: String,

        /// Arguments the button takes, if any
        #[arg(value_name = "ARG")]
        args: Vec<String>,
    },

    /// Show which features the device supports
    Features {
        // `features=all` upstream (`atvremote.py:443-448`).
        /// Include features no connected protocol implements
        #[arg(long)]
        all: bool,
    },

    /// Print hardware and firmware details.
    DeviceInfo,

    /// Print the identifier the connected protocol knows this device by.
    DeviceId,

    /// Turn the device on.
    TurnOn,

    /// Turn the device off.
    TurnOff,

    /// Print the device's power state.
    PowerState,

    /// List installed apps.
    AppList,

    /// Launch an app by bundle identifier or URL.
    LaunchApp {
        /// Bundle identifier or URL.
        target: String,
    },

    /// Print the app that owns whatever is playing.
    App,

    /// List the user accounts configured on the device.
    AccountList,

    /// Switch to a different user account.
    SwitchAccount {
        /// Account identifier, as reported by `account_list`.
        #[arg(help = "Account identifier, as reported by account_list")]
        account_id: String,
    },

    /// Print the current volume.
    Volume,

    /// Set the volume.
    SetVolume {
        /// New volume as a percentage in 0.0..=100.0
        level: f32,

        // `set_volume(level, output_device)` (`pyatv/interface.py:1180-1188`); only MRP honours the
        // targeted form.
        //
        // The long name is spelled out because the enum's `rename_all = "snake_case"` — which is
        // there for the *subcommand* names — would otherwise reach the flags too and produce
        // `--output_device`, breaking with every global flag on the tool.
        /// Set this one speaker's volume rather than the group's
        #[arg(long = "output-device", value_name = "IDENTIFIER")]
        output_device: Option<String>,
    },

    /// List the speakers in the playback group.
    OutputDevices,

    /// Add speakers to the playback group.
    AddOutputDevices {
        /// Output device identifiers.
        #[arg(required = true, value_name = "IDENTIFIER")]
        identifiers: Vec<String>,
    },

    /// Remove speakers from the playback group.
    RemoveOutputDevices {
        /// Output device identifiers.
        #[arg(required = true, value_name = "IDENTIFIER")]
        identifiers: Vec<String>,
    },

    /// Replace the playback group outright.
    SetOutputDevices {
        /// Output device identifiers.
        #[arg(required = true, value_name = "IDENTIFIER")]
        identifiers: Vec<String>,
    },

    /// Print whether a text field currently has focus.
    TextFocusState,

    /// Read the focused text field.
    TextGet,

    /// Replace the focused text field's contents.
    TextSet {
        /// New contents.
        text: String,
    },

    /// Append to the focused text field.
    TextAppend {
        /// Text to append.
        text: String,
    },

    /// Clear the focused text field.
    TextClear,

    /// Play a video URL over AirPlay
    PlayUrl {
        /// URL to play.
        url: String,
    },

    /// Stream an audio file over RAOP
    StreamFile {
        /// Path to the audio file, an http(s):// URL, or - for standard input
        path: PathBuf,

        /// Title to announce instead of the file's own.
        #[arg(long)]
        title: Option<String>,

        /// Artist to announce instead of the file's own.
        #[arg(long)]
        artist: Option<String>,

        /// Album to announce instead of the file's own.
        #[arg(long)]
        album: Option<String>,

        // `MediaMetadata` carries `title`, `artist`, `album`, `artwork` and `duration`
        // (`pyatv/interface.py:74-84`). Artwork would need a second file argument and duration is
        // read off the stream itself, so the three text fields are the ones worth a flag.
        // `override_missing_metadata` (`pyatv/interface.py:886-901`). The long name is spelled out
        // for the same reason `--output-device` is.
        /// Only fill in the fields the file does not carry, rather than replacing them
        #[arg(long = "override-missing-metadata")]
        override_missing_metadata: bool,
    },

    // Upstream blocks on `sys.stdin.readline()` and stops on ENTER
    // (`pyatv/scripts/atvremote.py:421-433`). Ctrl-C does the same job here without needing a
    // terminal, and `--timeout` is an addition so the command can be scripted.
    /// Follow now-playing updates until interrupted
    ///
    /// Stops on Ctrl-C. Pass --timeout to stop after a fixed time instead.
    PushUpdates {
        /// Stop after this many seconds instead of waiting for Ctrl-C.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },

    /// Save the current artwork to a file.
    Artwork {
        /// Where to write the image.
        #[arg(long, short, value_name = "FILE")]
        output: PathBuf,

        /// Requested width in pixels. Omit for the device's own choice.
        #[arg(long)]
        width: Option<u32>,

        /// Requested height in pixels. Omit for the device's own choice.
        #[arg(long)]
        height: Option<u32>,
    },

    /// Print the artwork cache token.
    ArtworkId,

    /// Wait, then carry on. Useful inside the cli loop
    Delay {
        /// How long to wait, in milliseconds.
        #[arg(value_name = "MS")]
        milliseconds: u64,
    },

    /// Read commands from standard input, one per line.
    Cli,

    // ---- Settings: these read and write storage, without connecting ----
    /// Print every stored setting for the selected device.
    PrintSettings,

    /// Change one stored setting.
    ChangeSetting {
        /// Dotted path, e.g. protocols.raop.password
        setting: String,
        /// New value.
        value: String,
    },

    /// Clear one stored setting.
    UnsetSetting {
        /// Dotted path, e.g. protocols.raop.password
        setting: String,
    },

    /// Forget the selected device entirely.
    RemoveSettings,
}

impl Command {
    /// Whether running this command requires a live connection to the device.
    ///
    /// The three groups upstream keeps apart: `GlobalCommands` never connects
    /// (`atvremote.py:719-721`), `SettingsCommands` reaches storage rather than the device
    /// (`atvremote.py:473-501`), and everything else goes through `_handle_commands`
    /// (`atvremote.py:862-884`), which connects first.
    #[must_use]
    pub const fn needs_connection(&self) -> bool {
        !matches!(
            self,
            Self::Scan
                | Self::Pair
                | Self::Commands
                | Self::PrintSettings
                | Self::ChangeSetting { .. }
                | Self::UnsetSetting { .. }
                | Self::RemoveSettings
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, ProtocolArg};
    use crate::cli::Cli;
    use clap::Parser as _;

    fn command_of(args: &[&str]) -> Command {
        Cli::try_parse_from(args)
            .expect("these arguments must parse")
            .command
    }

    #[test]
    fn subcommands_keep_pyatvs_snake_case_names() {
        assert!(matches!(
            command_of(&["atvremote", "device_info"]),
            Command::DeviceInfo
        ));
        assert!(matches!(
            command_of(&["atvremote", "app_list"]),
            Command::AppList
        ));
        assert!(matches!(
            command_of(&["atvremote", "text_focus_state"]),
            Command::TextFocusState
        ));
        assert!(matches!(
            command_of(&["atvremote", "add_output_devices", "a", "b"]),
            Command::AddOutputDevices { .. }
        ));

        assert!(
            Cli::try_parse_from(["atvremote", "device-info"]).is_err(),
            "kebab-case is not upstream's spelling"
        );
    }

    #[test]
    fn remote_takes_a_button_and_trailing_arguments() {
        let Command::Remote { button, args } = command_of(&["atvremote", "remote", "up"]) else {
            panic!("expected a remote command");
        };
        assert_eq!(button, "up");
        assert!(args.is_empty());

        let Command::Remote { button, args } =
            command_of(&["atvremote", "remote", "action", "10", "20", "1"])
        else {
            panic!("expected a remote command");
        };
        assert_eq!(button, "action");
        assert_eq!(args, ["10", "20", "1"]);
    }

    #[test]
    fn output_device_lists_must_not_be_empty() {
        assert!(Cli::try_parse_from(["atvremote", "set_output_devices"]).is_err());
        assert!(Cli::try_parse_from(["atvremote", "set_output_devices", "a"]).is_ok());
    }

    #[test]
    fn features_takes_upstreams_all_switch() {
        assert!(matches!(
            command_of(&["atvremote", "features"]),
            Command::Features { all: false }
        ));
        assert!(matches!(
            command_of(&["atvremote", "features", "--all"]),
            Command::Features { all: true }
        ));
    }

    #[test]
    fn stream_file_accepts_metadata_overrides() {
        let Command::StreamFile {
            path,
            title,
            override_missing_metadata,
            ..
        } = command_of(&[
            "atvremote",
            "stream_file",
            "-",
            "--title",
            "Song",
            "--override-missing-metadata",
        ])
        else {
            panic!("expected a stream_file command");
        };

        assert_eq!(path.to_str(), Some("-"));
        assert_eq!(title.as_deref(), Some("Song"));
        assert!(override_missing_metadata);
    }

    #[test]
    fn only_the_device_commands_need_a_connection() {
        for args in [
            vec!["atvremote", "scan"],
            vec!["atvremote", "--protocol", "mrp", "pair"],
            vec!["atvremote", "commands"],
            vec!["atvremote", "print_settings"],
            vec!["atvremote", "change_setting", "a.b", "c"],
            vec!["atvremote", "unset_setting", "a.b"],
            vec!["atvremote", "remove_settings"],
        ] {
            assert!(
                !command_of(&args).needs_connection(),
                "{args:?} must not connect"
            );
        }

        for args in [
            vec!["atvremote", "playing"],
            vec!["atvremote", "remote", "menu"],
            vec!["atvremote", "volume"],
            vec!["atvremote", "cli"],
        ] {
            assert!(
                command_of(&args).needs_connection(),
                "{args:?} must connect"
            );
        }
    }

    #[test]
    fn protocol_arguments_map_onto_the_library_enum() {
        for (arg, protocol) in [
            (ProtocolArg::Dmap, pyatv::Protocol::Dmap),
            (ProtocolArg::Mrp, pyatv::Protocol::Mrp),
            (ProtocolArg::Airplay, pyatv::Protocol::AirPlay),
            (ProtocolArg::Companion, pyatv::Protocol::Companion),
            (ProtocolArg::Raop, pyatv::Protocol::Raop),
        ] {
            assert_eq!(pyatv::Protocol::from(arg), protocol);
        }
    }
}
