//! Argument parsing.
//!
//! The subcommand set mirrors pyatv's `atvremote`, documented at
//! <https://pyatv.dev/documentation/atvremote/>.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Control Apple TV and AirPlay devices from the command line.
#[derive(Debug, Parser)]
#[command(name = "atvremote", version, about, long_about = None)]
pub struct Cli {
    /// Device identifier, as reported by `scan`.
    #[arg(short, long, global = true)]
    pub id: Option<String>,

    /// Scan these hosts directly instead of browsing the network.
    #[arg(long, global = true, value_delimiter = ',')]
    pub scan_hosts: Vec<IpAddr>,

    /// Seconds to spend scanning.
    #[arg(long, global = true, default_value_t = 5)]
    pub scan_timeout: u64,

    /// Path to the credentials and settings file.
    #[arg(long, global = true)]
    pub storage_filename: Option<PathBuf>,

    /// Companion credentials, overriding whatever the settings file holds.
    ///
    /// Mirrors upstream's per-protocol `--<protocol>-credentials` group
    /// (`pyatv/scripts/atvremote.py:649-654`), which lets a caller connect without a settings
    /// file at all.
    #[arg(long, global = true, value_name = "CREDENTIALS")]
    pub companion_credentials: Option<String>,

    /// `AirPlay` credentials, overriding whatever the settings file holds.
    //
    // The other half of upstream's credential group. These are also what unlocks the MRP tunnel on
    // tvOS 15 and later — though a Companion pairing does just as well, because the receiver's
    // `/pair-verify` accepts any HAP pairing registered on the device (see
    // `pyatv_proto_airplay::tunnel_credentials`).
    //
    // `help` is spelled out rather than taken from the doc comment because clap prints the comment
    // verbatim, backticks and all, and clippy's `doc_markdown` insists on them around `AirPlay`.
    #[arg(
        long,
        global = true,
        value_name = "CREDENTIALS",
        help = "AirPlay credentials, overriding whatever the settings file holds"
    )]
    pub airplay_credentials: Option<String>,

    /// Print more detail. Repeat for more.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// The tracing filter implied by the verbosity flags, used when `RUST_LOG` is unset.
    #[must_use]
    pub fn log_level(&self) -> &'static str {
        match self.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    }
}

/// Which protocol to act on, where a command needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
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
///
/// Named in `snake_case` rather than clap's default `kebab-case` because upstream's command names
/// are its interface method names verbatim (`retrieve_commands`, `pyatv/scripts/atvremote.py:890`)
/// — `app_list`, `device_info`, `power_state`. Someone moving between the two tools types the same
/// thing.
#[derive(Debug, Subcommand)]
#[command(rename_all = "snake_case")]
pub enum Command {
    /// Find devices on the local network.
    Scan,

    /// Pair with a device.
    Pair {
        /// Protocol to pair.
        #[arg(long)]
        protocol: ProtocolArg,
    },

    /// Show what is currently playing.
    Playing,

    /// Send a remote control button press.
    Remote {
        /// Button to press, e.g. `up`, `select`, `menu`, `play_pause`.
        button: String,
    },

    /// Show which features the device supports.
    Features,

    /// Print hardware and firmware details.
    DeviceInfo,

    /// Turn the device on.
    TurnOn,

    /// Turn the device off.
    TurnOff,

    /// List installed apps.
    AppList,

    /// Launch an app by bundle identifier or URL.
    LaunchApp {
        /// Bundle identifier or URL.
        target: String,
    },

    /// Play a video URL over AirPlay.
    PlayUrl {
        /// URL to play.
        url: String,
    },

    /// Stream an audio file over RAOP.
    StreamFile {
        /// Path to the audio file, an `http(s)://` URL, or `-` for standard input.
        path: PathBuf,
    },

    /// Follow now-playing updates until interrupted.
    ///
    /// Upstream blocks on `sys.stdin.readline()` and stops on ENTER
    /// (`pyatv/scripts/atvremote.py:421-433`). Ctrl-C does the same job here without needing a
    /// terminal, and `--timeout` is an addition so the command can be scripted.
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

    /// Get or set the volume.
    Volume {
        /// New volume as a percentage. Omit to read the current value.
        level: Option<f32>,
    },

    /// Print the device's power state.
    PowerState,
}
