//! The argument groups that hang off [`super::Cli`].
//!
//! Each corresponds to one of upstream's `parser.add_argument_group(...)` calls
//! (`pyatv/scripts/atvremote.py:649,658,667`) plus the storage choice from the shared parser
//! (`pyatv/scripts/__init__.py:97-111`). They are separate types rather than more fields on `Cli`
//! for the reason upstream groups them — `--help` reads better — and because a dozen more fields on
//! one struct is where both clippy and a reader start objecting.

use clap::ValueEnum;

/// The `debugging` argument group (`atvremote.py:667-683`).
///
/// A group of its own rather than three fields on [`Cli`](super::Cli), for the reason upstream groups them and
/// because three booleans on one struct is where `clippy::struct_excessive_bools` starts objecting.
#[derive(Debug, clap::Args)]
#[command(next_help_heading = "Debugging")]
pub struct Debugging {
    /// Print more detail. Repeat for more
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Print debug-level logs, equivalent to -vv
    #[arg(long, global = true)]
    pub debug: bool,

    // `--mdns-debug` (`atvremote.py:678-683`), which raises just `pyatv.core.mdns` to a custom
    // `TRAFFIC` level. Here it adds a `pyatv_mdns=trace` directive to the filter, leaving the rest
    // of the workspace at whatever `-v` selected.
    /// Print the mDNS traffic discovery sends and receives
    #[arg(long, global = true)]
    pub mdns_debug: bool,
}

/// The `--<protocol>-credentials` group (`atvremote.py:649-656`).
///
/// One flag per [`pyatv::Protocol`], generated in a loop upstream. An explicitly empty string
/// *unsets* whatever storage holds rather than being treated as absent, which is the asymmetry in
/// `_set_credentials` (`atvremote.py:753-762`).
///
/// The fields are named after the protocol alone and the flag name is spelled out, rather than the
/// fields carrying a `_credentials` suffix clap would derive the flag from: five fields sharing one
/// postfix is what `clippy::struct_field_names` exists to catch, and the flag names are what
/// actually has to match upstream.
#[derive(Debug, clap::Args)]
#[command(next_help_heading = "Credentials")]
pub struct Credentials {
    /// Credentials for DMAP.
    #[arg(
        id = "dmap-credentials",
        long,
        global = true,
        value_name = "CREDENTIALS"
    )]
    pub dmap: Option<String>,

    /// Credentials for MRP.
    #[arg(
        id = "mrp-credentials",
        long,
        global = true,
        value_name = "CREDENTIALS"
    )]
    pub mrp: Option<String>,

    // `help` is spelled out rather than taken from a doc comment because clap prints the comment
    // verbatim, backticks and all, and clippy's `doc_markdown` insists on them around `AirPlay`.
    /// Credentials for `AirPlay`.
    #[arg(
        id = "airplay-credentials",
        long,
        global = true,
        value_name = "CREDENTIALS",
        help = "Credentials for AirPlay"
    )]
    pub airplay: Option<String>,

    /// Credentials for Companion.
    #[arg(
        id = "companion-credentials",
        long,
        global = true,
        value_name = "CREDENTIALS"
    )]
    pub companion: Option<String>,

    /// Credentials for RAOP.
    #[arg(
        id = "raop-credentials",
        long,
        global = true,
        value_name = "CREDENTIALS"
    )]
    pub raop: Option<String>,
}

impl Credentials {
    /// Each protocol paired with whatever the command line said about it.
    ///
    /// The iteration order is [`pyatv::Protocol`]'s own, matching `for prot in Protocol`
    /// (`atvremote.py:775-776`).
    pub fn iter(&self) -> impl Iterator<Item = (pyatv::Protocol, Option<&str>)> {
        [
            (pyatv::Protocol::Dmap, self.dmap.as_deref()),
            (pyatv::Protocol::Mrp, self.mrp.as_deref()),
            (pyatv::Protocol::AirPlay, self.airplay.as_deref()),
            (pyatv::Protocol::Companion, self.companion.as_deref()),
            (pyatv::Protocol::Raop, self.raop.as_deref()),
        ]
        .into_iter()
    }

    /// Whatever was supplied for one protocol.
    #[must_use]
    pub fn for_protocol(&self, protocol: pyatv::Protocol) -> Option<&str> {
        self.iter()
            .find(|(candidate, _)| *candidate == protocol)
            .and_then(|(_, value)| value)
    }
}

/// The `--<protocol>-password` group (`atvremote.py:658-665`), which upstream builds for `AirPlay`
/// and RAOP only.
#[derive(Debug, clap::Args)]
#[command(next_help_heading = "Passwords")]
pub struct Passwords {
    /// Password for `AirPlay`.
    #[arg(
        id = "airplay-password",
        long,
        global = true,
        value_name = "PASSWORD",
        help = "Password for AirPlay"
    )]
    pub airplay: Option<String>,

    /// Password for RAOP.
    #[arg(id = "raop-password", long, global = true, value_name = "PASSWORD")]
    pub raop: Option<String>,
}

impl Passwords {
    /// Each password-taking protocol paired with whatever the command line said about it.
    ///
    /// RAOP first, matching `for prot in [Protocol.RAOP, Protocol.AirPlay]`
    /// (`atvremote.py:778-779`).
    pub fn iter(&self) -> impl Iterator<Item = (pyatv::Protocol, Option<&str>)> {
        [
            (pyatv::Protocol::Raop, self.raop.as_deref()),
            (pyatv::Protocol::AirPlay, self.airplay.as_deref()),
        ]
        .into_iter()
    }

    /// Whatever was supplied for one protocol.
    #[must_use]
    pub fn for_protocol(&self, protocol: pyatv::Protocol) -> Option<&str> {
        self.iter()
            .find(|(candidate, _)| *candidate == protocol)
            .and_then(|(_, value)| value)
    }
}

/// Which storage backend to use (`pyatv/scripts/__init__.py:99-104`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StorageKind {
    /// A JSON file, by default `$HOME/.pyatv.conf`.
    #[value(help = "A JSON file, by default $HOME/.pyatv.conf")]
    File,
    /// In memory only; nothing is read from or written to disk.
    None,
}
