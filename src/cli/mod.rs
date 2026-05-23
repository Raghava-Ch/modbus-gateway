// cli/mod.rs — Command-line interface definition (clap derive API)

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

// ─────────────────────────────────────────────────────────────────────────────
// Root CLI
// ─────────────────────────────────────────────────────────────────────────────

/// Modbus Gateway — bridges upstream Modbus masters to downstream slaves
/// with live TUI observability and PCAP/CSV traffic capture.
#[derive(Debug, Parser)]
#[command(
    name = "modbus-gateway",
    version,
    author,
    about,
    long_about = None,
    propagate_version = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level subcommands
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the Modbus gateway (optionally with interactive TUI).
    Run(RunArgs),

    /// Validate a TOML config file without starting the gateway.
    Check(CheckArgs),

    /// Convert a .pcap capture file to human-readable Modbus traffic log.
    Dump(DumpArgs),
}

// ─────────────────────────────────────────────────────────────────────────────
// `run` subcommand
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `modbus-gateway run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Path to a TOML configuration file.
    ///
    /// When supplied together with CLI flags, the flags override the file.
    #[arg(short = 'c', long, value_name = "FILE", env = "MODBUS_GATEWAY_CONFIG")]
    pub config: Option<PathBuf>,

    /// Upstream listener URI(s).
    ///
    /// Examples:
    ///   tcp://0.0.0.0:502
    ///   ws://0.0.0.0:8502
    ///   serial:///dev/ttyUSB0?mode=rtu&baud=19200
    #[arg(
        short = 'u',
        long,
        value_name = "URI",
        num_args = 1..,
        value_delimiter = ','
    )]
    pub upstream: Vec<String>,

    /// Downstream target URI(s).
    ///
    /// Examples:
    ///   tcp://192.168.1.10:502
    ///   serial:///dev/ttyUSB1?mode=rtu&baud=9600
    #[arg(
        short = 'd',
        long,
        value_name = "URI",
        num_args = 1..,
        value_delimiter = ','
    )]
    pub downstream: Vec<String>,

    /// Routing rule(s).
    ///
    /// Examples:
    ///   unit:1=0         (unit ID 1 → downstream channel 0)
    ///   unit:2=1         (unit ID 2 → downstream channel 1)
    ///   range:10-32=0    (unit IDs 10–32 → downstream channel 0)
    #[arg(
        short = 'r',
        long,
        value_name = "SPEC",
        num_args = 1..,
        value_delimiter = ','
    )]
    pub route: Vec<String>,

    /// Additive unit-ID rewrite offset applied to all downstream frames.
    ///
    /// Wraps the routing table in `UnitIdRewriteRouter`.  For example,
    /// `--rewrite-offset -10` maps upstream unit 11 to downstream unit 1.
    #[arg(long, value_name = "N", allow_hyphen_values = true)]
    pub rewrite_offset: Option<i16>,

    /// Disable the TUI; log structured output to stderr instead.
    #[arg(long)]
    pub no_tui: bool,

    /// Enable PCAP traffic capture to the given file path.
    #[arg(long, value_name = "FILE")]
    pub pcap: Option<PathBuf>,

    /// Enable CSV traffic capture to the given file path.
    #[arg(long, value_name = "FILE")]
    pub csv: Option<PathBuf>,

    /// WebSocket idle-session timeout in seconds (0 = no timeout).
    #[arg(long, value_name = "SECS", default_value = "0")]
    pub ws_idle_timeout: u64,

    /// Maximum concurrent WebSocket sessions (0 = unlimited).
    #[arg(long, value_name = "N", default_value = "0")]
    pub ws_max_sessions: usize,

    /// Require the `"modbus"` WebSocket subprotocol during handshake.
    #[arg(long)]
    pub ws_require_subprotocol: bool,

    /// Allowed WebSocket `Origin` header values (comma-separated).
    #[arg(long, value_name = "ORIGIN", num_args = 1.., value_delimiter = ',')]
    pub ws_allowed_origins: Vec<String>,

    /// Log verbosity (-v = debug, -vv = trace).
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// `check` subcommand
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `modbus-gateway check`.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Path to the TOML configuration file to validate.
    #[arg(value_name = "FILE")]
    pub config: PathBuf,
}

// ─────────────────────────────────────────────────────────────────────────────
// `dump` subcommand
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `modbus-gateway dump`.
#[derive(Debug, Args)]
pub struct DumpArgs {
    /// Path to the `.pcap` file to decode.
    #[arg(value_name = "PCAP_FILE")]
    pub file: PathBuf,

    /// Filter output by unit ID (0 = show all).
    #[arg(long, value_name = "UNIT", default_value = "0")]
    pub unit_filter: u8,

    /// Output format: `text` or `csv`.
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: String,
}
