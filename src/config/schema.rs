// config/schema.rs — Serde-deserializable TOML configuration types

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Top-level AppConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Root configuration deserialized from `gateway.toml`.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub pcap: Option<PcapConfig>,

    #[serde(default)]
    pub csv: Option<CsvConfig>,

    #[serde(default)]
    pub upstream: Vec<UpstreamConfig>,

    #[serde(default)]
    pub downstream: Vec<DownstreamConfig>,

    #[serde(default)]
    pub route: Vec<RouteConfig>,

    #[serde(default)]
    pub rewrite: Option<RewriteConfig>,
}

// ─────────────────────────────────────────────────────────────────────────────
// [general]
// ─────────────────────────────────────────────────────────────────────────────

/// General application settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeneralConfig {
    /// Minimum log level: trace | debug | info | warn | error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Enable interactive TUI (false → headless stderr logging).
    #[serde(default = "default_true")]
    pub tui: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            tui: true,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// [pcap] / [csv]
// ─────────────────────────────────────────────────────────────────────────────

/// PCAP traffic dump settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PcapConfig {
    #[serde(default)]
    pub enabled: bool,
    pub path: String,
}

/// CSV traffic dump settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CsvConfig {
    #[serde(default)]
    pub enabled: bool,
    pub path: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// [[upstream]]
// ─────────────────────────────────────────────────────────────────────────────

/// A single upstream listener entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum UpstreamConfig {
    /// Plain Modbus TCP listener (port 502).
    Tcp(TcpUpstreamConfig),
    /// WebSocket listener for browser-side WASM clients.
    Websocket(WsUpstreamConfig),
    /// Physical RS-485 / RS-232 serial upstream master.
    Serial(SerialUpstreamConfig),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TcpUpstreamConfig {
    /// Bind address, e.g. `"0.0.0.0:502"`.
    pub bind: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WsUpstreamConfig {
    /// Bind address, e.g. `"0.0.0.0:8502"`.
    pub bind: String,

    /// Idle session timeout in seconds (None = no timeout).
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,

    /// Maximum concurrent WebSocket sessions (0 = unlimited).
    #[serde(default)]
    pub max_sessions: usize,

    /// Require the `"modbus"` WebSocket subprotocol header.
    #[serde(default)]
    pub require_subprotocol: bool,

    /// Allowed Origin values (empty = allow all).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SerialUpstreamConfig {
    /// Serial port path, e.g. `"/dev/ttyUSB0"` or `"COM3"`.
    pub port: String,

    /// Framing mode: `"rtu"` or `"ascii"`.
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Baud rate (e.g. 9600, 19200, 115200).
    #[serde(default = "default_baud")]
    pub baud_rate: u32,

    /// Data bits (5–8).
    #[serde(default = "default_data_bits")]
    pub data_bits: u8,

    /// Stop bits (1 or 2).
    #[serde(default = "default_stop_bits")]
    pub stop_bits: u8,

    /// Parity: `"none"`, `"odd"`, or `"even"`.
    #[serde(default = "default_parity")]
    pub parity: String,

    /// Response timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub response_timeout_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// [[downstream]]
// ─────────────────────────────────────────────────────────────────────────────

/// A single downstream target entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DownstreamConfig {
    /// TCP Modbus slave.
    Tcp(TcpDownstreamConfig),
    /// Serial Modbus slave.
    Serial(SerialDownstreamConfig),
}

impl DownstreamConfig {
    /// Human-readable label for TUI display.
    pub fn name(&self) -> &str {
        match self {
            DownstreamConfig::Tcp(c) => &c.name,
            DownstreamConfig::Serial(c) => &c.name,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TcpDownstreamConfig {
    /// Display name shown in TUI (e.g. `"plc-floor-1"`).
    pub name: String,
    /// Host:port of the downstream Modbus TCP slave.
    pub address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SerialDownstreamConfig {
    /// Display name shown in TUI (e.g. `"rtu-bus"`).
    pub name: String,
    /// Serial port path.
    pub port: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_baud")]
    pub baud_rate: u32,
    #[serde(default = "default_data_bits")]
    pub data_bits: u8,
    #[serde(default = "default_stop_bits")]
    pub stop_bits: u8,
    #[serde(default = "default_parity")]
    pub parity: String,
    #[serde(default = "default_timeout_ms")]
    pub response_timeout_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// [[route]]
// ─────────────────────────────────────────────────────────────────────────────

/// A single routing rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RouteConfig {
    /// Exact unit-ID match.
    Unit(UnitRouteConfig),
    /// Range of unit IDs.
    Range(RangeRouteConfig),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnitRouteConfig {
    /// Modbus unit ID (1–247).
    pub unit_id: u8,
    /// Name of the `[[downstream]]` entry to route to.
    pub downstream: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RangeRouteConfig {
    /// Inclusive minimum unit ID.
    pub min_unit: u8,
    /// Inclusive maximum unit ID.
    pub max_unit: u8,
    /// Name of the `[[downstream]]` entry to route to.
    pub downstream: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// [rewrite]
// ─────────────────────────────────────────────────────────────────────────────

/// Optional unit-ID rewrite configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RewriteConfig {
    /// Additive offset applied to the unit ID in downstream frames.
    /// Positive values increase the unit ID; negative values decrease it.
    pub offset: i16,
}

// ─────────────────────────────────────────────────────────────────────────────
// Default helpers
// ─────────────────────────────────────────────────────────────────────────────

fn default_mode() -> String {
    "rtu".to_string()
}
fn default_baud() -> u32 {
    19200
}
fn default_data_bits() -> u8 {
    8
}
fn default_stop_bits() -> u8 {
    1
}
fn default_parity() -> String {
    "none".to_string()
}
fn default_timeout_ms() -> u64 {
    1000
}
