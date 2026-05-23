// config/loader.rs — Read and merge TOML config with CLI overrides

use std::path::Path;

use crate::cli::RunArgs;
use crate::error::{AppError, AppResult};

use super::schema::{
    AppConfig, DownstreamConfig, RouteConfig, TcpDownstreamConfig, TcpUpstreamConfig,
    UpstreamConfig, WsUpstreamConfig,
};

/// Load configuration from an optional TOML file, then apply CLI overrides.
///
/// Priority (highest first):
///   1. CLI flags  
///   2. TOML file  
///   3. Defaults
pub fn load_config(args: &RunArgs) -> AppResult<AppConfig> {
    // ── Base: from file or empty defaults ─────────────────────────────────────
    let mut cfg = if let Some(path) = &args.config {
        load_toml_file(path)?
    } else {
        AppConfig::default()
    };

    // ── Override: general settings from CLI ───────────────────────────────────
    // Verbosity → log_level override
    if args.verbose >= 2 {
        cfg.general.log_level = "trace".to_string();
    } else if args.verbose == 1 {
        cfg.general.log_level = "debug".to_string();
    }

    // --no-tui disables TUI regardless of config file setting.
    if args.no_tui {
        cfg.general.tui = false;
    }

    // ── Override: upstream URIs from CLI (additive over config file) ──────────
    for uri in &args.upstream {
        match parse_upstream_uri(uri)? {
            Some(up) => cfg.upstream.push(up),
            None => {
                return Err(AppError::Config(format!(
                    "unrecognised upstream URI format: {uri}"
                )));
            }
        }
    }

    // ── Override: downstream URIs from CLI ────────────────────────────────────
    for (idx, uri) in args.downstream.iter().enumerate() {
        match parse_downstream_uri(uri, idx)? {
            Some(ds) => cfg.downstream.push(ds),
            None => {
                return Err(AppError::Config(format!(
                    "unrecognised downstream URI format: {uri}"
                )));
            }
        }
    }

    // ── Override: routing rules from CLI ──────────────────────────────────────
    for spec in &args.route {
        cfg.route.push(parse_route_spec(spec)?);
    }

    // ── Override: rewrite offset ──────────────────────────────────────────────
    if let Some(offset) = args.rewrite_offset {
        cfg.rewrite = Some(super::schema::RewriteConfig { offset });
    }

    // ── Override: PCAP / CSV from CLI ─────────────────────────────────────────
    if let Some(pcap_path) = &args.pcap {
        cfg.pcap = Some(super::schema::PcapConfig {
            enabled: true,
            path: pcap_path.to_string_lossy().to_string(),
        });
    }
    if let Some(csv_path) = &args.csv {
        cfg.csv = Some(super::schema::CsvConfig {
            enabled: true,
            path: csv_path.to_string_lossy().to_string(),
        });
    }

    // ── Override: WebSocket config (applied to first WS upstream) ─────────────
    apply_ws_cli_overrides(&mut cfg, args);

    Ok(cfg)
}

// ─────────────────────────────────────────────────────────────────────────────
// TOML file loader
// ─────────────────────────────────────────────────────────────────────────────

fn load_toml_file(path: &Path) -> AppResult<AppConfig> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| AppError::Config(format!("cannot read {}: {e}", path.display())))?;
    let cfg: AppConfig = toml::from_str(&content)?;
    Ok(cfg)
}

// ─────────────────────────────────────────────────────────────────────────────
// URI parsers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse `tcp://0.0.0.0:502`, `ws://0.0.0.0:8502`, or
/// `serial:///dev/ttyUSB0?mode=rtu&baud=19200` into an `UpstreamConfig`.
fn parse_upstream_uri(uri: &str) -> AppResult<Option<UpstreamConfig>> {
    if let Some(rest) = uri.strip_prefix("tcp://") {
        return Ok(Some(UpstreamConfig::Tcp(TcpUpstreamConfig {
            bind: rest.to_string(),
        })));
    }

    if let Some(rest) = uri.strip_prefix("ws://") {
        return Ok(Some(UpstreamConfig::Websocket(WsUpstreamConfig {
            bind: rest.to_string(),
            idle_timeout_secs: None,
            max_sessions: 0,
            require_subprotocol: false,
            allowed_origins: vec![],
        })));
    }

    if uri.starts_with("serial://") {
        let serial_cfg = parse_serial_uri_upstream(uri)?;
        return Ok(Some(UpstreamConfig::Serial(serial_cfg)));
    }

    Ok(None)
}

/// Parse `tcp://host:port` or `serial:///dev/ttyX?mode=rtu&baud=9600` into
/// a `DownstreamConfig`.
fn parse_downstream_uri(uri: &str, idx: usize) -> AppResult<Option<DownstreamConfig>> {
    if let Some(rest) = uri.strip_prefix("tcp://") {
        return Ok(Some(DownstreamConfig::Tcp(TcpDownstreamConfig {
            name: format!("downstream-{idx}"),
            address: rest.to_string(),
        })));
    }

    if uri.starts_with("serial://") {
        let serial_cfg = parse_serial_uri_downstream(uri, idx)?;
        return Ok(Some(DownstreamConfig::Serial(serial_cfg)));
    }

    Ok(None)
}

// ─────────────────────────────────────────────────────────────────────────────
// Serial URI parser helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_serial_uri_upstream(uri: &str) -> AppResult<super::schema::SerialUpstreamConfig> {
    // serial:///dev/ttyUSB0?mode=rtu&baud=19200&data=8&stop=1&parity=none&timeout=1000
    let (port, params) = split_serial_uri(uri)?;
    Ok(super::schema::SerialUpstreamConfig {
        port,
        mode: params.get("mode").cloned().unwrap_or_else(|| "rtu".to_string()),
        baud_rate: params.get("baud").and_then(|v| v.parse().ok()).unwrap_or(19200),
        data_bits: params.get("data").and_then(|v| v.parse().ok()).unwrap_or(8),
        stop_bits: params.get("stop").and_then(|v| v.parse().ok()).unwrap_or(1),
        parity: params.get("parity").cloned().unwrap_or_else(|| "none".to_string()),
        response_timeout_ms: params
            .get("timeout")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000),
    })
}

fn parse_serial_uri_downstream(
    uri: &str,
    idx: usize,
) -> AppResult<super::schema::SerialDownstreamConfig> {
    let (port, params) = split_serial_uri(uri)?;
    Ok(super::schema::SerialDownstreamConfig {
        name: format!("serial-{idx}"),
        port,
        mode: params.get("mode").cloned().unwrap_or_else(|| "rtu".to_string()),
        baud_rate: params.get("baud").and_then(|v| v.parse().ok()).unwrap_or(9600),
        data_bits: params.get("data").and_then(|v| v.parse().ok()).unwrap_or(8),
        stop_bits: params.get("stop").and_then(|v| v.parse().ok()).unwrap_or(1),
        parity: params.get("parity").cloned().unwrap_or_else(|| "none".to_string()),
        response_timeout_ms: params
            .get("timeout")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000),
    })
}

/// Split `serial:///dev/ttyUSB0?mode=rtu&baud=19200` into `("/dev/ttyUSB0", params)`.
fn split_serial_uri(uri: &str) -> AppResult<(String, std::collections::HashMap<String, String>)> {
    // Remove the `serial://` prefix, leaving `/dev/ttyX?params`.
    let without_scheme = uri
        .strip_prefix("serial://")
        .ok_or_else(|| AppError::Config(format!("invalid serial URI: {uri}")))?;

    let (path_part, query_part) = if let Some(idx) = without_scheme.find('?') {
        without_scheme.split_at(idx)
    } else {
        (without_scheme, "")
    };

    let port = path_part.to_string();
    let mut params = std::collections::HashMap::new();

    let query = query_part.trim_start_matches('?');
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_string(), v.to_string());
        }
    }

    Ok((port, params))
}

// ─────────────────────────────────────────────────────────────────────────────
// Route spec parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parse `unit:1=0`, `unit:2=1`, or `range:10-32=0`.
///
/// The downstream value is treated as a channel index (usize) and converted
/// to the name `"downstream-{idx}"` to match how CLI URIs are auto-named.
fn parse_route_spec(spec: &str) -> AppResult<RouteConfig> {
    if let Some(rest) = spec.strip_prefix("unit:") {
        let (unit_str, ch_str) = rest
            .split_once('=')
            .ok_or_else(|| AppError::Config(format!("invalid route spec: {spec}")))?;
        let unit_id: u8 = unit_str
            .parse()
            .map_err(|_| AppError::Config(format!("invalid unit ID in route spec: {spec}")))?;
        return Ok(RouteConfig::Unit(super::schema::UnitRouteConfig {
            unit_id,
            downstream: format!("downstream-{ch_str}"),
        }));
    }

    if let Some(rest) = spec.strip_prefix("range:") {
        let (range_str, ch_str) = rest
            .split_once('=')
            .ok_or_else(|| AppError::Config(format!("invalid route spec: {spec}")))?;
        let (min_str, max_str) = range_str
            .split_once('-')
            .ok_or_else(|| AppError::Config(format!("invalid range in route spec: {spec}")))?;
        let min_unit: u8 = min_str
            .parse()
            .map_err(|_| AppError::Config(format!("invalid range min in route spec: {spec}")))?;
        let max_unit: u8 = max_str
            .parse()
            .map_err(|_| AppError::Config(format!("invalid range max in route spec: {spec}")))?;
        return Ok(RouteConfig::Range(super::schema::RangeRouteConfig {
            min_unit,
            max_unit,
            downstream: format!("downstream-{ch_str}"),
        }));
    }

    Err(AppError::Config(format!(
        "unknown route spec format: {spec} (expected unit:N=CH or range:N-M=CH)"
    )))
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI → WS config overlay
// ─────────────────────────────────────────────────────────────────────────────

/// Apply WebSocket CLI flags to the first `Websocket` upstream found in cfg.
fn apply_ws_cli_overrides(cfg: &mut AppConfig, args: &RunArgs) {
    for up in cfg.upstream.iter_mut() {
        if let UpstreamConfig::Websocket(ws) = up {
            if args.ws_idle_timeout > 0 {
                ws.idle_timeout_secs = Some(args.ws_idle_timeout);
            }
            if args.ws_max_sessions > 0 {
                ws.max_sessions = args.ws_max_sessions;
            }
            if args.ws_require_subprotocol {
                ws.require_subprotocol = true;
            }
            if !args.ws_allowed_origins.is_empty() {
                ws.allowed_origins.clone_from(&args.ws_allowed_origins);
            }
            break;
        }
    }
}
