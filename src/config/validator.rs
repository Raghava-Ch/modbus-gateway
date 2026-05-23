// config/validator.rs — Semantic validation of a loaded AppConfig

use crate::error::{AppError, AppResult};

use super::schema::{AppConfig, RouteConfig};

/// Perform semantic validation of the merged configuration.
///
/// Returns `Ok(())` if all checks pass, or the first `AppError::Config` found.
pub fn validate_config(cfg: &AppConfig) -> AppResult<()> {
    check_not_empty(cfg)?;
    check_downstream_names_unique(cfg)?;
    check_route_downstreams_exist(cfg)?;
    check_route_ranges(cfg)?;
    check_bind_addresses(cfg)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation rules
// ─────────────────────────────────────────────────────────────────────────────

fn check_not_empty(cfg: &AppConfig) -> AppResult<()> {
    if cfg.upstream.is_empty() {
        return Err(AppError::Config(
            "at least one [[upstream]] is required".to_string(),
        ));
    }
    if cfg.downstream.is_empty() {
        return Err(AppError::Config(
            "at least one [[downstream]] is required".to_string(),
        ));
    }
    Ok(())
}

fn check_downstream_names_unique(cfg: &AppConfig) -> AppResult<()> {
    let mut seen = std::collections::HashSet::new();
    for ds in &cfg.downstream {
        let name = ds.name();
        if !seen.insert(name) {
            return Err(AppError::Config(format!(
                "duplicate downstream name: \"{name}\""
            )));
        }
    }
    Ok(())
}

fn check_route_downstreams_exist(cfg: &AppConfig) -> AppResult<()> {
    let known: std::collections::HashSet<&str> =
        cfg.downstream.iter().map(|d| d.name()).collect();

    for route in &cfg.route {
        let ds_name = match route {
            RouteConfig::Unit(r) => r.downstream.as_str(),
            RouteConfig::Range(r) => r.downstream.as_str(),
        };
        if !known.contains(ds_name) {
            return Err(AppError::Config(format!(
                "route references unknown downstream \"{ds_name}\""
            )));
        }
    }
    Ok(())
}

fn check_route_ranges(cfg: &AppConfig) -> AppResult<()> {
    for route in &cfg.route {
        if let RouteConfig::Range(r) = route {
            if r.min_unit > r.max_unit {
                return Err(AppError::Config(format!(
                    "route range min_unit ({}) > max_unit ({}) for downstream \"{}\"",
                    r.min_unit, r.max_unit, r.downstream
                )));
            }
            if r.min_unit == 0 {
                return Err(AppError::Config(
                    "route range: unit ID 0 is reserved (broadcast); use 1–247".to_string(),
                ));
            }
        }
        if let RouteConfig::Unit(r) = route {
            if r.unit_id == 0 {
                return Err(AppError::Config(
                    "route unit_id 0 is reserved (broadcast); use 1–247".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn check_bind_addresses(cfg: &AppConfig) -> AppResult<()> {
    use crate::config::schema::UpstreamConfig;
    use std::net::ToSocketAddrs;

    for up in &cfg.upstream {
        let addr = match up {
            UpstreamConfig::Tcp(c) => c.bind.as_str(),
            UpstreamConfig::Websocket(c) => c.bind.as_str(),
            UpstreamConfig::Serial(_) => continue,
        };
        addr.to_socket_addrs().map_err(|e| {
            AppError::Config(format!("invalid bind address \"{addr}\": {e}"))
        })?;
    }
    Ok(())
}
