// orchestrator/mod.rs — Gateway orchestrator: builds and runs all servers

mod session;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use modbus_rs::gateway::{
    AsyncTcpGatewayServer, AsyncWsGatewayServer, GatewayShutdown, GatewayShutdownToken,
    UnitRouteTable, WsGatewayConfig,
    DownstreamConfig, SerialDownstreamConfig,
    transport_types::UnitIdOrSlaveAddr,
    transport_types::{BaudRate, DataBits, Parity, SerialMode},
};
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::{error, info, warn};

use crate::capture::{CaptureConfig, CaptureState};
use crate::config::schema::{AppConfig, DownstreamConfig as CfgDownstream, RouteConfig, UpstreamConfig};
use crate::error::{AppError, AppResult};
use crate::metrics::{MetricsCollector, TrafficEvent};

// Maximum number of routing entries supported at runtime.
const MAX_ROUTES: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// GatewayOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Owns all shared gateway state and spawns upstream server tasks.
pub struct GatewayOrchestrator {
    /// Shared, dynamically-mutable routing table.
    pub router: Arc<RwLock<UnitRouteTable<MAX_ROUTES>>>,
    /// Shutdown token — call `.cancel()` to stop all servers.
    pub shutdown_token: GatewayShutdownToken,
    /// Shared watch receiver for shutdown signal propagation.
    pub shutdown_rx: tokio::sync::watch::Receiver<bool>,
    /// In-process metrics shared with the TUI.
    pub metrics: Arc<MetricsCollector>,
    /// Receiver end of the TUI traffic fan-out channel.
    pub traffic_rx: Option<broadcast::Receiver<TrafficEvent>>,
    /// Live capture toggle state (shared with TUI for `p`/`c` keys).
    pub capture_state: CaptureState,
    /// Names of downstream channels (index-aligned with the router).
    pub downstream_names: Vec<String>,
}

impl GatewayOrchestrator {
    /// Build and start the orchestrator from a merged `AppConfig`.
    pub async fn start(cfg: &AppConfig) -> AppResult<Self> {
        let metrics = MetricsCollector::new();

        // ── Capture configuration ──────────────────────────────────────────────
        let capture_cfg = CaptureConfig::from_app_config(cfg);
        let capture_state = CaptureState::new(
            capture_cfg.pcap_path.is_some(),
            capture_cfg.csv_path.is_some(),
        );

        // ── Traffic channels ───────────────────────────────────────────────────
        // 1. mpsc: gateway event handler → sink task (high-throughput, lossless)
        // 2. broadcast: sink task → TUI (lossy-ok; TUI drops old events gracefully)
        let needs_traffic = capture_cfg.is_active() || cfg.general.tui;

        let (raw_traffic_tx, raw_traffic_rx): (
            Option<mpsc::Sender<TrafficEvent>>,
            Option<mpsc::Receiver<TrafficEvent>>,
        ) = if needs_traffic {
            let (tx, rx) = mpsc::channel::<TrafficEvent>(2048);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        // Broadcast channel for TUI — 512 slots, older items overwritten.
        let (bcast_tx, bcast_rx): (
            broadcast::Sender<TrafficEvent>,
            broadcast::Receiver<TrafficEvent>,
        ) = broadcast::channel(512);

        // ── Downstream channels ────────────────────────────────────────────────
        let mut downstream_names: Vec<String> = Vec::new();
        let mut downstreams: Vec<Arc<Mutex<session::GatewayTransport>>> = Vec::new();

        for ds_cfg in &cfg.downstream {
            let (name, lib_cfg) = match ds_cfg {
                CfgDownstream::Tcp(tc) => {
                    info!(address = %tc.address, name = %tc.name, "connecting downstream TCP");
                    (tc.name.clone(), DownstreamConfig::Tcp { address: tc.address.clone() })
                }
                CfgDownstream::Serial(sc) => {
                    info!(port = %sc.port, name = %sc.name, "connecting downstream Serial");

                    let mode = match sc.mode.to_lowercase().as_str() {
                        "rtu"   => SerialMode::Rtu,
                        "ascii" => SerialMode::Ascii,
                        _ => return Err(AppError::Config(format!("Invalid serial mode: {}", sc.mode))),
                    };
                    let baud_rate = match sc.baud_rate {
                        9600  => BaudRate::Baud9600,
                        19200 => BaudRate::Baud19200,
                        other => BaudRate::Custom(other),
                    };
                    let data_bits = match sc.data_bits {
                        5 => DataBits::Five,
                        6 => DataBits::Six,
                        7 => DataBits::Seven,
                        8 => DataBits::Eight,
                        _ => return Err(AppError::Config(format!("Invalid data bits: {}", sc.data_bits))),
                    };
                    let parity = match sc.parity.to_lowercase().as_str() {
                        "none" => Parity::None,
                        "even" => Parity::Even,
                        "odd"  => Parity::Odd,
                        _      => return Err(AppError::Config(format!("Invalid parity: {}", sc.parity))),
                    };

                    let serial_cfg = SerialDownstreamConfig {
                        port: sc.port.clone(),
                        mode,
                        baud_rate,
                        data_bits,
                        stop_bits: sc.stop_bits,
                        parity,
                        response_timeout_ms: sc.response_timeout_ms as u32,
                        retry_attempts: 3,
                    };
                    (sc.name.clone(), DownstreamConfig::Serial(serial_cfg))
                }
            };

            let transport = lib_cfg.connect().await.map_err(|e| {
                AppError::Gateway(format!("downstream \"{name}\": {e}"))
            })?;
            downstreams.push(Arc::new(Mutex::new(transport)));
            downstream_names.push(name);
        }


        if downstreams.is_empty() {
            return Err(AppError::Config(
                "no downstream channels could be established".to_string(),
            ));
        }

        // ── Routing table ──────────────────────────────────────────────────────
        let mut route_table: UnitRouteTable<MAX_ROUTES> = UnitRouteTable::new();

        let name_to_idx: std::collections::HashMap<&str, usize> = downstream_names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), i))
            .collect();

        for route in &cfg.route {
            match route {
                RouteConfig::Unit(r) => {
                    let idx = name_to_idx
                        .get(r.downstream.as_str())
                        .copied()
                        .ok_or_else(|| {
                            AppError::Config(format!(
                                "route references unknown downstream \"{}\"",
                                r.downstream
                            ))
                        })?;
                    let unit = UnitIdOrSlaveAddr::new(r.unit_id)
                        .map_err(|_| {
                            AppError::Config(format!("invalid unit ID: {}", r.unit_id))
                        })?;
                    route_table.add(unit, idx).map_err(|e| {
                        AppError::Config(format!(
                            "routing table error for unit {}: {e:?}",
                            r.unit_id
                        ))
                    })?;
                    info!(
                        unit_id = r.unit_id,
                        downstream = %r.downstream,
                        channel = idx,
                        "route added"
                    );
                }
                RouteConfig::Range(_r) => {
                    warn!("range routes are not yet wired to the runtime (Phase 4)");
                }
            }
        }

        if cfg.route.is_empty() && downstreams.len() == 1 {
            info!("no routes configured — using PassthroughRouter (all traffic → channel 0)");
        }

        let router = Arc::new(RwLock::new(route_table));

        // ── Shutdown token & watch propagation ────────────────────────────────
        let (shutdown_token, shutdown_future) = GatewayShutdown::new();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        tokio::spawn(async move {
            shutdown_future.await;
            let _ = shutdown_tx.send(true);
        });

        // ── Traffic fan-out task: mpsc → PCAP/CSV + broadcast → TUI ─────────
        if let Some(mut raw_rx) = raw_traffic_rx {
            use crate::capture::csv::CsvWriter;
            use crate::capture::pcap::PcapWriter;
            use crate::metrics::TrafficDirection;

            let bcast_tx_clone = bcast_tx.clone();
            let cap_cfg   = capture_cfg.clone();
            let cap_state = capture_state.clone();

            tokio::spawn(async move {
                let mut pcap: Option<PcapWriter> = None;
                let mut csv:  Option<CsvWriter>  = None;

                // Open writers for paths configured at startup.
                if let Some(p) = &cap_cfg.pcap_path {
                    if cap_state.pcap_on() {
                        match PcapWriter::create(&p.to_string_lossy()) {
                            Ok(w)  => { info!(path = %p.display(), "PCAP capture started"); pcap = Some(w); }
                            Err(e) => error!(%e, "cannot open PCAP file"),
                        }
                    }
                }
                if let Some(p) = &cap_cfg.csv_path {
                    if cap_state.csv_on() {
                        match CsvWriter::create(&p.to_string_lossy()) {
                            Ok(w)  => { info!(path = %p.display(), "CSV capture started"); csv = Some(w); }
                            Err(e) => error!(%e, "cannot open CSV file"),
                        }
                    }
                }

                let mut flush_ctr = 0u32;

                while let Some(event) = raw_rx.recv().await {
                    // Fan-out to TUI (best-effort; no TUI subscriber = silent drop).
                    let _ = bcast_tx_clone.send(event.clone());

                    // ── PCAP ──────────────────────────────────────────────────
                    if cap_state.pcap_on() {
                        if pcap.is_none() {
                            if let Some(p) = &cap_cfg.pcap_path {
                                match PcapWriter::create(&p.to_string_lossy()) {
                                    Ok(w)  => { info!(path = %p.display(), "PCAP resumed"); pcap = Some(w); }
                                    Err(e) => error!(%e, "PCAP reopen failed"),
                                }
                            }
                        }
                        if let Some(w) = &mut pcap {
                            let up = event.direction == TrafficDirection::UpstreamRx;
                            if let Err(e) = w.write_packet(event.timestamp, up, &event.frame) {
                                error!(%e, "PCAP write error");
                            }
                        }
                    } else if pcap.is_some() {
                        if let Some(mut w) = pcap.take() { w.flush().ok(); }
                        info!("PCAP capture paused");
                    }

                    // ── CSV ───────────────────────────────────────────────────
                    if cap_state.csv_on() {
                        if csv.is_none() {
                            if let Some(p) = &cap_cfg.csv_path {
                                match CsvWriter::create(&p.to_string_lossy()) {
                                    Ok(w)  => { info!(path = %p.display(), "CSV resumed"); csv = Some(w); }
                                    Err(e) => error!(%e, "CSV reopen failed"),
                                }
                            }
                        }
                        if let Some(w) = &mut csv {
                            if let Err(e) = w.write_event(&event) {
                                error!(%e, "CSV write error");
                            }
                        }
                    } else if csv.is_some() {
                        if let Some(mut w) = csv.take() { w.flush().ok(); }
                        info!("CSV capture paused");
                    }

                    // Flush every 64 events.
                    flush_ctr = flush_ctr.wrapping_add(1);
                    if flush_ctr % 64 == 0 {
                        if let Some(w) = &mut pcap { w.flush().ok(); }
                        if let Some(w) = &mut csv  { w.flush().ok(); }
                    }
                }

                // Channel closed — flush everything.
                if let Some(mut w) = pcap { w.flush().ok(); }
                if let Some(mut w) = csv  { w.flush().ok(); }
                info!("traffic sink shut down");
            });
        }

        // ── Spawn upstream server tasks ────────────────────────────────────────
        for up_cfg in &cfg.upstream {
            spawn_upstream_task(
                up_cfg,
                router.clone(),
                downstreams.clone(),
                shutdown_rx.clone(),
                metrics.clone(),
                raw_traffic_tx.clone(),
            )
            .await?;
        }

        Ok(Self {
            router,
            shutdown_token,
            shutdown_rx,
            metrics,
            traffic_rx: if cfg.general.tui { Some(bcast_rx) } else { None },
            capture_state,
            downstream_names,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-upstream spawner
// ─────────────────────────────────────────────────────────────────────────────

async fn spawn_upstream_task(
    cfg: &UpstreamConfig,
    router: Arc<RwLock<UnitRouteTable<MAX_ROUTES>>>,
    downstreams: Vec<Arc<Mutex<crate::orchestrator::session::GatewayTransport>>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    metrics: Arc<MetricsCollector>,
    traffic_tx: Option<mpsc::Sender<TrafficEvent>>,
) -> AppResult<()> {
    let handler = Arc::new(tokio::sync::Mutex::new(crate::orchestrator::session::OrchestratorEventHandler {
        metrics: metrics.clone(),
        traffic_tx: traffic_tx.clone(),
    }));
    // Note: Gateway timeout could be configurable later. Default to 2000ms.
    let response_timeout = Duration::from_millis(2000);

    match cfg {
        // ── TCP upstream ───────────────────────────────────────────────────────
        UpstreamConfig::Tcp(tc) => {
            let bind = tc.bind.clone();
            info!(bind = %bind, "starting TCP upstream server (instrumented)");

            let mut rx = shutdown_rx.clone();
            tokio::spawn(async move {
                loop {
                    let mut rx_clone = rx.clone();
                    let shutdown_future = async move {
                        if *rx_clone.borrow() { return; }
                        let _ = rx_clone.changed().await;
                    };

                    // Use the built-in core async gateway server!
                    let result = AsyncTcpGatewayServer::serve_with_shutdown(
                        &bind,
                        router.clone(),
                        downstreams.clone(),
                        handler.clone(),
                        response_timeout,
                        shutdown_future,
                    )
                    .await;

                    match result {
                        Ok(()) => {
                            info!("TCP upstream server stopped cleanly");
                            break;
                        }
                        Err(e) => {
                            if *rx.borrow() {
                                info!("TCP upstream server stopped during shutdown");
                                break;
                            }
                            error!(error = %e, bind = %bind, "TCP upstream error; restarting in 2s");
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                                _ = rx.changed() => { break; }
                            }
                        }
                    }
                }
            });
        }

        // ── WebSocket upstream ─────────────────────────────────────────────────
        UpstreamConfig::Websocket(wc) => {
            let bind = wc.bind.clone();
            let ws_cfg = WsGatewayConfig {
                idle_timeout: wc
                    .idle_timeout_secs
                    .filter(|&s| s > 0)
                    .map(Duration::from_secs),
                max_sessions: wc.max_sessions,
                require_modbus_subprotocol: wc.require_subprotocol,
                allowed_origins: wc.allowed_origins.clone(),
            };
            info!(bind = %bind, "starting WebSocket upstream server");

            let mut rx = shutdown_rx.clone();
            tokio::spawn(async move {
                loop {
                    let mut rx_clone = rx.clone();
                    let shutdown_future = async move {
                        if *rx_clone.borrow() { return; }
                        let _ = rx_clone.changed().await;
                    };

                    let result = AsyncWsGatewayServer::serve_with_shutdown(
                        &bind,
                        ws_cfg.clone(),
                        router.clone(),
                        downstreams.clone(),
                        handler.clone(),
                        response_timeout,
                        shutdown_future,
                    )
                    .await;

                    match result {
                        Ok(()) => {
                            info!("WebSocket upstream server stopped cleanly");
                            break;
                        }
                        Err(e) => {
                            if *rx.borrow() { break; }
                            error!(error = %e, bind = %bind, "WS upstream error; restarting in 2s");
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                                _ = rx.changed() => { break; }
                            }
                        }
                    }
                }
            });
        }

        // ── Serial upstream ────────────────────────────────────────────────────
        UpstreamConfig::Serial(sc) => {
            warn!(
                port = %sc.port,
                "serial upstream support will be enabled in a future phase"
            );
        }
    }
    Ok(())
}
