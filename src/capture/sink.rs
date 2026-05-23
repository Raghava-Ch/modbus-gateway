// capture/sink.rs — Background Tokio task consuming TrafficEvents → PCAP + CSV

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{error, info};

use crate::config::schema::AppConfig;
use crate::metrics::{TrafficDirection, TrafficEvent};

use super::csv::CsvWriter;
use super::pcap::PcapWriter;

// ─────────────────────────────────────────────────────────────────────────────
// CaptureConfig — built from AppConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Static configuration for the capture pipeline.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub pcap_path: Option<PathBuf>,
    pub csv_path:  Option<PathBuf>,
}

impl CaptureConfig {
    pub fn from_app_config(cfg: &AppConfig) -> Self {
        let pcap_path = cfg
            .pcap
            .as_ref()
            .filter(|p| p.enabled && !p.path.is_empty())
            .map(|p| PathBuf::from(&p.path));

        let csv_path = cfg
            .csv
            .as_ref()
            .filter(|c| c.enabled && !c.path.is_empty())
            .map(|c| PathBuf::from(&c.path));

        Self { pcap_path, csv_path }
    }

    /// True when at least one capture target is configured.
    pub fn is_active(&self) -> bool {
        self.pcap_path.is_some() || self.csv_path.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CaptureState — shared with the TUI for live toggle
// ─────────────────────────────────────────────────────────────────────────────

/// Shared toggle flags.  The TUI flips these with `p` / `c` keys.
#[derive(Debug)]
pub struct CaptureState {
    pub pcap_enabled: Arc<AtomicBool>,
    pub csv_enabled:  Arc<AtomicBool>,
}

impl CaptureState {
    pub fn new(pcap_initially: bool, csv_initially: bool) -> Self {
        Self {
            pcap_enabled: Arc::new(AtomicBool::new(pcap_initially)),
            csv_enabled:  Arc::new(AtomicBool::new(csv_initially)),
        }
    }

    /// Toggle PCAP recording. Returns the new state.
    pub fn toggle_pcap(&self) -> bool {
        let prev = self.pcap_enabled.fetch_xor(true, Ordering::Relaxed);
        !prev
    }

    /// Toggle CSV recording. Returns the new state.
    pub fn toggle_csv(&self) -> bool {
        let prev = self.csv_enabled.fetch_xor(true, Ordering::Relaxed);
        !prev
    }

    pub fn pcap_on(&self) -> bool { self.pcap_enabled.load(Ordering::Relaxed) }
    pub fn csv_on(&self)  -> bool { self.csv_enabled.load(Ordering::Relaxed) }
}

impl Clone for CaptureState {
    fn clone(&self) -> Self {
        Self {
            pcap_enabled: self.pcap_enabled.clone(),
            csv_enabled:  self.csv_enabled.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TrafficSink
// ─────────────────────────────────────────────────────────────────────────────

/// Consumes `TrafficEvent` items from an mpsc channel and writes them to
/// PCAP and/or CSV files, honouring the live `CaptureState` toggles.
///
/// The orchestrator inlines this logic directly; `TrafficSink` is retained
/// as a standalone reusable component for testing and future serial capture.
#[allow(dead_code)]
pub struct TrafficSink {
    config:     CaptureConfig,
    state:      CaptureState,
    traffic_rx: mpsc::Receiver<TrafficEvent>,
}

#[allow(dead_code)]
impl TrafficSink {
    pub fn new(
        config: CaptureConfig,
        state: CaptureState,
        traffic_rx: mpsc::Receiver<TrafficEvent>,
    ) -> Self {
        Self { config, state, traffic_rx }
    }

    /// Access the capture configuration.
    pub fn config(&self) -> &CaptureConfig { &self.config }

    /// Access the shared capture state.
    pub fn state(&self) -> &CaptureState { &self.state }

    /// Run the sink until the channel is closed (gateway shutdown).
    ///
    /// Call this in a `tokio::spawn` task.
    pub async fn run(mut self) {
        // Open writers lazily on first enabled event.
        let mut pcap: Option<PcapWriter> = None;
        let mut csv:  Option<CsvWriter>  = None;

        // Try to open files that are configured at startup.
        if let Some(p) = &self.config.pcap_path {
            if self.state.pcap_on() {
                match PcapWriter::create(&p.to_string_lossy()) {
                    Ok(w) => {
                        info!(path = %p.display(), "PCAP capture started");
                        pcap = Some(w);
                    }
                    Err(e) => error!(path = %p.display(), error = %e, "cannot open PCAP file"),
                }
            }
        }
        if let Some(p) = &self.config.csv_path {
            if self.state.csv_on() {
                match CsvWriter::create(&p.to_string_lossy()) {
                    Ok(w) => {
                        info!(path = %p.display(), "CSV capture started");
                        csv = Some(w);
                    }
                    Err(e) => error!(path = %p.display(), error = %e, "cannot open CSV file"),
                }
            }
        }

        // ── Main drain loop ───────────────────────────────────────────────────
        let mut flush_counter = 0u32;
        while let Some(event) = self.traffic_rx.recv().await {
            // ── PCAP ──────────────────────────────────────────────────────────
            if self.state.pcap_on() {
                // Lazy open on first enabled event after a toggle.
                if pcap.is_none() {
                    if let Some(p) = &self.config.pcap_path {
                        match PcapWriter::create(&p.to_string_lossy()) {
                            Ok(w) => {
                                info!(path = %p.display(), "PCAP capture resumed");
                                pcap = Some(w);
                            }
                            Err(e) => error!(%e, "PCAP reopen failed"),
                        }
                    }
                }
                if let Some(w) = &mut pcap {
                    let upstream_rx = event.direction == TrafficDirection::UpstreamRx;
                    if let Err(e) = w.write_packet(event.timestamp, upstream_rx, &event.frame) {
                        error!(error = %e, "PCAP write error");
                    }
                }
            } else {
                // Toggle closed — drop the writer to flush & close the file.
                if pcap.is_some() {
                    if let Some(mut w) = pcap.take() {
                        w.flush().ok();
                    }
                    info!("PCAP capture paused");
                }
            }

            // ── CSV ───────────────────────────────────────────────────────────
            if self.state.csv_on() {
                if csv.is_none() {
                    if let Some(p) = &self.config.csv_path {
                        match CsvWriter::create(&p.to_string_lossy()) {
                            Ok(w) => {
                                info!(path = %p.display(), "CSV capture resumed");
                                csv = Some(w);
                            }
                            Err(e) => error!(%e, "CSV reopen failed"),
                        }
                    }
                }
                if let Some(w) = &mut csv {
                    if let Err(e) = w.write_event(&event) {
                        error!(error = %e, "CSV write error");
                    }
                }
            } else if csv.is_some() {
                if let Some(mut w) = csv.take() {
                    w.flush().ok();
                }
                info!("CSV capture paused");
            }

            // ── Periodic flush (every 64 events) ──────────────────────────────
            flush_counter = flush_counter.wrapping_add(1);
            if flush_counter % 64 == 0 {
                if let Some(w) = &mut pcap { w.flush().ok(); }
                if let Some(w) = &mut csv  { w.flush().ok(); }
            }
        }

        // ── Channel closed — flush and close all writers ──────────────────────
        if let Some(mut w) = pcap { w.flush().ok(); }
        if let Some(mut w) = csv  { w.flush().ok(); }
        info!("traffic sink shut down");
    }
}
