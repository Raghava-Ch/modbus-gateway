// orchestrator/session.rs — OrchestratorEventHandler only.
//
// All transport types, framing, and protocol logic live in the mbus-gateway
// crate. This module is purely application-layer glue: it receives events from
// the gateway library and forwards them to the metrics collector and traffic
// broadcast channel.

use std::sync::Arc;
use tokio::sync::mpsc;

use modbus_rs::gateway::GatewayEventHandler;
use modbus_rs::gateway::transport_types::UnitIdOrSlaveAddr;

use crate::metrics::{MetricsCollector, TrafficDirection, TrafficEvent};

// ─────────────────────────────────────────────────────────────────────────────
// GatewayTransport re-export
// ─────────────────────────────────────────────────────────────────────────────

/// Heterogeneous downstream transport — re-exported from `mbus-gateway` so the
/// rest of the binary never needs to import `mbus-core`/`mbus-serial` directly.
pub use modbus_rs::gateway::GatewayTransport;

// ─────────────────────────────────────────────────────────────────────────────
// OrchestratorEventHandler
// ─────────────────────────────────────────────────────────────────────────────

/// Routes `GatewayEventHandler` callbacks into the metrics collector and the
/// traffic mpsc channel that feeds the PCAP/CSV sink task and (via broadcast)
/// the TUI live-traffic panel.
pub struct OrchestratorEventHandler {
    pub metrics: Arc<MetricsCollector>,
    pub traffic_tx: Option<mpsc::Sender<TrafficEvent>>,
}

impl GatewayEventHandler for OrchestratorEventHandler {
    fn on_forward(&mut self, _session_id: u8, _unit: UnitIdOrSlaveAddr, channel_idx: usize) {
        self.metrics.inc_forward(channel_idx);
    }

    fn on_routing_miss(&mut self, _session_id: u8, _unit: UnitIdOrSlaveAddr) {
        self.metrics.inc_routing_miss();
    }

    fn on_downstream_timeout(&mut self, _session_id: u8, _internal_txn: u16) {
        self.metrics.inc_timeout();
    }

    fn on_upstream_disconnect(&mut self, _session_id: u8) {
        self.metrics.inc_disconnect();
    }

    // ── Traffic hooks (requires `traffic` feature in mbus-gateway) ─────────

    #[cfg(feature = "traffic")]
    fn on_upstream_rx(&mut self, _session_id: u8, frame: &[u8]) {
        self.emit(frame, TrafficDirection::UpstreamRx, 0);
    }

    #[cfg(feature = "traffic")]
    fn on_downstream_tx(&mut self, channel_idx: usize, frame: &[u8]) {
        self.emit(frame, TrafficDirection::DownstreamTx, channel_idx);
    }

    #[cfg(feature = "traffic")]
    fn on_downstream_rx(&mut self, _session_id: u8, channel_idx: usize, frame: &[u8]) {
        self.emit(frame, TrafficDirection::DownstreamRx, channel_idx);
    }

    #[cfg(feature = "traffic")]
    fn on_upstream_tx(&mut self, _session_id: u8, frame: &[u8]) {
        self.emit(frame, TrafficDirection::UpstreamTx, 0);
    }
}

impl OrchestratorEventHandler {
    fn emit(&self, frame: &[u8], direction: TrafficDirection, channel_idx: usize) {
        if let Some(tx) = &self.traffic_tx {
            let event = TrafficEvent {
                timestamp: chrono::Local::now(),
                direction,
                session_id: 0,
                channel_idx,
                frame: frame.to_vec(),
            };
            let _ = tx.try_send(event);
        }
    }
}
