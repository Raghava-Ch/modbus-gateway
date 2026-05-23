// metrics/mod.rs — In-process metrics collector using atomics + ring buffers

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// MetricsCollector
// ─────────────────────────────────────────────────────────────────────────────

const LATENCY_RING_SIZE: usize = 256;

/// Shared metrics state updated by `MetricsEventHandler` and read by the TUI.
pub struct MetricsCollector {
    /// Total requests successfully routed and forwarded.
    pub forwards: AtomicU64,
    /// Total routing misses (no downstream configured for unit ID).
    pub routing_misses: AtomicU64,
    /// Total downstream timeouts.
    pub timeouts: AtomicU64,
    /// Total upstream client disconnections.
    pub disconnects: AtomicU64,
    /// Gateway start time (for uptime calculation).
    pub started_at: Instant,

    /// Lock-protected latency ring buffer (microseconds per request).
    /// Using std::sync::Mutex here because the TUI read is infrequent.
    latency_ring: std::sync::Mutex<LatencyRing>,
}

impl MetricsCollector {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            forwards: AtomicU64::new(0),
            routing_misses: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            disconnects: AtomicU64::new(0),
            started_at: Instant::now(),
            latency_ring: std::sync::Mutex::new(LatencyRing::new()),
        })
    }

    /// Increment forward counter.
    #[inline]
    pub fn inc_forward(&self, _channel_idx: usize) {
        self.forwards.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment routing miss counter.
    #[inline]
    pub fn inc_routing_miss(&self) {
        self.routing_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment timeout counter.
    #[inline]
    pub fn inc_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment upstream disconnect counter.
    #[inline]
    pub fn inc_disconnect(&self) {
        self.disconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a request latency in microseconds.
    #[allow(dead_code)] // Used by Phase 2 latency instrumentation
    pub fn record_latency_us(&self, us: u64) {
        if let Ok(mut ring) = self.latency_ring.lock() {
            ring.push(us);
        }
    }

    /// Return a snapshot of the latency ring buffer (newest last).
    pub fn latency_snapshot(&self) -> Vec<u64> {
        self.latency_ring
            .lock()
            .map(|ring| ring.as_slice().to_vec())
            .unwrap_or_default()
    }

    /// Compute latency bucket percentages: (<1ms, 1–5ms, >5ms).
    pub fn latency_buckets(&self) -> LatencyBuckets {
        let samples = self.latency_snapshot();
        if samples.is_empty() {
            return LatencyBuckets::default();
        }
        let total = samples.len() as f64;
        let mut fast = 0u64;
        let mut mid = 0u64;
        let mut slow = 0u64;
        for &us in &samples {
            if us < 1_000 {
                fast += 1;
            } else if us < 5_000 {
                mid += 1;
            } else {
                slow += 1;
            }
        }
        LatencyBuckets {
            under_1ms_pct: (fast as f64 / total * 100.0) as u8,
            one_to_5ms_pct: (mid as f64 / total * 100.0) as u8,
            over_5ms_pct: (slow as f64 / total * 100.0) as u8,
        }
    }

    /// Gateway uptime.
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Latency ring buffer
// ─────────────────────────────────────────────────────────────────────────────

struct LatencyRing {
    buf: [u64; LATENCY_RING_SIZE],
    head: usize,
    len: usize,
}

impl LatencyRing {
    fn new() -> Self {
        Self {
            buf: [0u64; LATENCY_RING_SIZE],
            head: 0,
            len: 0,
        }
    }

    #[allow(dead_code)] // Called by record_latency_us
    fn push(&mut self, val: u64) {
        self.buf[self.head] = val;
        self.head = (self.head + 1) % LATENCY_RING_SIZE;
        if self.len < LATENCY_RING_SIZE {
            self.len += 1;
        }
    }

    fn as_slice(&self) -> Vec<u64> {
        if self.len == 0 {
            return vec![];
        }
        let start = if self.len < LATENCY_RING_SIZE {
            0
        } else {
            self.head
        };
        let mut out = Vec::with_capacity(self.len);
        for i in 0..self.len {
            out.push(self.buf[(start + i) % LATENCY_RING_SIZE]);
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LatencyBuckets
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct LatencyBuckets {
    pub under_1ms_pct: u8,
    pub one_to_5ms_pct: u8,
    pub over_5ms_pct: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// Traffic events (for PCAP / CSV / TUI traffic list)
// ─────────────────────────────────────────────────────────────────────────────

/// A single traffic event emitted by the gateway event handler.
#[derive(Debug, Clone)]
pub struct TrafficEvent {
    pub timestamp: chrono::DateTime<chrono::Local>,
    pub direction: TrafficDirection,
    #[allow(dead_code)] // Populated by on_upstream_rx for Phase 3 PCAP linking
    pub session_id: u8,
    pub channel_idx: usize,
    pub frame: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficDirection {
    /// Frame received from upstream (client → gateway).
    UpstreamRx,
    /// Frame sent to downstream (gateway → device).
    DownstreamTx,
    /// Frame received from downstream (device → gateway).
    DownstreamRx,
    /// Frame sent to upstream (gateway → client).
    UpstreamTx,
}

impl std::fmt::Display for TrafficDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrafficDirection::UpstreamRx => write!(f, "UpRx"),
            TrafficDirection::DownstreamTx => write!(f, "DsTx"),
            TrafficDirection::DownstreamRx => write!(f, "DsRx"),
            TrafficDirection::UpstreamTx => write!(f, "UpTx"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MetricsEventHandler — implements GatewayEventHandler
// ─────────────────────────────────────────────────────────────────────────────

use modbus_rs::gateway::GatewayEventHandler;
use modbus_rs::gateway::transport_types::UnitIdOrSlaveAddr;

/// Connects `mbus-gateway` events to the in-process metrics + traffic channel.
#[allow(dead_code)]
pub struct MetricsEventHandler {
    pub metrics: Arc<MetricsCollector>,
    /// Send traffic frames to the sink task (PCAP/CSV writer or TUI).
    pub traffic_tx: Option<tokio::sync::mpsc::Sender<TrafficEvent>>,
}

#[allow(dead_code)]
impl MetricsEventHandler {
    pub fn new(
        metrics: Arc<MetricsCollector>,
        traffic_tx: Option<tokio::sync::mpsc::Sender<TrafficEvent>>,
    ) -> Self {
        Self { metrics, traffic_tx }
    }
}

impl GatewayEventHandler for MetricsEventHandler {
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

    fn on_upstream_rx(&mut self, session_id: u8, frame: &[u8]) {
        if let Some(tx) = &self.traffic_tx {
            let event = TrafficEvent {
                timestamp: chrono::Local::now(),
                direction: TrafficDirection::UpstreamRx,
                session_id,
                channel_idx: 0,
                frame: frame.to_vec(),
            };
            let _ = tx.try_send(event);
        }
    }

    fn on_downstream_tx(&mut self, channel_idx: usize, frame: &[u8]) {
        if let Some(tx) = &self.traffic_tx {
            let event = TrafficEvent {
                timestamp: chrono::Local::now(),
                direction: TrafficDirection::DownstreamTx,
                session_id: 0,
                channel_idx,
                frame: frame.to_vec(),
            };
            let _ = tx.try_send(event);
        }
    }
}
