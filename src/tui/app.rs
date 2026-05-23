// tui/app.rs — TUI application state and render loop

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use modbus_rs::gateway::UnitRouteTable;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::broadcast;
use tracing::info;

use crate::capture::CaptureState;
use crate::error::AppResult;
use crate::metrics::{MetricsCollector, TrafficEvent};
use crate::orchestrator::GatewayOrchestrator;
use super::event::{AppEvent, is_quit, next_event};
use super::ui;

const MAX_ROUTES: usize = 64;
const TRAFFIC_HISTORY: usize = 200;
const TICK_RATE: Duration = Duration::from_millis(250); // 4 Hz

// ─────────────────────────────────────────────────────────────────────────────
// TuiApp — state owned by the render loop
// ─────────────────────────────────────────────────────────────────────────────

pub struct TuiApp {
    /// Shared metrics from the gateway tasks.
    metrics: Arc<MetricsCollector>,
    /// Shared routing table (for display).
    #[allow(dead_code)] // Phase 4: live route display from shared router
    router: Arc<RwLock<UnitRouteTable<MAX_ROUTES>>>,
    /// Downstream channel names (index-aligned).
    downstream_names: Vec<String>,
    /// Received traffic events (bounded ring).
    traffic: VecDeque<TrafficEvent>,
    /// Broadcast receiver for traffic events from the fan-out task.
    traffic_rx: Option<broadcast::Receiver<TrafficEvent>>,
    /// Log messages captured from tracing.
    #[allow(dead_code)] // Phase 2: populated by tui-logger tracing layer
    log_messages: VecDeque<String>,
    /// Live capture toggle state shared with the sink task.
    capture_state: CaptureState,
    /// Active pane focus (0=routing, 1=traffic, 2=logs).
    focus: usize,
    /// Whether to show the help overlay.
    show_help: bool,
    /// Application version string.
    version: &'static str,
}

impl TuiApp {
    pub fn from_orchestrator(orch: GatewayOrchestrator) -> Self {
        Self {
            metrics: orch.metrics,
            router: orch.router,
            downstream_names: orch.downstream_names,
            traffic: VecDeque::with_capacity(TRAFFIC_HISTORY),
            traffic_rx: orch.traffic_rx,
            log_messages: VecDeque::with_capacity(200),
            capture_state: orch.capture_state,
            focus: 0,
            show_help: false,
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Run the TUI render loop until the user quits.
    ///
    /// On exit, calls `on_quit` to trigger graceful gateway shutdown.
    pub fn run(mut self, on_quit: impl Fn()) -> AppResult<()> {
        // ── Enter raw / alternate-screen terminal ──────────────────────────────
        enable_raw_mode().map_err(crate::error::AppError::Io)?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen).map_err(crate::error::AppError::Io)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)
            .map_err(crate::error::AppError::Io)?;

        let result = self.event_loop(&mut terminal, on_quit);

        // ── Restore terminal ───────────────────────────────────────────────────
        disable_raw_mode().ok();
        execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
        terminal.show_cursor().ok();

        result
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Inner event loop
    // ─────────────────────────────────────────────────────────────────────────

    fn event_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
        on_quit: impl Fn(),
    ) -> AppResult<()> {
        loop {
            // ── Drain traffic broadcast channel ────────────────────────────────
            self.drain_traffic();

            // ── Draw frame ────────────────────────────────────────────────────
            terminal
                .draw(|frame| ui::draw(frame, self))
                .map_err(crate::error::AppError::Io)?;

            // ── Poll for input (blocks up to TICK_RATE) ───────────────────────
            match next_event(TICK_RATE)? {
                AppEvent::Key(key) => {
                    if is_quit(&key) {
                        info!("quit requested from TUI");
                        on_quit();
                        break;
                    }
                    self.handle_key(key.code);
                }
                AppEvent::Resize(_, _) => {
                    // ratatui handles resize automatically on next draw.
                }
                AppEvent::Tick => {}
            }
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Drain broadcast channel into the local ring buffer
    // ─────────────────────────────────────────────────────────────────────────

    fn drain_traffic(&mut self) {
        if let Some(rx) = &mut self.traffic_rx {
            loop {
                match rx.try_recv() {
                    Ok(event) => {
                        if self.traffic.len() >= TRAFFIC_HISTORY {
                            self.traffic.pop_front();
                        }
                        self.traffic.push_back(event);
                    }
                    // Lagged means we fell behind — skip lost events, keep going.
                    Err(broadcast::error::TryRecvError::Lagged(n)) => {
                        info!("TUI traffic display lagged by {n} events (channel full)");
                    }
                    Err(broadcast::error::TryRecvError::Empty) => break,
                    Err(broadcast::error::TryRecvError::Closed) => break,
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Key handler
    // ─────────────────────────────────────────────────────────────────────────

    fn handle_key(&mut self, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode::*;
        match code {
            Tab => {
                self.focus = (self.focus + 1) % 3;
            }
            Char('?') => {
                self.show_help = !self.show_help;
            }
            Char('p') => {
                let new_state = self.capture_state.toggle_pcap();
                info!(enabled = new_state, "PCAP capture toggled");
            }
            Char('c') => {
                let new_state = self.capture_state.toggle_csv();
                info!(enabled = new_state, "CSV capture toggled");
            }
            Char('l') => {
                // Cycle log level (Phase 2: hook into tracing subscriber).
            }
            _ => {}
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Accessors used by ui module
    // ─────────────────────────────────────────────────────────────────────────

    pub fn metrics(&self) -> &MetricsCollector {
        &self.metrics
    }

    pub fn traffic_events(&self) -> &VecDeque<TrafficEvent> {
        &self.traffic
    }

    pub fn downstream_names(&self) -> &[String] {
        &self.downstream_names
    }

    pub fn focus(&self) -> usize {
        self.focus
    }

    pub fn show_help(&self) -> bool {
        self.show_help
    }

    pub fn version(&self) -> &str {
        self.version
    }

    pub fn capture_state(&self) -> &CaptureState {
        &self.capture_state
    }
}
