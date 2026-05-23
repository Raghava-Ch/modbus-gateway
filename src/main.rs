// main.rs — modbus-gateway entry point

mod capture;
mod cli;
mod config;
mod error;
mod metrics;
mod orchestrator;
mod tui;

use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use cli::{Cli, Command};
use config::{load_config, validate_config};
use error::AppResult;
use orchestrator::GatewayOrchestrator;
use tui::TuiApp;

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> AppResult<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => cmd_run(args).await,
        Command::Check(args) => cmd_check(args),
        Command::Dump(args) => cmd_dump(args),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `run` command
// ─────────────────────────────────────────────────────────────────────────────

async fn cmd_run(args: cli::RunArgs) -> AppResult<()> {
    // ── Load & validate config ─────────────────────────────────────────────────
    let cfg = load_config(&args)?;
    validate_config(&cfg)?;

    // ── Initialise logging ─────────────────────────────────────────────────────
    let log_level = cfg.general.log_level.clone();
    init_logging(&log_level, cfg.general.tui);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        upstreams = cfg.upstream.len(),
        downstreams = cfg.downstream.len(),
        routes = cfg.route.len(),
        tui = cfg.general.tui,
        "modbus-gateway starting"
    );

    // ── Start gateway orchestrator ─────────────────────────────────────────────
    let orchestrator = GatewayOrchestrator::start(&cfg).await?;
    let shutdown_token = orchestrator.shutdown_token.clone();

    // ── Install Ctrl+C signal handler ─────────────────────────────────────────
    let signal_token = shutdown_token.clone();
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("Ctrl+C received — initiating graceful shutdown");
                signal_token.cancel();
            }
            Err(e) => {
                tracing::error!("signal handler error: {e}");
            }
        }
    });

    let mut shutdown_rx = orchestrator.shutdown_rx.clone();

    if cfg.general.tui {
        // ── Interactive TUI mode ───────────────────────────────────────────────
        // The TUI runs on the current thread (blocking).
        // The gateway tasks run on the Tokio runtime.
        let app = TuiApp::from_orchestrator(orchestrator);
        app.run(move || shutdown_token.cancel())?;

        // Wait up to 3s for background servers to stop cleanly
        let shutdown_future = async move {
            if *shutdown_rx.borrow() {
                return;
            }
            let _ = shutdown_rx.changed().await;
        };
        tokio::time::timeout(std::time::Duration::from_secs(3), shutdown_future).await.ok();
    } else {
        // ── Headless mode: wait for shutdown signal ────────────────────────────
        info!("running in headless mode — press Ctrl+C to stop");
        // Wait until the shutdown token is cancelled and propagated via shutdown_rx.
        let shutdown_future = async move {
            if *shutdown_rx.borrow() {
                return;
            }
            let _ = shutdown_rx.changed().await;
        };
        shutdown_future.await;
    }

    info!("modbus-gateway exited cleanly");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// `check` command
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_check(args: cli::CheckArgs) -> AppResult<()> {
    // Stub RunArgs for config loading (no CLI overrides).
    let run_args = cli::RunArgs {
        config: Some(args.config.clone()),
        upstream: vec![],
        downstream: vec![],
        route: vec![],
        rewrite_offset: None,
        no_tui: true,
        pcap: None,
        csv: None,
        ws_idle_timeout: 0,
        ws_max_sessions: 0,
        ws_require_subprotocol: false,
        ws_allowed_origins: vec![],
        verbose: 0,
    };

    let cfg = load_config(&run_args)?;
    validate_config(&cfg)?;

    println!("✓ {}: configuration is valid", args.config.display());
    println!("  upstreams:   {}", cfg.upstream.len());
    println!("  downstreams: {}", cfg.downstream.len());
    println!("  routes:      {}", cfg.route.len());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// `dump` command
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_dump(args: cli::DumpArgs) -> AppResult<()> {
    use capture::dump::{DumpFormat, dump_pcap_file};

    let fmt = match args.format.to_lowercase().as_str() {
        "csv"  => DumpFormat::Csv,
        _      => DumpFormat::Text,
    };

    let path = args.file.to_string_lossy();
    dump_pcap_file(&path, args.unit_filter, fmt)
}

// ─────────────────────────────────────────────────────────────────────────────
// Logging initialisation
// ─────────────────────────────────────────────────────────────────────────────

fn init_logging(level: &str, tui_mode: bool) {
    if tui_mode {
        // In TUI mode: route tracing events to tui-logger so the log pane
        // can display them. The tui-logger crate provides a tracing layer.
        tui_logger::init_logger(tui_logger::LevelFilter::Trace).ok();
        tui_logger::set_default_level(tui_logger::LevelFilter::Debug);

        // Also install the tui-logger tracing layer.
        tracing_subscriber::registry()
            .with(tui_logger::TuiTracingSubscriberLayer)
            .init();
    } else {
        // Headless mode: pretty-print to stderr.
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(level));
        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(std::io::stderr))
            .with(filter)
            .init();
    }
}
