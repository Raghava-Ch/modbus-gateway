# Modbus Gateway CLI & TUI

A high-performance, cross-platform, asynchronous Modbus gateway and terminal monitor powered by [modbus-rs](https://crates.io/crates/modbus-rs) and Ratatui. 

`modbus-rs` acts as a dynamic router and protocol-level bridge. It enables communication across highly heterogeneous Modbus environments by connecting various upstream master interfaces (TCP, WebSockets, Serial, Raw Sockets) to arbitrary downstream slave channels (TCP, RTU, ASCII) with PDU-level translation, packet captures, and rich visual telemetry.

---

## 🚀 Key Features

- **PDU-Level Bridge**: Seamlessly translates framing between **Modbus TCP**, **RTU (Serial)**, **ASCII (Serial)**, and **WebSockets** (specifically optimized for browser-side WASM Modbus clients).
- **Heterogeneous Upstream/Downstream Config**: Spin up multiple listeners and targets concurrently. Mix-and-match TCP, WebSocket, Raw Sockets, and Serial lines.
- **Dynamic User-Space Routing**: Maps upstream Unit IDs to downstream targets dynamically using exact Unit ID routing, range-based routing, or unit translation rewrites (`UnitIdRewriteRouter`).
- **Interactive TUI Dashboard**: A gorgeous, real-time terminal UI built with `ratatui` featuring live latency graphs, error ratios, connection lifecycle states, and route trees.
- **Traffic Capture and Analysis**:
  - **PCAP (Wireshark-ready)**: Live packet dumping. It programmatically wraps raw userspace Modbus frames in synthetic Ethernet, IPv4, and TCP headers (port 502) so that Wireshark can parse, filter, and dissect the captures seamlessly!
  - **CSV**: Simple, tabular logging of timestamps, unit IDs, function codes, and byte frames.
- **Robustness**: Complete graceful shutdown system via Tokio `CancellationToken`s and resilient channel states.

---

## 🛠️ Build & Installation

Prerequisites:
- [Rust Toolchain (Cargo)](https://rustup.rs/) (edition 2021)
- Appropriate serial drivers/permissions for your operating system if mapping serial ports.

Clone the repository and build the project in release mode:

```bash
cargo build --release
```

The compiled binary will be available at `target/release/modbus-gateway`.

---

## 💻 Subcommands & Options

`modbus-gateway` exposes an intuitive CLI built with `clap`.

### Commands Overview

```text
Usage: modbus-gateway <COMMAND>

Commands:
  run    Start the Modbus gateway (optionally with interactive TUI)
  check  Validate a TOML config file without starting the gateway
  dump   Convert a .pcap capture file to human-readable Modbus traffic log
  help   Print this message or the help of the given subcommand(s)
```

---

### 1. `run` Subcommand
Starts the Modbus gateway engine. You can configure it entirely via CLI flags or point it to a structured TOML file.

```text
Usage: modbus-gateway run [OPTIONS]

Options:
  -c, --config <FILE>           Path to a TOML configuration file.
  -u, --upstream <URI>...       Upstream listener URI(s) (e.g., tcp://0.0.0.0:502, ws://0.0.0.0:8502)
  -d, --downstream <URI>...     Downstream target URI(s) (e.g., tcp://192.168.1.10:502)
  -r, --route <SPEC>...         Routing rule(s) (e.g., unit:1=0, range:10-32=1)
      --rewrite-offset <N>      Additive unit-ID rewrite offset applied to all downstream frames
      --no-tui                  Disable the interactive TUI; log structured output to stderr instead
      --pcap <FILE>             Enable Wireshark-ready PCAP traffic capture to this file path
      --csv <FILE>              Enable tabular CSV traffic capture to this file path
      --ws-idle-timeout <SECS>  WebSocket idle-session timeout (default: 0 = disabled)
      --ws-max-sessions <N>     Max concurrent WebSocket sessions (default: 0 = unlimited)
      --ws-require-subprotocol  Require the "modbus" WebSocket subprotocol during handshake
      --ws-allowed-origins <O>  Allowed WebSocket Origin values (comma-separated list)
  -v, --verbose                 Log verbosity (-v = debug, -vv = trace)
```

#### CLI Command Examples:

- **Quick Single-Target TCP Bridge** (Headless with PCAP dump):
  ```bash
  modbus-gateway run \
    --upstream tcp://0.0.0.0:5020 \
    --downstream tcp://192.168.1.100:502 \
    --route unit:1=0 \
    --no-tui \
    --pcap capture.pcap
  ```

- **Mix TCP and RTU Downstreams** (Start with dynamic TUI dashboard):
  ```bash
  modbus-gateway run \
    --upstream tcp://0.0.0.0:502 \
    --downstream tcp://192.168.1.50:502 serial:///dev/ttyUSB0?mode=rtu&baud=19200 \
    --route range:1-10=0 range:11-30=1
  ```

---

### 2. `check` Subcommand
Validates a configuration schema, ensures formatting is correct, and tests routing rules for overlaps without spinning up listeners. Useful for CI/CD or staging config rollouts.

```bash
modbus-gateway check config/gateway.toml
```

---

### 3. `dump` Subcommand
Reads a userspace `.pcap` packet capture file produced by the gateway and decodes the encapsulated Modbus application payloads into text logs or CSV records.

```text
Usage: modbus-gateway dump [OPTIONS] <PCAP_FILE>

Arguments:
  <PCAP_FILE>  Path to the `.pcap` file to decode

Options:
      --unit-filter <UNIT>  Filter output by unit ID (0 = show all) [default: 0]
      --format <FORMAT>     Output format: `text` or `csv` [default: text]
```

#### Example Decoding:
```bash
modbus-gateway dump --format text --unit-filter 5 capture.pcap
```

---

## ⚙️ TOML Configuration Schema

For complex production networks managing multiple serial lines and routes, use a TOML configuration file.

Here is a fully documented configuration template matching `gateway.toml`:

```toml
# ==============================================================================
# General Gateway Config
# ==============================================================================
[general]
log_level = "info"  # trace | debug | info | warn | error
tui = true          # Set to false to run headless with standard logging

# ==============================================================================
# Traffic Logging & Wireshark captures
# ==============================================================================
[pcap]
enabled = true
path = "logs/traffic_capture.pcap"

[csv]
enabled = false
path = "logs/traffic_log.csv"

# ==============================================================================
# Upstream Listeners (TCP, WebSockets, or RTU Serial)
# ==============================================================================
[[upstream]]
type = "tcp"
bind = "0.0.0.0:502"

[[upstream]]
type = "websocket"
bind = "0.0.0.0:8502"
idle_timeout_secs = 60
max_sessions = 16
require_subprotocol = true
allowed_origins = ["http://localhost:3000", "https://hmi.example.com"]

[[upstream]]
type = "serial"
port = "/dev/ttyUSB0"
mode = "rtu"         # rtu | ascii
baud_rate = 19200
data_bits = 8
stop_bits = 1
parity = "none"      # none | odd | even
response_timeout_ms = 1000

# ==============================================================================
# Downstream Devices / Sub-networks
# ==============================================================================
[[downstream]]
type = "tcp"
name = "hvac-controller"
address = "192.168.1.80:502"

[[downstream]]
type = "serial"
name = "rtu-io-rack"
port = "/dev/ttyUSB1"
mode = "rtu"
baud_rate = 9600
data_bits = 8
stop_bits = 1
parity = "none"
response_timeout_ms = 1500

# ==============================================================================
# Dynamic Routing Table
# ==============================================================================
# Maps Upstream Unit IDs to downstream channel names

[[route]]
type = "unit"
unit_id = 1
downstream = "hvac-controller"

[[route]]
type = "range"
min_unit = 10
max_unit = 40
downstream = "rtu-io-rack"

# ==============================================================================
# Unit ID Rewrite Offset (Optional)
# ==============================================================================
# Translates Upstream Unit IDs to match downstream device addressing.
[rewrite]
offset = 100 # Additive: upstream unit ID 5 -> downstream unit ID 105
```

To run using the configuration file:
```bash
modbus-gateway run --config config/gateway.toml
```

---

## 🖥️ Terminal UI (TUI) Dashboard

If TUI mode is active, the interactive dashboard takes over the terminal window:

```text
┌───────────────────────────────── Modbus Gateway Dashboard ──────────────────────────────────┐
│ Upstream Listener: ws://0.0.0.0:8502, tcp://0.0.0.0:502             Uptime: 00h:04m:12s     │
├──────────────────────────┬──────────────────────────────────────────────────────────────────┤
│ Routing Policies [Focus] │  Live Modbus Frame Decodes                                       │
│ ┌──────────────────────┐ │ ┌──────────────────────────────────────────────────────────────┐ │
│ │ unit: 1 -> hvac_tcp  │ │ │ [TX] Target: hvac_tcp  | Unit: 1   | FC: 03 (Holding Regs)   │ │
│ │ range: 10-40 -> rtu  │ │ │ [RX] Target: hvac_tcp  | Unit: 1   | Regs: [100, 201, 30]    │ │
│ └──────────────────────┘ │ │ [TX] Target: rtu_rack  | Unit: 15  | FC: 01 (Read Coils)     │ │
│                          │ │ [ERR] Target: rtu_rack | Unit: 22  | Timeout / No Response   │ │
│                          │ └──────────────────────────────────────────────────────────────┘ │
├──────────────────────────┴──────────────────────────────────────────────────────────────────┤
│ Logs                                                                                        │
│ [INFO] Server listening on ws://0.0.0.0:8502                                                │
│ [DEBUG] Accepted new WebSocket session from 192.168.1.42                                    │
│ [WARN] Retry attempt #1 for unit 15 on channel 1 (rtu-io-rack)...                           │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Keyboard Shortcuts & Navigation
* **`Tab`**: Cycles visual focus between panes (Routing table, Live decodes, Log window).
* **`?`**: Toggles a help overlay showing short descriptions of controls and metrics.
* **`q`** or **`Ctrl+C`**: Triggers a **graceful shutdown** sequence. It stops accepting new connections, allows in-flight frame pipelines to finish, writes and flushes PCAP/CSV buffers cleanly, and exits.

---

## 📈 Wireshark Captures Under User Space

Since our gateway operates entirely in user space, standard network utilities cannot see its internal serial-line or WebSocket routing transitions. 

To bridge this gap, when `--pcap` is enabled, the program programmatically constructs standard Ethernet, IPv4, and TCP frames wrapping the Modbus TCP ADU payload. 
- Packets to TCP or WebSocket upstreams are captured natively.
- Serial (RTU/ASCII) packets are encapsulated into the same synthetic TCP stream using port `502`.
- When opened in Wireshark, **all packets appear as standard Modbus TCP frames** allowing you to use Wireshark filters like `mbtcp` or `modbus` seamlessly.

---

## 🛡️ License

This project source code is licensed under the MIT License. Refer the licensing terms of the libraries used in this project in the crates.