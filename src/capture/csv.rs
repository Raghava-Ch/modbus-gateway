// capture/csv.rs — CSV traffic log writer

use std::io::{BufWriter, Write};

use crate::error::{AppError, AppResult};
use crate::metrics::{TrafficDirection, TrafficEvent};

// ─────────────────────────────────────────────────────────────────────────────
// CsvWriter
// ─────────────────────────────────────────────────────────────────────────────

/// Appends CSV rows to a file.
///
/// Format:
/// ```csv
/// timestamp,direction,session,channel,unit_id,function_code,data_len,raw_hex
/// ```
pub struct CsvWriter {
    writer: BufWriter<std::fs::File>,
}

impl CsvWriter {
    /// Create (or truncate) a CSV file and write the header row.
    pub fn create(path: &str) -> AppResult<Self> {
        let file = std::fs::File::create(path).map_err(AppError::Io)?;
        let mut writer = BufWriter::new(file);
        writeln!(
            writer,
            "timestamp,direction,session,channel,unit_id,function_code,data_len,raw_hex"
        )
        .map_err(AppError::Io)?;
        Ok(Self { writer })
    }

    /// Write one CSV row for a `TrafficEvent`.
    pub fn write_event(&mut self, ev: &TrafficEvent) -> AppResult<()> {
        let ts = ev.timestamp.format("%Y-%m-%dT%H:%M:%S%.3f");
        let dir = match ev.direction {
            TrafficDirection::UpstreamRx => "UpstreamRx",
            TrafficDirection::DownstreamTx => "DownstreamTx",
            TrafficDirection::DownstreamRx => "DownstreamRx",
            TrafficDirection::UpstreamTx => "UpstreamTx",
        };

        // Parse Modbus TCP ADU fields (best-effort — MBAP header is 7 bytes).
        let (unit_id, fc, data_len) = if ev.frame.len() >= 8 {
            // MBAP: [txn_hi, txn_lo, proto_hi, proto_lo, len_hi, len_lo, unit_id]
            // PDU:  [function_code, data...]
            let unit = ev.frame[6];
            let fc   = ev.frame[7];
            let data = ev.frame.len().saturating_sub(8);
            (unit.to_string(), format!("0x{:02X}", fc), data.to_string())
        } else {
            ("-".to_string(), "-".to_string(), ev.frame.len().to_string())
        };

        let hex: String = ev.frame.iter().map(|b| format!("{b:02x}")).collect();

        writeln!(
            self.writer,
            "{ts},{dir},{},{},{unit_id},{fc},{data_len},{hex}",
            ev.session_id,
            ev.channel_idx,
        )
        .map_err(AppError::Io)?;

        Ok(())
    }

    /// Flush the write buffer to disk.
    pub fn flush(&mut self) -> AppResult<()> {
        self.writer.flush().map_err(AppError::Io)
    }
}
