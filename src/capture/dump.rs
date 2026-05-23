// capture/dump.rs — Offline PCAP → human-readable Modbus traffic decoder
//
// Used by `modbus-gateway dump <FILE>`.

use crate::error::AppResult;
use super::pcap::read_pcap_records;

// ─────────────────────────────────────────────────────────────────────────────
// Modbus function code names
// ─────────────────────────────────────────────────────────────────────────────

fn fc_name(fc: u8) -> &'static str {
    match fc & 0x7F {
        0x01 => "ReadCoils",
        0x02 => "ReadDiscreteInputs",
        0x03 => "ReadHoldingRegisters",
        0x04 => "ReadInputRegisters",
        0x05 => "WriteSingleCoil",
        0x06 => "WriteSingleRegister",
        0x07 => "ReadExceptionStatus",
        0x0F => "WriteMultipleCoils",
        0x10 => "WriteMultipleRegisters",
        0x11 => "ReportServerId",
        0x14 => "ReadFileRecord",
        0x15 => "WriteFileRecord",
        0x16 => "MaskWriteRegister",
        0x17 => "ReadWriteMultipleRegisters",
        0x18 => "ReadFifoQueue",
        0x2B => "EncapsulatedInterfaceTransport",
        _    => "Unknown",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DumpFormat
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpFormat {
    Text,
    Csv,
}

// ─────────────────────────────────────────────────────────────────────────────
// dump_pcap_file
// ─────────────────────────────────────────────────────────────────────────────

/// Decode and print all packets in a pcap file.
///
/// - `unit_filter = 0` means "show all units".
/// - `format` selects text or CSV output.
pub fn dump_pcap_file(path: &str, unit_filter: u8, format: DumpFormat) -> AppResult<()> {
    let records = read_pcap_records(path)?;

    if format == DumpFormat::Csv {
        println!("timestamp,direction,unit_id,txn_id,function_code,fc_name,payload_len,payload_hex");
    } else {
        println!("=== PCAP Dump: {} ===", path);
        println!("  {:>6} records\n", records.len());
    }

    for rec in &records {
        // Our synthesised frame layout:
        //   14  bytes Ethernet
        //   20  bytes IPv4
        //   20  bytes TCP
        //   N   bytes Modbus TCP ADU
        let hdr_offset = 14 + 20 + 20;
        if rec.data.len() <= hdr_offset + 8 {
            continue; // too short to contain a Modbus PDU
        }

        let adu = &rec.data[hdr_offset..];

        // Determine direction from Ethernet src/dst MAC:
        // CLIENT_MAC = 02:00:00:00:00:01
        let src_mac = &rec.data[6..12];
        let upstream_rx = src_mac[5] == 0x01;
        let dir = if upstream_rx { "request " } else { "response" };

        // MBAP header: [txn_hi, txn_lo, proto_hi, proto_lo, len_hi, len_lo, unit_id]
        let txn_id  = u16::from_be_bytes([adu[0], adu[1]]);
        let unit_id = adu[6];
        let fc_raw  = adu[7];
        let is_exc  = fc_raw & 0x80 != 0;
        let fc      = fc_raw & 0x7F;
        let payload_len = adu.len().saturating_sub(8);
        let payload = &adu[8..];

        if unit_filter != 0 && unit_id != unit_filter {
            continue;
        }

        let ts_s  = rec.ts_sec;
        let ts_us = rec.ts_usec;
        let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();

        match format {
            DumpFormat::Text => {
                let exception_tag = if is_exc { " [EXCEPTION]" } else { "" };
                println!(
                    "{ts_s}.{ts_us:06}  {dir}  Unit {:3}  Txn {:5}  FC 0x{fc_raw:02X} {}{exception_tag}",
                    unit_id, txn_id, fc_name(fc),
                );
                if !hex.is_empty() {
                    println!("                               payload({payload_len}): {hex}");
                }
            }
            DumpFormat::Csv => {
                println!(
                    "{ts_s}.{ts_us:06},{dir},{unit_id},{txn_id},0x{fc_raw:02X},{},{payload_len},{hex}",
                    fc_name(fc),
                );
            }
        }
    }

    if format == DumpFormat::Text {
        println!("\n=== End of dump ===");
    }

    Ok(())
}
