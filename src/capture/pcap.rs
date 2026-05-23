// capture/pcap.rs — Self-contained PCAP writer synthesising Ethernet/IPv4/TCP headers
//
// Output format: libpcap 2.4, LINKTYPE_ETHERNET (1).
// No external PCAP crate is needed — we write raw bytes directly.
//
// Wireshark opens the resulting file and the Modbus TCP dissector parses the
// payload natively when `dst_port = 502`.

use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;

use crate::error::{AppError, AppResult};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const PCAP_MAGIC: u32       = 0xa1b2c3d4; // little-endian host byte order
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const LINK_TYPE_ETHERNET: u32 = 1;

// Synthesised MAC addresses (locally-administered unicast).
const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]; // upstream side
const SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02]; // downstream side

// Synthesised IP addresses.
const UPSTREAM_IP: Ipv4Addr  = Ipv4Addr::new(10, 0, 0, 1);
const DOWNSTREAM_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

const MODBUS_TCP_PORT: u16 = 502;
const IP_TTL: u8           = 64;
const IP_PROTO_TCP: u8     = 6;
const ETHERTYPE_IPV4: u16  = 0x0800;

// ─────────────────────────────────────────────────────────────────────────────
// PcapWriter
// ─────────────────────────────────────────────────────────────────────────────

/// Writes synthesised Ethernet/IPv4/TCP packets encapsulating Modbus TCP ADUs
/// into a libpcap 2.4 file that Wireshark can open directly.
pub struct PcapWriter {
    writer: BufWriter<std::fs::File>,
    /// Per-direction TCP sequence number accumulators.
    seq_upstream:   u32,
    seq_downstream: u32,
    /// Per-direction source port (rotates to simulate distinct connections).
    src_port_upstream:   u16,
    src_port_downstream: u16,
}

impl PcapWriter {
    /// Open (and truncate) a new PCAP file, writing the global header immediately.
    pub fn create(path: &str) -> AppResult<Self> {
        let file = std::fs::File::create(path)
            .map_err(|e| AppError::Io(e))?;
        let mut writer = BufWriter::new(file);
        write_global_header(&mut writer)?;
        Ok(Self {
            writer,
            seq_upstream:        0,
            seq_downstream:      0,
            src_port_upstream:   60000,
            src_port_downstream: 60001,
        })
    }

    /// Write a single traffic frame as a synthesised Ethernet/IPv4/TCP packet.
    ///
    /// - `upstream_rx = true`  → frame flows from client (10.0.0.1) to gateway (10.0.0.2)
    /// - `upstream_rx = false` → frame flows from gateway (10.0.0.2) to device (10.0.0.1)
    pub fn write_packet(
        &mut self,
        ts: chrono::DateTime<chrono::Local>,
        upstream_rx: bool,
        payload: &[u8],
    ) -> AppResult<()> {
        // Choose direction-specific addresses and ports.
        let (src_ip, dst_ip, src_port, dst_port, seq) = if upstream_rx {
            let s = self.seq_upstream;
            self.seq_upstream = self.seq_upstream.wrapping_add(payload.len() as u32);
            (UPSTREAM_IP, DOWNSTREAM_IP, self.src_port_upstream, MODBUS_TCP_PORT, s)
        } else {
            let s = self.seq_downstream;
            self.seq_downstream = self.seq_downstream.wrapping_add(payload.len() as u32);
            (DOWNSTREAM_IP, UPSTREAM_IP, self.src_port_downstream, MODBUS_TCP_PORT, s)
        };

        // Build Ethernet + IPv4 + TCP header chain.
        let tcp_hdr   = build_tcp_header(src_port, dst_port, seq, payload);
        let ip_hdr    = build_ipv4_header(src_ip, dst_ip, &tcp_hdr, payload);
        let eth_frame = build_ethernet_frame(&ip_hdr, &tcp_hdr, payload, upstream_rx);

        // Write pcap record header (16 bytes).
        let ts_sec  = ts.timestamp() as u32;
        let ts_usec = ts.timestamp_subsec_micros();
        let total_len = eth_frame.len() as u32;
        write_u32_le(&mut self.writer, ts_sec)?;
        write_u32_le(&mut self.writer, ts_usec)?;
        write_u32_le(&mut self.writer, total_len)?; // incl_len
        write_u32_le(&mut self.writer, total_len)?; // orig_len

        // Write the packet data.
        self.writer.write_all(&eth_frame)
            .map_err(AppError::Io)?;

        Ok(())
    }

    /// Flush the internal buffer to disk.
    pub fn flush(&mut self) -> AppResult<()> {
        self.writer.flush().map_err(AppError::Io)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global header
// ─────────────────────────────────────────────────────────────────────────────

fn write_global_header(w: &mut impl Write) -> AppResult<()> {
    write_u32_le(w, PCAP_MAGIC)?;
    write_u16_le(w, PCAP_VERSION_MAJOR)?;
    write_u16_le(w, PCAP_VERSION_MINOR)?;
    write_i32_le(w, 0)?;          // thiszone  (GMT)
    write_u32_le(w, 0)?;          // sigfigs
    write_u32_le(w, 65535)?;      // snaplen
    write_u32_le(w, LINK_TYPE_ETHERNET)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Frame builders
// ─────────────────────────────────────────────────────────────────────────────

fn build_ethernet_frame(
    ip_hdr: &[u8],
    tcp_hdr: &[u8],
    payload: &[u8],
    upstream_rx: bool,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + ip_hdr.len() + tcp_hdr.len() + payload.len());
    // dst MAC, src MAC
    if upstream_rx {
        frame.extend_from_slice(&SERVER_MAC); // dst = gateway side
        frame.extend_from_slice(&CLIENT_MAC); // src = client side
    } else {
        frame.extend_from_slice(&CLIENT_MAC);
        frame.extend_from_slice(&SERVER_MAC);
    }
    // EtherType = IPv4
    frame.push((ETHERTYPE_IPV4 >> 8) as u8);
    frame.push((ETHERTYPE_IPV4 & 0xFF) as u8);
    frame.extend_from_slice(ip_hdr);
    frame.extend_from_slice(tcp_hdr);
    frame.extend_from_slice(payload);
    frame
}

fn build_ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, tcp_hdr: &[u8], payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + tcp_hdr.len() + payload.len()) as u16;
    let mut hdr = vec![
        0x45,                               // version=4, IHL=5 (20 bytes)
        0x00,                               // DSCP+ECN
        (total_len >> 8) as u8,             // total length high
        (total_len & 0xFF) as u8,           // total length low
        0x00, 0x01,                         // identification
        0x40, 0x00,                         // flags=DF, fragment offset=0
        IP_TTL,                             // TTL
        IP_PROTO_TCP,                       // protocol
        0x00, 0x00,                         // checksum placeholder
    ];
    hdr.extend_from_slice(&src.octets());
    hdr.extend_from_slice(&dst.octets());

    // Calculate IPv4 header checksum.
    let cksum = ipv4_checksum(&hdr);
    hdr[10] = (cksum >> 8) as u8;
    hdr[11] = (cksum & 0xFF) as u8;

    hdr
}

fn build_tcp_header(src_port: u16, dst_port: u16, seq: u32, _payload: &[u8]) -> Vec<u8> {
    vec![
        (src_port >> 8) as u8, (src_port & 0xFF) as u8,  // src port
        (dst_port >> 8) as u8, (dst_port & 0xFF) as u8,  // dst port
        (seq >> 24) as u8, (seq >> 16) as u8,             // sequence number
        (seq >> 8) as u8,  (seq & 0xFF) as u8,
        0x00, 0x00, 0x00, 0x00,                           // ack number
        0x50,                                             // data offset = 5 (20 bytes), reserved
        0x18,                                             // flags: PSH + ACK
        0x20, 0x00,                                       // window = 8192
        0x00, 0x00,                                       // checksum = 0 (unchecked)
        0x00, 0x00,                                       // urgent pointer
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// IPv4 header checksum (RFC 791)
// ─────────────────────────────────────────────────────────────────────────────

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        let word = ((header[i] as u32) << 8) | (header[i + 1] as u32);
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < header.len() {
        sum = sum.wrapping_add((header[i] as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ─────────────────────────────────────────────────────────────────────────────
// PCAP reader — used by the `dump` subcommand
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal pcap record parsed from a file written by `PcapWriter`.
#[derive(Debug)]
pub struct PcapRecord {
    pub ts_sec:  u32,
    pub ts_usec: u32,
    pub data:    Vec<u8>,
}

/// Read all packet records from a pcap file.
/// Returns `Err` if the file is not a valid libpcap file.
pub fn read_pcap_records(path: &str) -> AppResult<Vec<PcapRecord>> {
    use std::io::{BufReader, Read};

    let file = std::fs::File::open(path).map_err(AppError::Io)?;
    let mut r = BufReader::new(file);

    // ── Global header ──────────────────────────────────────────────────────────
    let magic = read_u32(&mut r)?;
    let byte_swap = match magic {
        0xa1b2c3d4 => false,  // host is little-endian (matches our writer)
        0xd4c3b2a1 => true,   // host is big-endian
        _ => return Err(AppError::Config(format!("not a pcap file (magic 0x{magic:08x})"))),
    };

    // Skip remainder of global header (20 bytes).
    let mut skip = [0u8; 20];
    r.read_exact(&mut skip).map_err(AppError::Io)?;

    // ── Packet records ────────────────────────────────────────────────────────
    let mut records = Vec::new();
    loop {
        let ts_sec = match read_u32_opt(&mut r)? {
            Some(v) => v,
            None    => break,
        };
        let ts_usec  = read_u32(&mut r)?;
        let incl_len = read_u32(&mut r)?;
        let _orig_len = read_u32(&mut r)?;

        let (ts_sec, ts_usec, incl_len) = if byte_swap {
            (ts_sec.swap_bytes(), ts_usec.swap_bytes(), incl_len.swap_bytes())
        } else {
            (ts_sec, ts_usec, incl_len)
        };

        let mut data = vec![0u8; incl_len as usize];
        r.read_exact(&mut data).map_err(AppError::Io)?;

        records.push(PcapRecord { ts_sec, ts_usec, data });
    }

    Ok(records)
}

// ─────────────────────────────────────────────────────────────────────────────
// Little-endian I/O helpers
// ─────────────────────────────────────────────────────────────────────────────

fn write_u16_le(w: &mut impl Write, v: u16) -> AppResult<()> {
    w.write_all(&v.to_le_bytes()).map_err(AppError::Io)
}
fn write_u32_le(w: &mut impl Write, v: u32) -> AppResult<()> {
    w.write_all(&v.to_le_bytes()).map_err(AppError::Io)
}
fn write_i32_le(w: &mut impl Write, v: i32) -> AppResult<()> {
    w.write_all(&v.to_le_bytes()).map_err(AppError::Io)
}

fn read_u32(r: &mut impl std::io::Read) -> AppResult<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).map_err(AppError::Io)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u32_opt(r: &mut impl std::io::Read) -> AppResult<Option<u32>> {
    let mut buf = [0u8; 4];
    match r.read_exact(&mut buf) {
        Ok(()) => Ok(Some(u32::from_le_bytes(buf))),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(AppError::Io(e)),
    }
}
