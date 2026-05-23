// capture/mod.rs — Traffic capture pipeline (PCAP + CSV)

pub mod csv;
pub mod dump;
pub mod pcap;
pub mod sink;

pub use sink::{CaptureConfig, CaptureState};
