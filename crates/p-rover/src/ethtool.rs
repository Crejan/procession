//! What only `ethtool` knows: driver-specific counters, rings, coalescing,
//! channels, EEE, offloads. A trait, so the subcommands are tested against a
//! fake; the real transport is an open decision (`REPORT.md`) and until it is
//! made [`Unavailable`] says so in the report's `unreadable`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use p_roc::Unreadable;
use serde::Serialize;

/// `ethtool -i`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DriverInfo {
    /// Driver name.
    pub driver: Option<String>,
    /// Driver version.
    pub version: Option<String>,
    /// Firmware version.
    pub firmware: Option<String>,
    /// Bus address.
    pub bus_info: Option<String>,
}

/// `ethtool -g`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Ring {
    /// Maximum receive ring size.
    pub rx_max: Option<u32>,
    /// Current receive ring size.
    pub rx: Option<u32>,
    /// Maximum transmit ring size.
    pub tx_max: Option<u32>,
    /// Current transmit ring size.
    pub tx: Option<u32>,
}

/// `ethtool -c`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Coalesce {
    /// Adaptive receive coalescing.
    pub adaptive_rx: Option<bool>,
    /// Adaptive transmit coalescing.
    pub adaptive_tx: Option<bool>,
    /// `rx-usecs`.
    pub rx_usecs: Option<u32>,
    /// `rx-frames`.
    pub rx_frames: Option<u32>,
    /// `tx-usecs`.
    pub tx_usecs: Option<u32>,
    /// `tx-frames`.
    pub tx_frames: Option<u32>,
}

/// `ethtool -l`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Channels {
    /// Maximum combined channels.
    pub max_combined: Option<u32>,
    /// Current combined channels.
    pub combined: Option<u32>,
    /// Current receive-only channels.
    pub rx: Option<u32>,
    /// Current transmit-only channels.
    pub tx: Option<u32>,
}

/// `ethtool --show-eee`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Eee {
    /// EEE is enabled.
    pub enabled: bool,
    /// EEE is active on the link.
    pub active: bool,
}

/// Everything one interface offers through `ethtool`; each part is absent
/// when the driver does not support it or it could not be read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EthtoolData {
    /// Driver information.
    pub driver: Option<DriverInfo>,
    /// Driver-specific statistics (`ethtool -S`).
    pub stats: BTreeMap<String, u64>,
    /// Ring sizes.
    pub ring: Option<Ring>,
    /// Interrupt coalescing.
    pub coalesce: Option<Coalesce>,
    /// Channel counts.
    pub channels: Option<Channels>,
    /// Energy-efficient Ethernet.
    pub eee: Option<Eee>,
    /// Offload features by name.
    pub features: BTreeMap<String, bool>,
}

/// A source of [`EthtoolData`].
pub trait Ethtool: Send + Sync {
    /// Queries `iface`; what could not be read is listed.
    fn query(&self, iface: &str) -> (EthtoolData, Vec<Unreadable>);
}

/// The real transport is not decided: reports every part as unreadable.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unavailable;

impl Ethtool for Unavailable {
    fn query(&self, iface: &str) -> (EthtoolData, Vec<Unreadable>) {
        let why = Unreadable {
            source: format!("ethtool {iface}"),
            reason: "no ethtool transport in this build: driver counters, rings, coalescing, channels, EEE and offloads are not reported".into(),
        };
        (EthtoolData::default(), vec![why])
    }
}

/// A fake: fixed data per interface, replaceable between samples.
#[derive(Default)]
pub struct Fixed(pub Mutex<BTreeMap<String, EthtoolData>>);

impl Fixed {
    /// A fake that answers for one interface.
    #[must_use]
    pub fn with(iface: &str, data: EthtoolData) -> Self {
        Self(Mutex::new(BTreeMap::from([(iface.to_string(), data)])))
    }
}

impl Ethtool for Fixed {
    fn query(&self, iface: &str) -> (EthtoolData, Vec<Unreadable>) {
        let known = self.0.lock().ok().and_then(|m| m.get(iface).cloned());
        match known {
            Some(d) => (d, Vec::new()),
            None => Unavailable.query(iface),
        }
    }
}
