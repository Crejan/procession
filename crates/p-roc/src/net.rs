//! Network interfaces from `/sys/class/net`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::Serialize;

use crate::error::Error;
use crate::root::{Root, read};

fn opt(path: &std::path::Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn num<T: std::str::FromStr>(path: &std::path::Path) -> Option<T> {
    opt(path)?.parse().ok()
}

/// Whether `s` is a PCI address (`0000:04:00.0`).
#[must_use]
pub fn is_pci_address(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 12
        && b[4] == b':'
        && b[7] == b':'
        && b[10] == b'.'
        && b.iter().enumerate().all(|(i, c)| matches!(i, 4 | 7 | 10) || c.is_ascii_hexdigit())
}

/// What `/sys/class/net/<if>` says about the link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Link {
    /// `operstate` (`up`, `down`, `unknown`, ...).
    pub operstate: Option<String>,
    /// `carrier`; unreadable while the interface is down.
    pub carrier: Option<bool>,
    /// `speed` in Mb/s; unreadable while the link is down.
    pub speed_mbps: Option<i64>,
    /// `duplex`.
    pub duplex: Option<String>,
    /// `mtu`.
    pub mtu: Option<u32>,
    /// `address`.
    pub address: Option<String>,
    /// `carrier_changes`.
    pub carrier_changes: Option<u64>,
    /// `flags` has `IFF_UP`.
    pub admin_up: Option<bool>,
}

/// One interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Interface {
    /// The name.
    pub name: String,
    /// `ifindex`.
    pub ifindex: Option<u32>,
    /// The link.
    #[serde(flatten)]
    pub link: Link,
    /// The kernel driver bound to the device (`device/driver`).
    pub driver: Option<String>,
    /// The PCI address of the device, when it is a PCI device.
    pub pci: Option<String>,
    /// Number of receive queues.
    pub rx_queues: usize,
    /// Number of transmit queues.
    pub tx_queues: usize,
    /// IRQs of the device: `device/msi_irqs`, else `device/irq`.
    pub irqs: Vec<u32>,
}

/// The interface names.
///
/// # Errors
/// When `/sys/class/net` cannot be listed.
pub fn interfaces(root: &Root) -> Result<Vec<String>, Error> {
    let dir = root.sys.join("class/net");
    let mut v: Vec<String> = fs::read_dir(&dir)
        .map_err(|e| Error::io(&dir, e))?
        .filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned()))
        .collect();
    v.sort();
    Ok(v)
}

fn count_queues(dir: &std::path::Path, prefix: &str) -> usize {
    fs::read_dir(dir).map_or(0, |rd| rd.filter_map(Result::ok).filter(|e| e.file_name().to_string_lossy().starts_with(prefix)).count())
}

/// Reads one interface.
///
/// # Errors
/// When the interface does not exist.
pub fn interface(root: &Root, name: &str) -> Result<Interface, Error> {
    let base: PathBuf = root.sys.join("class/net").join(name);
    if !base.is_dir() {
        return Err(Error::io(&base, std::io::ErrorKind::NotFound.into()));
    }
    let dev = base.join("device");
    let flags: Option<u32> = opt(&base.join("flags")).and_then(|f| u32::from_str_radix(f.trim_start_matches("0x"), 16).ok());
    let mut irqs: Vec<u32> = fs::read_dir(dev.join("msi_irqs"))
        .map(|rd| rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect())
        .unwrap_or_default();
    if irqs.is_empty() {
        irqs.extend(num::<u32>(&dev.join("irq")).filter(|i| *i > 0));
    }
    irqs.sort_unstable();
    Ok(Interface {
        name: name.to_string(),
        ifindex: num(&base.join("ifindex")),
        link: Link {
            operstate: opt(&base.join("operstate")),
            carrier: opt(&base.join("carrier")).map(|c| c == "1"),
            speed_mbps: num(&base.join("speed")),
            duplex: opt(&base.join("duplex")),
            mtu: num(&base.join("mtu")),
            address: opt(&base.join("address")),
            carrier_changes: num(&base.join("carrier_changes")),
            admin_up: flags.map(|f| f & 1 != 0),
        },
        driver: fs::read_link(dev.join("driver")).ok().and_then(|p| Some(p.file_name()?.to_string_lossy().into_owned())),
        pci: fs::read_link(&dev)
            .ok()
            .and_then(|p| Some(p.file_name()?.to_string_lossy().into_owned()))
            .filter(|n| is_pci_address(n)),
        rx_queues: count_queues(&base.join("queues"), "rx-"),
        tx_queues: count_queues(&base.join("queues"), "tx-"),
        irqs,
    })
}

/// The kernel's generic counters in `/sys/class/net/<if>/statistics`.
///
/// # Errors
/// When the directory cannot be read.
pub fn statistics(root: &Root, name: &str) -> Result<BTreeMap<String, u64>, Error> {
    let dir = root.sys.join("class/net").join(name).join("statistics");
    let mut out = BTreeMap::new();
    for e in fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
        let Ok(e) = e else { continue };
        if let Some(v) = read(&e.path()).ok().and_then(|s| s.trim().parse::<u64>().ok()) {
            out.insert(e.file_name().to_string_lossy().into_owned(), v);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_addresses() {
        assert!(is_pci_address("0000:04:00.0"));
        assert!(!is_pci_address("platform"));
        assert!(!is_pci_address("0000:04:00:0"));
    }
}
