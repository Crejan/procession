//! Network-class PCI devices and what drives them: the kernel, or a
//! userspace driver that takes the NIC out of the network stack.

use std::fs;

use serde::Serialize;

use crate::error::Error;
use crate::root::{Root, Scan, Unreadable};

/// Drivers that hand a device to userspace.
pub const BYPASS_DRIVERS: [&str; 3] = ["vfio-pci", "uio_pci_generic", "igb_uio"];

/// What a NIC is attached to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Attached {
    /// A kernel driver; the NIC has a netdev.
    #[serde(rename = "kernel")]
    Kernel,
    /// `vfio-pci`.
    #[serde(rename = "vfio-pci")]
    VfioPci,
    /// `uio_pci_generic`.
    #[serde(rename = "uio")]
    Uio,
    /// `igb_uio`.
    #[serde(rename = "igb_uio")]
    IgbUio,
    /// No driver bound.
    #[serde(rename = "none")]
    None,
}

impl Attached {
    /// From the bound driver's name.
    #[must_use]
    pub fn from_driver(driver: Option<&str>) -> Self {
        match driver {
            None => Self::None,
            Some("vfio-pci") => Self::VfioPci,
            Some("uio_pci_generic") => Self::Uio,
            Some("igb_uio") => Self::IgbUio,
            Some(_) => Self::Kernel,
        }
    }

    /// The device is driven from userspace.
    #[must_use]
    pub fn is_bypass(self) -> bool {
        matches!(self, Self::VfioPci | Self::Uio | Self::IgbUio)
    }
}

/// A network-class PCI device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PciNic {
    /// The address (`0000:04:00.0`).
    pub address: String,
    /// `vendor:device` ids (`8086:1533`).
    pub id: Option<String>,
    /// The bound driver.
    pub driver: Option<String>,
    /// What it is attached to.
    pub attached: Attached,
    /// The netdev, when a kernel driver is bound.
    pub netdev: Option<String>,
    /// The IOMMU group.
    pub iommu_group: Option<u32>,
}

fn file_name(p: &std::path::Path) -> Option<String> {
    Some(p.file_name()?.to_string_lossy().into_owned())
}

/// Every PCI device of class `0x02` (network), by address.
///
/// # Errors
/// When `/sys/bus/pci/devices` cannot be listed.
pub fn network_devices(root: &Root) -> Result<Scan<PciNic>, Error> {
    let dir = root.sys.join("bus/pci/devices");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .map_err(|e| Error::io(&dir, e))?
        .filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned()))
        .collect();
    names.sort();
    let mut out = Scan::default();
    for address in names {
        let d = dir.join(&address);
        let class = match fs::read_to_string(d.join("class")) {
            Ok(c) => c,
            Err(e) => {
                out.unreadable.push(Unreadable::new(d.join("class").display().to_string(), &e));
                continue;
            }
        };
        if !class.trim().starts_with("0x02") {
            continue;
        }
        let read = |f: &str| fs::read_to_string(d.join(f)).ok().map(|s| s.trim().trim_start_matches("0x").to_string());
        let driver = fs::read_link(d.join("driver")).ok().and_then(|p| file_name(&p));
        out.items.push(PciNic {
            id: read("vendor").zip(read("device")).map(|(v, d)| format!("{v}:{d}")),
            attached: Attached::from_driver(driver.as_deref()),
            netdev: fs::read_dir(d.join("net"))
                .ok()
                .and_then(|rd| rd.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).min()),
            iommu_group: fs::read_link(d.join("iommu_group")).ok().and_then(|p| file_name(&p)?.parse().ok()),
            driver,
            address,
        });
    }
    Ok(out)
}

/// The PCI address behind `/dev/uio<n>`.
#[must_use]
pub fn uio_device(root: &Root, n: u32) -> Option<String> {
    file_name(&fs::read_link(root.sys.join("class/uio").join(format!("uio{n}")).join("device")).ok()?)
}

/// The PCI addresses in an IOMMU group (what `/dev/vfio/<group>` opens).
#[must_use]
pub fn vfio_group_devices(root: &Root, group: u32) -> Vec<String> {
    let dir = root.sys.join("kernel/iommu_groups").join(group.to_string()).join("devices");
    let mut v: Vec<String> = fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned())).collect())
        .unwrap_or_default();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_from_driver() {
        assert_eq!(Attached::from_driver(Some("igb")), Attached::Kernel);
        assert_eq!(Attached::from_driver(Some("vfio-pci")), Attached::VfioPci);
        assert_eq!(Attached::from_driver(None), Attached::None);
        assert!(Attached::from_driver(Some("igb_uio")).is_bypass());
        assert!(!Attached::Kernel.is_bypass());
    }
}
