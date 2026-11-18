//! Which CPUs exist and which the kernel calls isolated.

use crate::cpuset::CpuSet;
use crate::error::Error;
use crate::root::{Root, read};

fn cpu_list(root: &Root, name: &str) -> Result<CpuSet, Error> {
    let path = root.sys.join("devices/system/cpu").join(name);
    let content = read(&path)?;
    CpuSet::parse_list(&content).map_err(|source| Error::Cpus { what: path.display().to_string(), source })
}

/// `/sys/devices/system/cpu/online`.
///
/// # Errors
/// When the file is missing or malformed.
pub fn online(root: &Root) -> Result<CpuSet, Error> {
    cpu_list(root, "online")
}

/// `/sys/devices/system/cpu/possible`.
///
/// # Errors
/// When the file is missing or malformed.
pub fn possible(root: &Root) -> Result<CpuSet, Error> {
    cpu_list(root, "possible")
}

/// `/sys/devices/system/cpu/isolated`: the CPUs the kernel calls isolated.
/// p-roc reports this source alone; merging it with `nohz_full` and the
/// command line is the tool's decision.
///
/// # Errors
/// When the file is missing or malformed.
pub fn sysfs_isolated(root: &Root) -> Result<CpuSet, Error> {
    cpu_list(root, "isolated")
}
