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

/// Every source that says which CPUs are isolated or tick-free. p-roc
/// reports each; it does not merge them. A source that could not be read is
/// empty here and listed in the `unreadable` of [`Isolation::read`].
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Isolation {
    /// `/sys/devices/system/cpu/isolated`.
    pub sysfs_isolated: CpuSet,
    /// `isolcpus=` on the command line, flags skipped.
    pub isolcpus: CpuSet,
    /// `/sys/devices/system/cpu/nohz_full`, else `nohz_full=` on the command line.
    pub nohz_full: CpuSet,
    /// `rcu_nocbs=` on the command line.
    pub rcu_nocbs: CpuSet,
    /// `irqaffinity=` on the command line.
    pub irqaffinity: CpuSet,
}

impl Isolation {
    /// Reads all sources; those that fail are listed, not fatal.
    #[must_use]
    pub fn read(root: &Root) -> (Self, Vec<crate::root::Unreadable>) {
        use crate::cmdline::Cmdline;
        use crate::root::Unreadable;
        let mut bad = Vec::new();
        let mut keep = |what: &str, r: Result<CpuSet, Error>| {
            r.unwrap_or_else(|e| {
                bad.push(Unreadable::new(what, &e));
                CpuSet::new()
            })
        };
        let cmdline = Cmdline::read(root);
        let from_cmd = |key: &str| cmdline.as_ref().map_err(|e| Error::parse("cmdline", e)).and_then(|c| c.cpu_list(key));
        let sysfs_isolated = keep("sys/devices/system/cpu/isolated", sysfs_isolated(root));
        let nohz_sys = cpu_list(root, "nohz_full");
        let nohz_full = match nohz_sys {
            Ok(s) => s,
            Err(_) => keep("cmdline: nohz_full", from_cmd("nohz_full").map(Option::unwrap_or_default)),
        };
        let isolcpus = keep("cmdline: isolcpus", from_cmd("isolcpus").map(Option::unwrap_or_default));
        let rcu_nocbs = keep("cmdline: rcu_nocbs", from_cmd("rcu_nocbs").map(Option::unwrap_or_default));
        let irqaffinity = keep("cmdline: irqaffinity", from_cmd("irqaffinity").map(Option::unwrap_or_default));
        (Self { sysfs_isolated, isolcpus, nohz_full, rcu_nocbs, irqaffinity }, bad)
    }
}
