//! The observe subcommands: each reads, none changes anything.

pub mod cmdline;
pub mod irq;
pub mod nic;
pub mod procs;
pub mod sched;

use p_roc::cpus::{self, Isolation};
use p_roc::{CpuSet, Unreadable};

use crate::env::Env;
use crate::report::{Finding, Metric, Report, Severity, Subject};

/// The CPUs p-rover treats as isolated: the kernel's isolated set plus the
/// tick-free ones, with every source it read from.
#[derive(Clone, Debug)]
pub struct Cpus {
    /// What each source says.
    pub sources: Isolation,
    /// `sysfs_isolated` ∪ `nohz_full`.
    pub isolated: CpuSet,
    /// Online CPUs that are not isolated; empty when the online set is unreadable.
    pub housekeeping: CpuSet,
}

/// Reads the isolation sources and the online set; what fails is added to
/// the report's `unreadable`.
pub fn cpus(env: &Env, report: &mut Report) -> Cpus {
    let (sources, bad) = Isolation::read(&env.root);
    report.unreadable(bad);
    let isolated = sources.sysfs_isolated.union(&sources.nohz_full);
    let housekeeping = match cpus::online(&env.root) {
        Ok(online) => online.difference(&isolated),
        Err(e) => {
            report.unreadable([Unreadable::new("sys/devices/system/cpu/online", &e)]);
            CpuSet::new()
        }
    };
    Cpus { sources, isolated, housekeeping }
}

/// Adds what every subcommand reports: `stale-probe` while an unrestored
/// probe ledger exists.
pub fn finish(env: &Env, report: &mut Report) {
    let dir = &env.config.probe.ledger_dir;
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut stale: Vec<String> = rd
        .filter_map(Result::ok)
        .filter(|e| e.path().join("plan.json").is_file() && !e.path().join("restored").exists())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    stale.sort();
    if !stale.is_empty() {
        report.findings.push(Finding {
            id: "stale-probe",
            severity: Severity::Warn,
            subject: Subject::Host,
            evidence: vec![Metric::new("ledgers", &stale), Metric::new("ledger_dir", dir.display().to_string())],
            recommendation: "a probe left knobs changed; run `prover probe status`, then `prover probe restore --all`".into(),
            changes: Vec::new(),
        });
    }
}
