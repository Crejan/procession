mod common;

use common::{Host, golden};
use p_rover::observe::procs::{self, Args};

#[test]
fn procs_lists_rt_and_isolated_and_flags_housekeeping() {
    let host = Host::new("host1");
    let report = procs::run(&host.env(|_| {}), &Args::default()).unwrap();
    golden("procs", &report);
    let ids: Vec<_> = report.findings.iter().map(|f| (f.id, format!("{:?}", f.subject))).collect();
    assert_eq!(ids.len(), 1, "{ids:?}"); // only tid 10 may run on housekeeping; 11 is pinned, 12 is a kthread
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn procs_caps_records_and_says_so() {
    let host = Host::new("host1");
    let report = procs::run(&host.env(|_| {}), &Args { max: 2 }).unwrap();
    assert_eq!(report.records.len(), 3);
    assert_eq!(report.records[2]["shown"], 2);
    assert_eq!(report.records[2]["truncated"], true);
}

#[test]
fn procs_without_isolation_sources_reports_them_unreadable() {
    let host = Host::new("host1");
    std::fs::remove_file(host.path("sys/devices/system/cpu/isolated")).unwrap();
    let report = procs::run(&host.env(|_| {}), &Args::default()).unwrap();
    assert!(report.unreadable.iter().any(|u| u.source.contains("isolated")));
}

#[test]
fn an_unrestored_ledger_is_a_finding_of_every_subcommand() {
    let host = Host::new("host1");
    let ledger = tempfile::tempdir().unwrap();
    for (id, restored) in [("a", true), ("b", false)] {
        std::fs::create_dir_all(ledger.path().join(id)).unwrap();
        std::fs::write(ledger.path().join(id).join("plan.json"), "{}").unwrap();
        if restored {
            std::fs::write(ledger.path().join(id).join("restored"), "").unwrap();
        }
    }
    let mut env = host.env(|_| {});
    env.config.probe.ledger_dir = ledger.path().to_path_buf();
    let report = procs::run(&env, &Args::default()).unwrap();
    let f = report.findings.iter().find(|f| f.id == "stale-probe").expect("stale-probe");
    assert_eq!(f.evidence[0].value, serde_json::json!(["b"]));
}
