mod common;

use std::fs;

use common::{Host, golden};
use p_rover::observe::cmdline;

#[test]
fn live_against_replayed_grub_config() {
    let host = Host::new("host1");
    let report = cmdline::run(&host.env(|_| {})).unwrap();
    golden("cmdline", &report);
    let diff = report.values.iter().find(|r| r["type"] == "diff").unwrap();
    // threadirqs and skew_tick are declared by grub.d but the live line lacks them.
    assert_eq!(diff["declared_not_live"], serde_json::json!(["threadirqs", "skew_tick=1"]));
    assert_eq!(diff["live_not_declared"], serde_json::json!(["console=ttyS0,115200"]));
    assert_eq!(diff["in_sync"], false);
    assert!(report.findings.iter().any(|f| f.id == "cmdline-drift"));
    assert!(!report.findings.iter().any(|f| f.id == "isolation-drift"));
}

#[test]
fn config_declared_cmdline_wins_and_isolation_drift_is_found() {
    let host = Host::new("host1");
    let mut env = host.env(|_| {});
    env.config.declared_cmdline = Some("BOOT_IMAGE=x root=/dev/sda ro isolcpus=2-4 nohz_full=2-4 quiet".into());
    let report = cmdline::run(&env).unwrap();
    let declared = report.values.iter().find(|r| r["type"] == "declared").unwrap();
    assert_eq!(declared["source"], "config");
    let drift = report.findings.iter().find(|f| f.id == "isolation-drift").expect("isolation-drift");
    assert_eq!(drift.evidence[1].value, "2-4");
}

#[test]
fn nothing_declared_is_no_drift_finding() {
    let host = Host::new("host1");
    fs::remove_dir_all(host.path("etc")).unwrap();
    let report = cmdline::run(&host.env(|_| {})).unwrap();
    let declared = report.values.iter().find(|r| r["type"] == "declared").unwrap();
    assert_eq!(declared["source"], "none");
    assert!(report.findings.is_empty());
}
