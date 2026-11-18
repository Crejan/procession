mod common;

use common::{Host, golden};
use p_rover::analyze::{self, Args};

fn args() -> Args {
    Args { pid: 100, tids: vec![], static_only: true }
}

#[test]
fn analyze_static_reports_placement_memory_endpoints_interfaces_and_bypass() {
    let host = Host::new("host3");
    let report = analyze::run(&host.env(|_| {}), &args()).unwrap();
    golden("analyze", &report);
    let ids: Vec<_> = report.findings.iter().map(|f| f.id).collect();
    for want in [
        "relative-sleep",
        "rt-on-housekeeping",
        "shared-rt-core",
        "no-mlock",
        "irq-off-core",
        "irq-below-app",
        "multi-queue",
        "irqbalance",
    ] {
        assert!(ids.contains(&want), "{want} missing in {ids:?}");
    }
    assert_eq!(ids.iter().filter(|i| **i == "relative-sleep").count(), 1, "only tid 100 sleeps relative");
    let by = |t: &str| report.values.iter().filter(|r| r["type"] == t).collect::<Vec<_>>();
    assert_eq!(by("process")[0]["vm_lck_kb"], 4096);
    let endpoints: Vec<_> = by("endpoint").iter().map(|e| e["endpoint"].as_str().unwrap().to_string()).collect();
    assert_eq!(endpoints, ["packet", "udp", "vfio", "device"]);
    let packet = by("endpoint")[0];
    assert_eq!((packet["interface"].as_str(), packet["proto"].as_str()), (Some("lan0"), Some("0x88a4")));
    let bypass = by("kernel_bypass");
    assert_eq!(bypass.len(), 2);
    assert_eq!(bypass[0]["pci"], "0000:05:00.0");
    assert_eq!(bypass[0]["attached"], "vfio-pci");
    assert_eq!(bypass[0]["tied_to_process"], true);
    assert_eq!(bypass[0]["irqs"][0]["irq"], 200);
    assert_eq!(bypass[1]["via"], "igh_device");
}

#[test]
fn proposed_changes_carry_the_value_they_replace() {
    let host = Host::new("host3");
    let report = analyze::run(&host.env(|_| {}), &args()).unwrap();
    let change =
        |id: &str| serde_json::to_value(&report.findings.iter().find(|f| f.id == id).unwrap().changes).unwrap();
    assert_eq!(change("rt-on-housekeeping")[0]["kind"], "set_affinity");
    assert_eq!(change("rt-on-housekeeping")[0]["from"], "0-3");
    assert_eq!(change("rt-on-housekeeping")[0]["to"], "2-3");
    assert_eq!(change("shared-rt-core")[0]["to"], "3");
    assert_eq!(change("irq-off-core")[0]["to"], "2");
    assert_eq!(change("irq-below-app")[0]["from"], 50);
    assert_eq!(change("irq-below-app")[0]["to"], 81);
}

#[test]
fn declared_tids_are_always_listed_and_must_belong_to_the_process() {
    let host = Host::new("host3");
    let mut a = args();
    a.tids = vec![103];
    let report = analyze::run(&host.env(|_| {}), &a).unwrap();
    let t = report.values.iter().find(|r| r["type"] == "thread" && r["tid"] == 103).unwrap();
    assert_eq!(t["declared_critical"], true);
    a.tids = vec![9999];
    assert_eq!(analyze::run(&host.env(|_| {}), &a).unwrap_err().exit_code(), 4);
}

#[test]
fn without_static_or_for_a_missing_process_it_is_refused() {
    let host = Host::new("host3");
    let mut a = args();
    a.static_only = false;
    assert_eq!(analyze::run(&host.env(|_| {}), &a).unwrap_err().exit_code(), 4);
    assert_eq!(
        analyze::run(&host.env(|_| {}), &Args { pid: 4242, static_only: true, tids: vec![] }).unwrap_err().exit_code(),
        4
    );
}

#[test]
fn a_process_whose_fds_cannot_be_read_still_gets_the_rest() {
    let host = Host::new("host3");
    std::fs::remove_dir_all(host.path("proc/100/fd")).unwrap();
    let report = analyze::run(&host.env(|_| {}), &args()).unwrap();
    assert!(report.unreadable.iter().any(|u| u.source.ends_with("100/fd")));
    assert!(report.values.iter().any(|r| r["type"] == "thread"));
    assert!(!report.values.iter().any(|r| r["type"] == "endpoint"));
}
