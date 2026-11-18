mod common;

use common::{Host, golden};
use p_rover::observe::clock;
use p_rover::runner::Scripted;

const TRACKING: &str = "Reference ID    : 0A000001 (ntp.lab)\nStratum         : 3\nSystem time     : 0.000001234 seconds fast of NTP time\nLeap status     : Normal\n";
const SOURCES: &str = "MS Name/IP address         Stratum Poll Reach LastRx Last sample\n===============================================================================\n^* 10.0.0.1                      2   6   377    33    +12us[  +15us] +/-  1100us\n^- 10.0.0.2                      3   6   377    35    -80us[  -80us] +/-   10ms\n";

#[test]
fn chrony_plus_phc2sys_is_two_clock_masters() {
    let host = Host::new("host1");
    let mut env = host.env(|_| {});
    env.runner = Box::new(Scripted::default().answer("chronyc tracking", TRACKING).answer("chronyc -n sources", SOURCES));
    let report = clock::run(&env).unwrap();
    golden("clock", &report);
    let f = report.findings.iter().find(|f| f.id == "two-clock-masters").expect("finding");
    assert_eq!(f.evidence[0].value, serde_json::json!(["chronyd", "phc2sys"]));
    let sources = report.records.iter().filter(|r| r["type"] == "chrony_source").count();
    assert_eq!(sources, 2);
}

#[test]
fn one_master_and_no_chronyc_is_reported_not_failed() {
    let host = Host::new("host1");
    std::fs::remove_file(host.path("proc/31/comm")).unwrap(); // no phc2sys
    let report = clock::run(&host.env(|_| {})).unwrap();
    assert!(report.findings.is_empty());
    assert!(report.unreadable.iter().any(|u| u.source == "chronyc"), "{:?}", report.unreadable);
    assert_eq!(report.records.last().unwrap()["conflict"], false);
}
