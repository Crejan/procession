mod common;

use std::fs;
use std::time::Duration;

use common::{Host, golden};
use p_rover::ethtool::{Channels, Coalesce, DriverInfo, Eee, EthtoolData, Fixed, Ring};
use p_rover::observe::nic::{self, Args};

fn lan0_data() -> EthtoolData {
    EthtoolData {
        driver: Some(DriverInfo {
            driver: Some("igb".into()),
            version: Some("6.8".into()),
            firmware: Some("1.63".into()),
            bus_info: Some("0000:04:00.0".into()),
        }),
        stats: [("rx_no_buffer_count".to_string(), 7), ("rx_packets".to_string(), 1000)].into(),
        ring: Some(Ring { rx_max: Some(4096), rx: Some(256), tx_max: Some(4096), tx: Some(256) }),
        coalesce: Some(Coalesce { adaptive_rx: Some(false), rx_usecs: Some(3), rx_frames: Some(0), ..Coalesce::default() }),
        channels: Some(Channels { max_combined: Some(4), combined: Some(2), rx: None, tx: None }),
        eee: Some(Eee { enabled: true, active: false }),
        features: [("generic-receive-offload".to_string(), true), ("large-receive-offload".to_string(), false)].into(),
    }
}

fn args(iface: &str) -> Args {
    Args { iface: iface.into(), delta: None, all_stats: false }
}

#[test]
fn nic_static_with_ethtool_data() {
    let host = Host::new("host1");
    let mut env = host.env(|_| {});
    env.ethtool = Box::new(Fixed::with("lan0", lan0_data()));
    let report = nic::run(&env, &args("lan0")).unwrap();
    golden("nic", &report);
    let ids: Vec<_> = report.findings.iter().map(|f| f.id).collect();
    assert_eq!(ids, ["coalescing-on", "eee-on", "multi-queue"]);
    let irq = report.records.iter().find(|r| r["type"] == "irq" && r["irq"] == 126).unwrap();
    assert_eq!(irq["thread"]["tid"], 12);
    assert_eq!(irq["thread"]["policy"], "fifo");
}

#[test]
fn nic_without_an_ethtool_transport_still_reports_sysfs_and_says_what_is_missing() {
    let host = Host::new("host1");
    let report = nic::run(&host.env(|_| {}), &args("lan0")).unwrap();
    golden("nic-sysfs-only", &report);
    assert!(report.unreadable.iter().any(|u| u.source == "ethtool lan0"));
    let link = &report.records[0];
    assert_eq!((link["name"].as_str(), link["driver"].as_str(), link["pci"].as_str()), (Some("lan0"), Some("igb"), Some("0000:04:00.0")));
    assert_eq!(link["speed_mbps"], 1000);
    assert_eq!(link["admin_up"], true);
    assert_eq!(link["rx_queues"], 2);
}

#[test]
fn nic_delta_lists_errors_first_and_flags_drops() {
    let host = Host::new("host1");
    let root = host.dir.path().to_path_buf();
    let env = host.env(move |_| {
        let stats = root.join("sys/class/net/lan0/statistics");
        for (k, v) in [("rx_missed_errors", 120), ("rx_fifo_errors", 120), ("rx_packets", 6000), ("tx_packets", 905)] {
            fs::write(stats.join(k), format!("{v}\n")).unwrap();
        }
    });
    let mut a = args("lan0");
    a.delta = Some(Duration::from_secs(10));
    let report = nic::run(&env, &a).unwrap();
    golden("nic-delta", &report);
    let names: Vec<_> = report.records.iter().map(|r| r["name"].as_str().unwrap_or("-")).collect();
    assert_eq!(names, ["rx_fifo_errors", "rx_missed_errors", "rx_packets", "tx_packets", "-"]);
    assert_eq!(report.findings[0].id, "nic-drops");
}

#[test]
fn nic_delta_on_a_quiet_interface_is_clean() {
    let host = Host::new("host1");
    let mut a = args("lan0");
    a.delta = Some(Duration::from_secs(2));
    let report = nic::run(&host.env(|_| {}), &a).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.records.last().unwrap()["clean"], true);
}

#[test]
fn bad_or_missing_interfaces_are_refused() {
    let host = Host::new("host1");
    for name in ["../etc", "nosuch0", "", "a b"] {
        let err = nic::run(&host.env(|_| {}), &args(name)).unwrap_err();
        assert_eq!(err.exit_code(), 4, "{name:?}");
    }
    let mut a = args("lan0");
    a.delta = Some(Duration::from_secs(1000));
    assert_eq!(nic::run(&host.env(|_| {}), &a).unwrap_err().exit_code(), 4);
}

#[test]
fn findings_are_for_fieldbus_interfaces_only_when_some_are_configured() {
    let host = Host::new("host1");
    let mut env = host.env(|_| {});
    env.config.fieldbus_interfaces = vec!["lab*".into()];
    env.ethtool = Box::new(Fixed::with("lan0", lan0_data()));
    assert!(nic::run(&env, &args("lan0")).unwrap().findings.is_empty());
}
