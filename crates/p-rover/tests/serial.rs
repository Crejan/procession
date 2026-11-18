mod common;

use common::{Host, golden};
use p_rover::observe::serial;

#[test]
fn serial_ports_console_and_getty() {
    let host = Host::new("host1");
    let report = serial::run(&host.env(|_| {})).unwrap();
    golden("serial", &report);
    let port = report.values.iter().find(|r| r["type"] == "port").unwrap();
    assert_eq!((port["tty_s"].as_u64(), port["rx"].as_u64(), port["irq"].as_u64()), (Some(0), Some(3456), Some(4)));
    assert_eq!(port["errors"]["oe"], 2);
    let getty = report.values.iter().find(|r| r["type"] == "getty").unwrap();
    assert_eq!(getty["tty"], "ttyS0");
    let sysfs = report.values.iter().find(|r| r["type"] == "sysfs").unwrap();
    assert_eq!(sysfs["pci"], "0000:00:16.3");
}

#[test]
fn a_host_without_serial_driver_says_so() {
    let host = Host::new("host1");
    std::fs::remove_file(host.path("proc/tty/driver/serial")).unwrap();
    let report = serial::run(&host.env(|_| {})).unwrap();
    assert!(report.unreadable.iter().any(|u| u.source.contains("tty/driver/serial")));
}
