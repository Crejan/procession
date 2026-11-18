//! `serial`: which serial port is the console, and what runs on it.

use p_roc::cmdline::Cmdline;
use p_roc::net::is_pci_address;
use p_roc::{Unreadable, task};
use serde::Serialize;

use crate::env::Env;
use crate::error::Error;
use crate::observe::finish;
use crate::report::{Cost, Report};

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Cmdline { console: Vec<String> },
    ActiveConsole { ttys: Vec<String> },
    Port {
        tty_s: u32,
        uart: String,
        port: Option<String>,
        irq: Option<u32>,
        tx: Option<u64>,
        rx: Option<u64>,
        modem_lines: Vec<String>,
        errors: std::collections::BTreeMap<String, u64>,
    },
    Sysfs { tty: String, pci: Option<String>, port: Option<String>, irq: Option<String>, kind: Option<String> },
    Getty { pid: i32, tty: Option<String>, cmdline: String },
}

/// One line of `/proc/tty/driver/serial`:
/// `0: uart:16550A port:000003F8 irq:4 tx:0 rx:0 RTS|CTS|DTR|DSR|CD`.
fn parse_port(line: &str) -> Option<Record> {
    let (n, rest) = line.trim().split_once(':')?;
    let tty_s: u32 = n.parse().ok()?;
    let (mut uart, mut port, mut irq, mut tx, mut rx) = (None, None, None, None, None);
    let (mut modem_lines, mut errors) = (Vec::new(), std::collections::BTreeMap::new());
    for tok in rest.split_whitespace() {
        match tok.split_once(':') {
            Some(("uart", v)) => uart = Some(v.to_string()),
            Some(("port", v)) => port = Some(v.to_string()),
            Some(("irq", v)) => irq = v.parse().ok(),
            Some(("tx", v)) => tx = v.parse().ok(),
            Some(("rx", v)) => rx = v.parse().ok(),
            Some((k @ ("fe" | "brk" | "oe" | "pe"), v)) => {
                if let Ok(v) = v.parse() {
                    errors.insert(k.to_string(), v);
                }
            }
            Some(_) => {}
            None => modem_lines = tok.split('|').map(str::to_string).collect(),
        }
    }
    let uart = uart.filter(|u| u != "unknown")?;
    Some(Record::Port { tty_s, uart, port, irq, tx, rx, modem_lines, errors })
}

/// Runs `serial`.
///
/// # Errors
/// When the process list cannot be read.
pub fn run(env: &Env) -> Result<Report, Error> {
    let mut report = Report::new(env, "serial", Cost::Light);
    let console = Cmdline::read(&env.root)
        .map(|c| c.tokens().iter().filter_map(|t| t.strip_prefix("console=").map(str::to_string)).collect())
        .unwrap_or_default();
    report.push(&Record::Cmdline { console });
    let active = std::fs::read_to_string(env.root.sys.join("class/tty/console/active")).unwrap_or_default();
    report.push(&Record::ActiveConsole { ttys: active.split_whitespace().map(str::to_string).collect() });

    match std::fs::read_to_string(env.root.proc.join("tty/driver/serial")) {
        Ok(text) => text.lines().filter_map(parse_port).for_each(|r| report.push(&r)),
        Err(e) => report.unreadable([Unreadable::new("proc/tty/driver/serial", &e)]),
    }

    let tty_dir = env.root.sys.join("class/tty");
    let mut names: Vec<String> = std::fs::read_dir(&tty_dir)
        .map(|rd| rd.filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned())).collect())
        .unwrap_or_default();
    names.retain(|n| n.starts_with("ttyS"));
    names.sort();
    for tty in names {
        let dir = tty_dir.join(&tty);
        let Ok(link) = std::fs::read_link(dir.join("device")) else { continue };
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).ok().map(|s| s.trim().to_string());
        report.push(&Record::Sysfs {
            pci: link.components().filter_map(|c| c.as_os_str().to_str()).find(|c| is_pci_address(c)).map(str::to_string),
            port: read("port"),
            irq: read("irq"),
            kind: read("type"),
            tty,
        });
    }

    for pid in task::pids_with_comm(&env.root, "agetty")?.into_iter().chain(task::pids_with_comm(&env.root, "getty")?) {
        let args = task::cmdline(&env.root, pid).unwrap_or_default();
        report.push(&Record::Getty {
            pid,
            tty: args.iter().find(|a| a.starts_with("ttyS") || a.starts_with("ttyUSB") || a.starts_with("ttyAMA")).cloned(),
            cmdline: args.join(" "),
        });
    }
    finish(env, &mut report);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_lines() {
        let Some(Record::Port { tty_s, uart, irq, tx, modem_lines, errors, .. }) =
            parse_port("1: uart:16550A port:000002F8 irq:3 tx:5 rx:12 fe:1 RTS|CTS")
        else {
            panic!("not a port")
        };
        assert_eq!((tty_s, uart.as_str(), irq, tx), (1, "16550A", Some(3), Some(5)));
        assert_eq!(modem_lines, ["RTS", "CTS"]);
        assert_eq!(errors["fe"], 1);
        assert!(parse_port("2: uart:unknown port:00000000 irq:0").is_none());
        assert!(parse_port("serinfo:1.0 driver revision:").is_none());
    }
}
