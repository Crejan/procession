//! The `ethtool` binary behind the [`Ethtool`] trait. `ethtool` is the
//! reference implementation for this data. Each setting is asked with
//! `--json` first (ethtool 6.x) and, where that is refused or not JSON, with
//! the plain text form.
//!
//! **Not yet checked against a capture from a real host.** The text parsers
//! follow the layout `ethtool` documents and the Python verbs rely on; the JSON
//! key names follow ethtool's own option names. See the runbook for the
//! exact commands whose output is still to be collected.

use std::collections::BTreeMap;
use std::time::Duration;

use p_roc::Unreadable;
use serde_json::Value;

use crate::ethtool::{Channels, Coalesce, DriverInfo, Eee, Ethtool, EthtoolData, Ring};
use crate::runner::{RunError, Runner};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Runs `ethtool` through a [`Runner`].
pub struct EthtoolCli {
    runner: Box<dyn Runner>,
}

impl EthtoolCli {
    /// Uses `runner` to start `ethtool`.
    #[must_use]
    pub fn new(runner: Box<dyn Runner>) -> Self {
        Self { runner }
    }
}

/// `key: value` lines to a map (first colon splits; keys trimmed).
fn kv(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

fn num(v: &str) -> Option<u32> {
    v.split_whitespace().next()?.parse().ok()
}

fn onoff(v: &str) -> Option<bool> {
    match v.split_whitespace().next()? {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

/// The settings object of an `ethtool --json` answer: `[ {...} ]` or `{...}`.
fn json_obj(text: &str) -> Option<serde_json::Map<String, Value>> {
    match serde_json::from_str::<Value>(text).ok()? {
        Value::Array(a) => a.into_iter().next()?.as_object().cloned(),
        Value::Object(o) => Some(o),
        _ => None,
    }
}

fn jnum(o: &serde_json::Map<String, Value>, k: &str) -> Option<u32> {
    o.get(k)?.as_u64().and_then(|n| u32::try_from(n).ok())
}

fn jbool(o: &serde_json::Map<String, Value>, k: &str) -> Option<bool> {
    match o.get(k)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => onoff(s),
        Value::Object(f) => f.get("active")?.as_bool(),
        _ => None,
    }
}

/// `-i`: `driver: igb`, `version:`, `firmware-version:`, `bus-info:`.
#[must_use]
pub fn parse_driver(text: &str) -> DriverInfo {
    let m = kv(text);
    let get = |k: &str| m.get(k).filter(|v| !v.is_empty()).cloned();
    DriverInfo {
        driver: get("driver"),
        version: get("version"),
        firmware: get("firmware-version"),
        bus_info: get("bus-info"),
    }
}

/// `-S` as text: `NIC statistics:` then `     name: value`.
#[must_use]
pub fn parse_stats(text: &str) -> BTreeMap<String, u64> {
    kv(text).into_iter().filter_map(|(k, v)| Some((k, v.parse().ok()?))).collect()
}

fn json_stats(o: &serde_json::Map<String, Value>) -> BTreeMap<String, u64> {
    o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_u64()?))).collect()
}

/// `-g` as text: `Pre-set maximums:` and `Current hardware settings:` sections with `RX:` and `TX:`.
#[must_use]
pub fn parse_ring(text: &str) -> Ring {
    let (mut r, mut section) = (Ring::default(), 0);
    for l in text.lines() {
        let (k, v) = l.split_once(':').map_or((l.trim(), ""), |(k, v)| (k.trim(), v.trim()));
        match (k, section) {
            ("Pre-set maximums", _) => section = 1,
            ("Current hardware settings", _) => section = 2,
            ("RX", 1) => r.rx_max = num(v),
            ("TX", 1) => r.tx_max = num(v),
            ("RX", 2) => r.rx = num(v),
            ("TX", 2) => r.tx = num(v),
            _ => {}
        }
    }
    r
}

/// `-c` as text: `Adaptive RX: off  TX: off`, `rx-usecs: 3`, ...
#[must_use]
pub fn parse_coalesce(text: &str) -> Coalesce {
    let mut c = Coalesce::default();
    for l in text.lines() {
        if let Some(rest) = l.trim().strip_prefix("Adaptive RX:") {
            let (rx, tx) = rest.split_once("TX:").unwrap_or((rest, ""));
            c.adaptive_rx = onoff(rx);
            c.adaptive_tx = onoff(tx);
        }
    }
    let m = kv(text);
    c.rx_usecs = m.get("rx-usecs").and_then(|v| num(v));
    c.rx_frames = m.get("rx-frames").and_then(|v| num(v));
    c.tx_usecs = m.get("tx-usecs").and_then(|v| num(v));
    c.tx_frames = m.get("tx-frames").and_then(|v| num(v));
    c
}

/// `-l` as text: like `-g`, with `Combined:` (and `RX:`/`TX:`/`Other:`).
#[must_use]
pub fn parse_channels(text: &str) -> Channels {
    let (mut c, mut section) = (Channels::default(), 0);
    for l in text.lines() {
        let (k, v) = l.split_once(':').map_or((l.trim(), ""), |(k, v)| (k.trim(), v.trim()));
        match (k, section) {
            ("Pre-set maximums", _) => section = 1,
            ("Current hardware settings", _) => section = 2,
            ("Combined", 1) => c.max_combined = num(v),
            ("Combined", 2) => c.combined = num(v),
            ("RX", 2) => c.rx = num(v),
            ("TX", 2) => c.tx = num(v),
            _ => {}
        }
    }
    c
}

/// `--show-eee` as text: `EEE status: disabled` / `enabled - active` / `enabled - inactive`.
#[must_use]
pub fn parse_eee(text: &str) -> Option<Eee> {
    let status = kv(text).remove("EEE status")?;
    Some(Eee { enabled: status.starts_with("enabled"), active: status.contains("- active") })
}

/// `-k` as text: `generic-receive-offload: on [fixed]`.
#[must_use]
pub fn parse_features(text: &str) -> BTreeMap<String, bool> {
    kv(text).into_iter().filter_map(|(k, v)| Some((k, onoff(&v)?))).collect()
}

impl EthtoolCli {
    /// Runs `ethtool <args> iface`; `Ok(stdout)` on success, else why not.
    fn ask(&self, iface: &str, args: &[&str]) -> Result<String, Unreadable> {
        let mut a: Vec<&str> = args.to_vec();
        a.push(iface);
        let what = format!("ethtool {}", a.join(" "));
        match self.runner.run("ethtool", &a, TIMEOUT) {
            Ok(o) if o.code == Some(0) => Ok(o.stdout),
            Ok(o) => {
                let why = o.stderr.lines().next().unwrap_or("failed").trim().to_string();
                Err(Unreadable {
                    source: what,
                    reason: if why.is_empty() { format!("exit {:?}", o.code) } else { why },
                })
            }
            Err(RunError::NotFound(_)) => Err(Unreadable { source: "ethtool".into(), reason: "not installed".into() }),
            Err(e) => Err(Unreadable::new(what, &e)),
        }
    }

    /// `--json` first, text when that is refused or not JSON.
    fn both<T>(
        &self,
        iface: &str,
        opt: &str,
        from_json: impl Fn(&serde_json::Map<String, Value>) -> Option<T>,
        from_text: impl Fn(&str) -> Option<T>,
        bad: &mut Vec<Unreadable>,
    ) -> Option<T> {
        if let Some(v) = self.ask(iface, &["--json", opt]).ok().and_then(|t| json_obj(&t)).and_then(|o| from_json(&o)) {
            return Some(v);
        }
        match self.ask(iface, &[opt]) {
            Ok(t) => from_text(&t),
            Err(u) => {
                bad.push(u);
                None
            }
        }
    }
}

impl Ethtool for EthtoolCli {
    fn query(&self, iface: &str) -> (EthtoolData, Vec<Unreadable>) {
        let mut bad = Vec::new();
        let mut d = EthtoolData::default();
        match self.ask(iface, &["-i"]) {
            Ok(t) => d.driver = Some(parse_driver(&t)),
            // Without the binary nothing else can work: say so once.
            Err(u) if u.source == "ethtool" => return (d, vec![u]),
            Err(u) => bad.push(u),
        }
        d.stats =
            self.both(iface, "-S", |o| Some(json_stats(o)), |t| Some(parse_stats(t)), &mut bad).unwrap_or_default();
        d.ring = self.both(
            iface,
            "-g",
            |o| {
                Some(Ring {
                    rx_max: jnum(o, "rx-max"),
                    rx: jnum(o, "rx"),
                    tx_max: jnum(o, "tx-max"),
                    tx: jnum(o, "tx"),
                })
            },
            |t| Some(parse_ring(t)),
            &mut bad,
        );
        d.coalesce = self.both(
            iface,
            "-c",
            |o| {
                Some(Coalesce {
                    adaptive_rx: jbool(o, "adaptive-rx"),
                    adaptive_tx: jbool(o, "adaptive-tx"),
                    rx_usecs: jnum(o, "rx-usecs"),
                    rx_frames: jnum(o, "rx-frames"),
                    tx_usecs: jnum(o, "tx-usecs"),
                    tx_frames: jnum(o, "tx-frames"),
                })
            },
            |t| Some(parse_coalesce(t)),
            &mut bad,
        );
        d.channels = self.both(
            iface,
            "-l",
            |o| {
                Some(Channels {
                    max_combined: jnum(o, "combined-max"),
                    combined: jnum(o, "combined"),
                    rx: jnum(o, "rx"),
                    tx: jnum(o, "tx"),
                })
            },
            |t| Some(parse_channels(t)),
            &mut bad,
        );
        d.eee = self.both(
            iface,
            "--show-eee",
            |o| Some(Eee { enabled: jbool(o, "enabled")?, active: jbool(o, "active").unwrap_or(false) }),
            parse_eee,
            &mut bad,
        );
        d.features = self
            .both(
                iface,
                "-k",
                |o| Some(o.keys().filter(|k| *k != "ifname").filter_map(|k| Some((k.clone(), jbool(o, k)?))).collect()),
                |t| Some(parse_features(t)),
                &mut bad,
            )
            .unwrap_or_default();
        (d, bad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Scripted;

    // Layouts as ethtool documents them; NOT captured from a real host.
    const RING: &str = "Ring parameters for eth0:\nPre-set maximums:\nRX:\t\t4096\nRX Mini:\t0\nTX:\t\t4096\nCurrent hardware settings:\nRX:\t\t256\nRX Mini:\t0\nTX:\t\t256\n";
    const COAL: &str = "Coalesce parameters for eth0:\nAdaptive RX: off  TX: off\nstats-block-usecs: 0\nrx-usecs: 3\nrx-frames: 0\ntx-usecs: 0\ntx-frames: 0\n";
    const CHAN: &str = "Channel parameters for eth0:\nPre-set maximums:\nRX:\t\t0\nTX:\t\t0\nOther:\t\t1\nCombined:\t4\nCurrent hardware settings:\nRX:\t\t0\nTX:\t\t0\nOther:\t\t1\nCombined:\t2\n";

    #[test]
    fn text_layouts() {
        let r = parse_ring(RING);
        assert_eq!((r.rx_max, r.rx, r.tx_max, r.tx), (Some(4096), Some(256), Some(4096), Some(256)));
        let c = parse_coalesce(COAL);
        assert_eq!(
            (c.adaptive_rx, c.adaptive_tx, c.rx_usecs, c.rx_frames),
            (Some(false), Some(false), Some(3), Some(0))
        );
        let h = parse_channels(CHAN);
        assert_eq!((h.max_combined, h.combined), (Some(4), Some(2)));
        assert_eq!(
            parse_eee("EEE settings for eth0:\n\tEEE status: enabled - active\n"),
            Some(Eee { enabled: true, active: true })
        );
        assert_eq!(parse_eee("EEE settings for eth0:\n\tEEE status: disabled\n").map(|e| e.enabled), Some(false));
        assert!(parse_eee("Cannot get EEE settings: Operation not supported\n").is_none());
        let f = parse_features(
            "Features for eth0:\ngeneric-receive-offload: on\nlarge-receive-offload: off [fixed]\nodd: maybe\n",
        );
        assert_eq!(f.len(), 2);
        assert!(f["generic-receive-offload"] && !f["large-receive-offload"]);
        assert_eq!(
            parse_driver("driver: igb\nversion: 6.8\nfirmware-version: 1.63\nbus-info: 0000:04:00.0\n")
                .bus_info
                .as_deref(),
            Some("0000:04:00.0")
        );
        assert_eq!(parse_stats("NIC statistics:\n     rx_packets: 5\n     name: x\n")["rx_packets"], 5);
    }

    #[test]
    fn json_first_then_text_and_absence_is_unavailable() {
        let s = Scripted::default()
            .answer("ethtool -i lan0", "driver: igb\n")
            .answer("ethtool --json -g lan0", r#"[{"ifname":"lan0","rx-max":4096,"rx":256,"tx-max":4096,"tx":256}]"#)
            .fail("ethtool --json -c lan0", 1, "unrecognized option '--json'")
            .answer("ethtool -c lan0", COAL)
            .fail("ethtool --json --show-eee lan0", 1, "x")
            .fail("ethtool --show-eee lan0", 94, "Cannot get EEE settings: Operation not supported");
        let (d, bad) = EthtoolCli::new(Box::new(s)).query("lan0");
        assert_eq!(d.ring.unwrap().rx, Some(256));
        assert_eq!(d.coalesce.unwrap().rx_usecs, Some(3));
        assert!(d.eee.is_none());
        assert!(
            bad.iter().any(|u| u.source.contains("--show-eee") && u.reason.contains("Operation not supported")),
            "{bad:?}"
        );
        // No binary at all: one entry, nothing else.
        let (d, bad) = EthtoolCli::new(Box::new(Scripted::default())).query("lan0");
        assert_eq!(d, EthtoolData::default());
        assert_eq!(bad, vec![Unreadable { source: "ethtool".into(), reason: "not installed".into() }]);
    }
}
