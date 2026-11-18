//! `clock`: who disciplines `CLOCK_REALTIME`.

use std::collections::BTreeMap;
use std::time::Duration;

use p_roc::{Unreadable, task};
use serde::Serialize;

use crate::env::Env;
use crate::error::Error;
use crate::observe::finish;
use crate::report::{Cost, Finding, Metric, Report, Severity, Subject};

/// Services that may steer `CLOCK_REALTIME`, by process name.
const DISCIPLINING: [&str; 4] = ["chronyd", "systemd-timesyn", "ntpd", "phc2sys"];
/// Other time services worth listing.
const OTHER: [&str; 1] = ["ptp4l"];
const CHRONYC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    ChronyTracking {
        fields: BTreeMap<String, String>,
    },
    ChronySource {
        state: String,
        source: String,
        stratum: String,
        poll: String,
        reach: String,
        last_rx: String,
        offset: String,
    },
    Service {
        name: String,
        disciplines_realtime: bool,
        pids: Vec<i32>,
        cmdlines: Vec<String>,
    },
    PtpClock {
        name: String,
        device: bool,
        clock_name: Option<String>,
    },
    Summary {
        disciplining: Vec<String>,
        conflict: bool,
    },
}

/// `Reference ID    : A9FEA97B (x)` to `("reference_id", "A9FEA97B (x)")`.
fn parse_tracking(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let key: String = k.trim().to_ascii_lowercase().replace([' ', '-'], "_").replace(['(', ')'], "");
            Some((key, v.trim().to_string()))
        })
        .collect()
}

fn parse_sources(text: &str) -> Vec<Record> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let first = f.first()?;
            (f.len() >= 8 && first.len() == 2 && first.starts_with(['^', '=', '#'])).then(|| Record::ChronySource {
                state: (*first).into(),
                source: f[1].into(),
                stratum: f[2].into(),
                poll: f[3].into(),
                reach: f[4].into(),
                last_rx: f[5].into(),
                offset: f[6..].join(" "),
            })
        })
        .collect()
}

/// Runs `clock`.
///
/// # Errors
/// When the process list cannot be read.
pub fn run(env: &Env) -> Result<Report, Error> {
    let mut report = Report::new(env, "clock", Cost::Light);

    match env.runner.run("chronyc", &["tracking"], CHRONYC_TIMEOUT) {
        Ok(o) if o.code == Some(0) => {
            report.push(&Record::ChronyTracking { fields: parse_tracking(&o.stdout) });
            match env.runner.run("chronyc", &["-n", "sources"], CHRONYC_TIMEOUT) {
                Ok(s) => parse_sources(&s.stdout).iter().for_each(|r| report.push(r)),
                Err(e) => report.unreadable([Unreadable::new("chronyc sources", &e)]),
            }
        }
        Ok(o) => {
            report.unreadable([Unreadable { source: "chronyc tracking".into(), reason: o.stderr.trim().to_string() }])
        }
        Err(e) => report.unreadable([Unreadable::new("chronyc", &e)]),
    }

    let mut disciplining = Vec::new();
    for (name, steers) in DISCIPLINING.iter().map(|n| (*n, true)).chain(OTHER.iter().map(|n| (*n, false))) {
        let pids = task::pids_with_comm(&env.root, name)?;
        if pids.is_empty() {
            continue;
        }
        let shown = if name == "systemd-timesyn" { "systemd-timesyncd" } else { name };
        if steers {
            disciplining.push(shown.to_string());
        }
        report.push(&Record::Service {
            name: shown.into(),
            disciplines_realtime: steers,
            cmdlines: pids.iter().filter_map(|p| task::cmdline(&env.root, *p)).map(|c| c.join(" ")).collect(),
            pids,
        });
    }

    let ptp = env.root.sys.join("class/ptp");
    let mut clocks: Vec<String> = std::fs::read_dir(&ptp)
        .map(|rd| rd.filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned())).collect())
        .unwrap_or_default();
    clocks.sort();
    for c in clocks {
        report.push(&Record::PtpClock {
            device: env.root.dev.join(&c).exists(),
            clock_name: std::fs::read_to_string(ptp.join(&c).join("clock_name")).ok().map(|s| s.trim().to_string()),
            name: c,
        });
    }

    let conflict = disciplining.len() > 1;
    if conflict {
        report.findings.push(Finding {
            id: "two-clock-masters",
            severity: Severity::Warn,
            subject: Subject::Host,
            evidence: vec![Metric::new("disciplining", &disciplining)],
            recommendation:
                "two services steer CLOCK_REALTIME at once and fight each other; one of them must be the only writer"
                    .into(),
            changes: Vec::new(),
        });
    }
    report.push(&Record::Summary { disciplining, conflict });
    finish(env, &mut report);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracking_and_sources() {
        let t = parse_tracking(
            "Reference ID    : A9FEA97B (169.254.169.123)\nStratum         : 4\nSystem time     : 0.000012 seconds fast of NTP time\n",
        );
        assert_eq!(t["reference_id"], "A9FEA97B (169.254.169.123)");
        assert_eq!(t["stratum"], "4");
        let s = parse_sources(
            "MS Name/IP address         Stratum Poll Reach LastRx Last sample\n===\n^* 10.0.0.1  2   6   377    33  +12us[  +15us] +/-  1ms\n",
        );
        assert_eq!(s.len(), 1);
    }
}
