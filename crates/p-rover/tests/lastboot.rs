mod common;

use common::{Host, golden};
use p_rover::observe::lastboot::{self, Args, PATTERN};
use p_rover::runner::Scripted;

fn journal(boot: &str) -> (String, String, String) {
    (
        "journalctl --list-boots --no-pager".into(),
        format!("journalctl -b {boot} -k --no-pager -o short-iso --grep {PATTERN} -n 120"),
        format!("journalctl -b {boot} --no-pager -o short-iso -n 40"),
    )
}

const BOOTS: &str = "-1 aaaa Tue 2026-11-03 08:00:00 UTC—Wed 2026-11-04 09:10:00 UTC\n 0 bbbb Wed 2026-11-04 09:12:00 UTC—Wed 2026-11-04 12:00:00 UTC\n";

#[test]
fn a_stalled_boot_that_ends_abruptly() {
    let host = Host::new("host1");
    let (a, b, c) = journal("-1");
    let mut env = host.env(|_| {});
    env.runner = Box::new(
        Scripted::default()
            .answer(&a, BOOTS)
            .answer(&b, "2026-11-04T09:05:00+0000 h kernel: rcu: INFO: rcu_sched self-detected stall on CPU\n2026-11-04T09:05:01+0000 h kernel: watchdog: Enabled. Permanently consumes one hw-PMU counter.\n")
            .answer(&c, "2026-11-04T09:09:59+0000 h kernel: eth0: link up\n"),
    );
    let report = lastboot::run(&env, &Args::default()).unwrap();
    golden("lastboot", &report);
    let ids: Vec<_> = report.findings.iter().map(|f| (f.id, f.severity)).collect();
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert!(report.findings.iter().any(|f| f.id == "freeze-signature" && f.severity == p_rover::Severity::Crit));
    assert!(report.findings.iter().any(|f| f.id == "unclean-shutdown"));
    assert_eq!(report.exit_code(), 2);
}

#[test]
fn an_orderly_quiet_boot_has_no_findings() {
    let host = Host::new("host1");
    let (a, b, c) = journal("-1");
    let mut env = host.env(|_| {});
    env.runner = Box::new(
        Scripted::default()
            .answer(&a, BOOTS)
            .fail(&b, 1, "")
            .answer(&c, "2026-11-04T09:09:59+0000 h systemd[1]: Reached target Reboot.\n"),
    );
    let report = lastboot::run(&env, &Args::default()).unwrap();
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(report.unreadable.is_empty(), "{:?}", report.unreadable);
}

#[test]
fn no_journalctl_or_no_persistent_journal_is_unreadable_not_a_verdict() {
    let host = Host::new("host1");
    let report = lastboot::run(&host.env(|_| {}), &Args::default()).unwrap();
    assert!(report.findings.is_empty());
    assert!(report.unreadable.iter().any(|u| u.source == "journalctl"));
    let (a, b, c) = journal("-1");
    let mut env = host.env(|_| {});
    env.runner = Box::new(
        Scripted::default()
            .answer(&a, "")
            .fail(&b, 1, "Specifying boot ID has no effect, no persistent journal was found.")
            .fail(&c, 1, "no persistent journal"),
    );
    let report = lastboot::run(&env, &Args::default()).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.unreadable.len(), 2);
}

#[test]
fn boot_offsets_are_checked() {
    let host = Host::new("host1");
    for bad in ["", "x", "-", "1;rm", "--1"] {
        let err = lastboot::run(&host.env(|_| {}), &Args { boot: bad.into() }).unwrap_err();
        assert_eq!(err.exit_code(), 4, "{bad:?}");
    }
    assert!(lastboot::run(&host.env(|_| {}), &Args { boot: "0".into() }).is_ok());
}
