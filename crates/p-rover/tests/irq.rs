mod common;

use std::time::Duration;

use common::{Host, golden};
use p_rover::Error;
use p_rover::observe::irq::{self, Args};

fn run_with_delta(host: &Host, args: &Args) -> Result<p_rover::Report, Error> {
    let (live, after) = (host.path("proc/interrupts"), host.path("interrupts.after"));
    irq::run(&host.env(move |_| std::fs::copy(&after, &live).map(|_| ()).unwrap()), args)
}

#[test]
fn irq_flags_moved_isolated_and_drifted_masks() {
    let host = Host::new("host1");
    let report = run_with_delta(&host, &Args::default()).unwrap();
    golden("irq", &report);
    let ids: Vec<_> = report.findings.iter().map(|f| f.id).collect();
    for want in ["irqbalance", "tick-on-isolated", "irq-on-isolated", "irq-mask-drift"] {
        assert!(ids.contains(&want), "{want} in {ids:?}");
    }
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn managed_irq_that_did_not_move_is_not_flagged() {
    let host = Host::new("host1");
    let report = run_with_delta(&host, &Args::default()).unwrap();
    // nvme0q1 (127): effective on isolated CPU 3 but its count never moved.
    let nvme = report.values.iter().find(|r| r["irq"] == 127);
    assert!(nvme.is_none(), "an idle unflagged IRQ is not listed: {nvme:?}");
}

#[test]
fn window_outside_the_limits_is_refused() {
    let host = Host::new("host1");
    for secs in [0, 61] {
        let err = irq::run(&host.env(|_| {}), &Args { duration: Duration::from_secs(secs), top: 5 }).unwrap_err();
        assert_eq!(err.exit_code(), 4, "{secs}");
    }
}
