mod common;

use std::fs;
use std::time::Duration;

use common::{Host, golden};
use p_roc::CpuSet;
use p_rover::observe::sched::{self, Args};

/// Rewrites a thread's counters as `secs` of activity later: run, wait, slices, voluntary, involuntary, migrations added.
fn bump(host: &std::path::Path, tid: i32, run_ns: u64, wait_ns: u64, slices: u64, vol: u64, invol: u64, migr: u64) {
    let d = host.join(format!("proc/{tid}/task/{tid}"));
    fs::write(d.join("schedstat"), format!("{} {} {}\n", 1_000_000_000 + run_ns, 100_000_000 + wait_ns, 100 + slices)).unwrap();
    fs::write(
        d.join("sched"),
        format!(
            "t ({tid})\nnr_switches : {}\nnr_voluntary_switches : {}\nnr_involuntary_switches : {}\nse.nr_migrations : {}\n",
            1000 + vol + invol,
            900 + vol,
            100 + invol,
            5 + migr
        ),
    )
    .unwrap();
}

fn run(host: &Host, args: &Args) -> p_rover::Report {
    let root = host.dir.path().to_path_buf();
    let env = host.env(move |_| {
        bump(&root, 10, 4_500_000_000, 500_000_000, 5000, 100, 400, 0); // busy FIFO, preempted
        bump(&root, 13, 1_000_000_000, 0, 100_000, 100_000, 0, 2); // micro-sleep poller
        bump(&root, 11, 10_000_000, 0, 10, 10, 0, 0);
        // tid 14 "restarts": counters below the first sample, as a reused tid would show.
        fs::write(root.join("proc/14/task/14/schedstat"), "5 5 1\n").unwrap();
    });
    sched::run(&env, args).unwrap()
}

#[test]
fn sched_rates_flags_and_per_cpu_totals() {
    let host = Host::new("host1");
    let report = run(&host, &Args::default());
    golden("sched", &report);
    let thread = |tid: i64| report.records.iter().find(|r| r["type"] == "thread" && r["tid"] == tid);
    assert_eq!(thread(10).unwrap()["busy"], true);
    assert_eq!(thread(13).unwrap()["polling"], true);
    assert_eq!(thread(11).unwrap()["polling"], false);
    assert!(thread(14).is_none(), "reused tid is dropped");
    let summary = report.records.last().unwrap();
    assert_eq!(summary["polling"], serde_json::json!([13]));
    assert_eq!(summary["sched_debug"], true);
}

#[test]
fn cpus_option_narrows_the_watch_set() {
    let host = Host::new("host1");
    // CPU 0: only threads running or allowed there, plus RT ones.
    let a = Args { cpus: Some("1".parse::<CpuSet>().unwrap()), ..Args::default() };
    let r = run(&host, &a);
    assert_eq!(r.records.last().unwrap()["cpus"], "1");
}

#[test]
fn without_sched_debug_the_report_is_degraded_not_failed() {
    let host = Host::new("host1");
    for tid in [1, 2, 10, 11, 12, 13, 14, 20] {
        fs::remove_file(host.path(&format!("proc/{tid}/task/{tid}/sched"))).unwrap();
    }
    let env = host.env(|_| {});
    let report = sched::run(&env, &Args::default()).unwrap();
    let summary = report.records.last().unwrap();
    assert_eq!(summary["sched_debug"], false);
    assert!(summary["degraded"].as_str().unwrap().contains("CONFIG_SCHED_DEBUG"));
    assert!(report.unreadable.iter().any(|u| u.reason.contains("CONFIG_SCHED_DEBUG")));
    let t = report.records.iter().find(|r| r["type"] == "thread").unwrap();
    assert!(t["migrations_per_s"].is_null());
    assert!(t["voluntary_per_s"].is_number(), "falls back to status counters");
}

#[test]
fn window_limits() {
    let host = Host::new("host1");
    let err = sched::run(&host.env(|_| {}), &Args { duration: Duration::from_secs(120), ..Args::default() }).unwrap_err();
    assert_eq!(err.exit_code(), 4);
}
