mod common;

use std::fs;
use std::time::Duration;

use common::{Host, golden};
use p_rover::observe::hung::{self, Args};

fn run(host: &Host, args: &Args) -> p_rover::Report {
    let root = host.dir.path().to_path_buf();
    let env = host.env(move |_| {
        // 52 was a passing D; 51 got CPU time in between (it is moving, not stuck on a server).
        let d = root.join("proc/52/task/52/stat");
        fs::write(&d, fs::read_to_string(&d).unwrap().replacen(") D ", ") S ", 1)).unwrap();
        fs::write(root.join("proc/51/task/51/schedstat"), "9000 2000 4\n").unwrap();
    });
    hung::run(&env, args).unwrap()
}

#[test]
fn tasks_in_d_across_both_samples_with_class_and_mount() {
    let host = Host::new("host2");
    let report = run(&host, &Args::default());
    golden("hung", &report);
    let tasks: Vec<_> = report.records.iter().filter(|r| r["type"] == "task").collect();
    let tids: Vec<_> = tasks.iter().map(|t| t["tid"].as_i64().unwrap()).collect();
    assert_eq!(tids, [50, 51], "the passing D (52) is not reported");
    assert_eq!(tasks[0]["wait_class"], "nfs_rpc");
    assert_eq!(tasks[0]["mount"], "/home/lab");
    assert_eq!(tasks[0]["d_for_at_least_s"], 2);
    assert_eq!(tasks[1]["wait_class"], "lock");
    assert!(tasks[1]["d_for_at_least_s"].is_null(), "51 ran in between");
    let f = &report.findings[0];
    assert_eq!((f.id, f.severity), ("hung-tasks", p_rover::Severity::Crit)); // 50 waited on the server for the whole window
}

#[test]
fn all_adds_sleepers_waiting_on_nfs() {
    let host = Host::new("host2");
    let report = run(&host, &Args { all: true, ..Args::default() });
    let tids: Vec<_> = report.records.iter().filter(|r| r["type"] == "task").map(|t| t["tid"].as_i64().unwrap()).collect();
    assert_eq!(tids, [50, 51, 53]);
    let summary = report.records.last().unwrap();
    assert_eq!(summary["hung"], 2);
    assert_eq!(summary["nfs_waiters"], 2);
}

#[test]
fn unreadable_stacks_are_reported_and_the_class_falls_back_to_wchan() {
    let host = Host::new("host2");
    fs::remove_file(host.path("proc/50/task/50/stack")).unwrap();
    let report = run(&host, &Args::default());
    assert!(report.unreadable.iter().any(|u| u.source.ends_with("/stack")));
    let t = report.records.iter().find(|r| r["tid"] == 50).unwrap();
    assert_eq!(t["wait_class"], "nfs_rpc");
    assert!(t["samples"][1]["stack"].is_null());
}

#[test]
fn nothing_in_d_is_clean_and_the_cap_is_applied() {
    let host = Host::new("host2");
    let report = run(&host, &Args { max: 1, ..Args::default() });
    assert_eq!(report.records.iter().filter(|r| r["type"] == "task").count(), 1);
    assert_eq!(report.records.last().unwrap()["truncated"], true);
    let quiet = Host::new("host2");
    for pid in [50, 51, 52] {
        let d = quiet.path(&format!("proc/{pid}/task/{pid}/stat"));
        fs::write(&d, fs::read_to_string(&d).unwrap().replacen(") D ", ") S ", 1)).unwrap();
    }
    let r = hung::run(&quiet.env(|_| {}), &Args::default()).unwrap();
    assert!(r.findings.is_empty());
    let err = hung::run(&quiet.env(|_| {}), &Args { duration: Duration::from_secs(0), ..Args::default() }).unwrap_err();
    assert_eq!(err.exit_code(), 4);
}
