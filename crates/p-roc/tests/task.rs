//! The thread scan and CPU readers against a fixture tree built in a temp dir.

use std::fs;
use std::path::Path;

use p_roc::{Policy, Root, cpus, task};

fn stat_line(pid: i32, comm: &str, policy: u32, prio: u32) -> String {
    // Fields 3..=52 after the comm; field 9 = flags, 40 = rt_priority, 41 = policy.
    let mut f = vec!["0".to_string(); 50];
    f[0] = "S".into();
    f[6] = "0".into(); // field 9
    f[37] = prio.to_string(); // field 40
    f[38] = policy.to_string(); // field 41
    format!("{pid} ({comm}) {}", f.join(" "))
}

fn task_dir(proc: &Path, pid: i32, stat: &str, status: Option<&str>) {
    let d = proc.join(pid.to_string()).join("task").join(pid.to_string());
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("stat"), stat).unwrap();
    if let Some(s) = status {
        fs::write(d.join("status"), s).unwrap();
    }
}

#[test]
fn scan_returns_rt_tasks_and_lists_unreadable_ones() {
    let t = tempfile::tempdir().unwrap();
    let (proc, sys) = (t.path().join("proc"), t.path().join("sys"));
    let status = "Tgid:\t10\nPid:\t10\nUid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\nGroups:\t100 200\nCpus_allowed_list:\t0-3\n";
    task_dir(&proc, 10, &stat_line(10, "rt (loop)", 1, 50), Some(status));
    task_dir(&proc, 11, &stat_line(11, "normal", 0, 0), None); // not RT: status never read
    task_dir(&proc, 12, &stat_line(12, "nostatus", 2, 10), None); // RT but status missing: ENOENT, treated as exited, skipped silently
    task_dir(&proc, 13, "garbage", None);
    fs::create_dir_all(sys.join("devices/system/cpu")).unwrap();
    fs::write(sys.join("devices/system/cpu/online"), "0-7\n").unwrap();
    fs::write(sys.join("devices/system/cpu/isolated"), "\n").unwrap();
    let root = Root::new(&proc, &sys, t.path().join("dev"));

    let scan = task::rt_threads(&root).unwrap();
    assert_eq!(scan.items.len(), 1);
    let th = &scan.items[0];
    assert_eq!((th.tid, th.comm.as_str(), th.policy, th.rt_priority), (10, "rt (loop)", Policy::Fifo, 50));
    assert_eq!(th.groups, vec![100, 200]);
    assert_eq!(th.cpus.to_string(), "0-3");
    let mut bad: Vec<_> = scan.unreadable.iter().map(|u| u.source.as_str()).collect();
    bad.sort_unstable();
    assert_eq!(bad, ["13/13"]);

    assert_eq!(cpus::online(&root).unwrap().to_string(), "0-7");
    assert!(cpus::sysfs_isolated(&root).unwrap().is_empty());
    assert!(cpus::possible(&root).is_err());
}

#[test]
fn a_vanished_task_is_gone() {
    let t = tempfile::tempdir().unwrap();
    let root = Root::new(t.path(), t.path(), t.path());
    assert!(task::read_thread(&root, 1, 1).unwrap_err().is_gone());
}
