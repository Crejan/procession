//! The rule for strings from outside, end to end: a host whose names, command lines and tool output
//! carry C1 controls (U+0085, U+009B), a bidirectional mark (U+202E), ESC and bytes that are not UTF-8
//! goes through every subcommand, in text and in JSON. Nothing the rule refuses may come out raw.

mod common;

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

use common::Host;
use p_rover::ethtool::{DriverInfo, EthtoolData, Fixed};
use p_rover::observe::{clock, cmdline, hung, irq, lastboot, nic, procs, sched, serial};
use p_rover::runner::Scripted;
use p_rover::{Report, analyze, render};

use p_ermit::probe::{assert_clean_in, is_dirty};

/// Every probe (C1 NEL and CSI, RLO, ESC) in one string, and DEL.
const BAD: &str = "a\u{85}b\u{9b}c\u{202e}d\u{1b}e\u{7f}";

/// One function for every output: no refused character in the text, in the JSON text, nor in any
/// string of the parsed JSON (so that a parser cannot turn an escape back into the character).
fn assert_clean(what: &str, r: &Report) {
    let json = serde_json::to_string_pretty(r).unwrap();
    let text = render::text(r);
    for (kind, out) in [("json", &json), ("text", &text)] {
        out.lines().for_each(|l| assert_clean_in(&format!("{what} {kind}"), l));
    }
    fn walk(v: &serde_json::Value, what: &str) {
        match v {
            serde_json::Value::String(s) => {
                assert!(!is_dirty(s), "{what}: parsed string holds a refused character: {s:?}")
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, what)),
            serde_json::Value::Object(o) => o.iter().for_each(|(k, x)| {
                assert!(!is_dirty(k), "{what}: key {k:?}");
                walk(x, what);
            }),
            _ => {}
        }
    }
    walk(&serde_json::from_str(&json).unwrap(), what);
}

fn put(host: &Host, rel: &str, bytes: &[u8]) {
    let p = host.path(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

fn hostile3() -> Host {
    let host = Host::new("host3");
    // comm of thread 10 (RT, on an isolated CPU): bad characters; thread 13: a byte that is not UTF-8.
    let stat10 = fs::read_to_string(host.path("proc/10/task/10/stat")).unwrap().replace("cyclic (app)", BAD);
    put(&host, "proc/10/task/10/stat", stat10.as_bytes());
    let mut stat13 = b"13 (poll\xffer) S 1".to_vec();
    stat13.extend_from_slice(
        fs::read_to_string(host.path("proc/13/task/13/stat")).unwrap().split_once(") S 1").unwrap().1.as_bytes(),
    );
    put(&host, "proc/13/task/13/stat", &stat13);
    // command lines of other users' processes
    put(&host, "proc/30/cmdline", format!("/usr/sbin/chronyd\0{BAD}\0").as_bytes());
    put(&host, "proc/40/cmdline", format!("/sbin/agetty\0{BAD}\0ttyS0\0").as_bytes());
    // the live command line and a sysctl value
    let cmd = fs::read_to_string(host.path("proc/cmdline")).unwrap();
    put(&host, "proc/cmdline", format!("{} bad={BAD}\n", cmd.trim_end()).as_bytes());
    put(&host, "proc/sys/kernel/watchdog_cpumask", BAD.as_bytes());
    put(
        &host,
        "etc/default/grub.d/60-bad.cfg",
        format!("GRUB_CMDLINE_LINUX=\"$GRUB_CMDLINE_LINUX bad={BAD}\"\n").as_bytes(),
    );
    // an IRQ name and an interface name
    let irqs = fs::read_to_string(host.path("proc/interrupts")).unwrap().replace("lan0-TxRx-0", &format!("lan0-{BAD}"));
    put(&host, "proc/interrupts", irqs.as_bytes());
    let after =
        fs::read_to_string(host.path("interrupts.after")).unwrap().replace("lan0-TxRx-0", &format!("lan0-{BAD}"));
    put(&host, "interrupts.after", after.as_bytes());
    for (f, v) in [("ifindex", "9\n"), ("operstate", "down\n")] {
        put(&host, &format!("sys/class/net/lan{BAD}/{f}"), v.as_bytes());
    }
    put(&host, "sys/class/tty/ttyS0/type", BAD.as_bytes());
    host
}

fn hostile_env(host: &Host) -> p_rover::Env {
    let root = host.dir.path().to_path_buf();
    let mut env = host.env(move |_| {
        let _ = fs::copy(root.join("interrupts.after"), root.join("proc/interrupts"));
    });
    env.ethtool = Box::new(Fixed::with(
        "lan0",
        EthtoolData {
            driver: Some(DriverInfo { driver: Some(format!("igb{BAD}")), ..DriverInfo::default() }),
            ..EthtoolData::default()
        },
    ));
    env.runner = Box::new(
        Scripted::default()
            .answer("chronyc tracking", &format!("Reference ID    : {BAD}\nStratum         : 3\n"))
            .answer("chronyc -n sources", &format!("MS Name/IP address Stratum Poll Reach LastRx Last sample\n^* {BAD} 2 6 377 33 +12us[ +15us] +/- 1ms\n"))
            .answer("journalctl --list-boots --no-pager", &format!("-1 {BAD} Tue\n"))
            .answer(
                &format!("journalctl -b -1 -k --no-pager -o short-iso --grep {} -n 120", lastboot::PATTERN),
                &format!("h kernel: rcu: INFO: stall {BAD}\n"),
            )
            .answer("journalctl -b -1 --no-pager -o short-iso -n 40", &format!("h kernel: last {BAD}\n")),
    );
    env
}

#[test]
fn nothing_the_rule_refuses_comes_out_raw_from_any_subcommand() {
    // A fresh host per subcommand: a sampling pause rewrites /proc/interrupts.
    let hs: Vec<Host> = (0..9).map(|_| hostile3()).collect();
    let d = Duration::from_secs(1);
    let reports: Vec<(&str, Report)> = vec![
        ("procs", procs::run(&hostile_env(&hs[0]), &procs::Args::default()).unwrap()),
        ("sched", sched::run(&hostile_env(&hs[1]), &sched::Args { duration: d, ..Default::default() }).unwrap()),
        ("irq", irq::run(&hostile_env(&hs[2]), &irq::Args { duration: d, top: 20 }).unwrap()),
        ("cmdline", cmdline::run(&hostile_env(&hs[3])).unwrap()),
        (
            "nic",
            nic::run(&hostile_env(&hs[4]), &nic::Args { iface: "lan0".into(), delta: None, all_stats: false }).unwrap(),
        ),
        ("serial", serial::run(&hostile_env(&hs[5])).unwrap()),
        ("clock", clock::run(&hostile_env(&hs[6])).unwrap()),
        ("lastboot", lastboot::run(&hostile_env(&hs[7]), &lastboot::Args::default()).unwrap()),
        (
            "analyze",
            analyze::run(&hostile_env(&hs[8]), &analyze::Args { pid: 100, tids: vec![], static_only: true }).unwrap(),
        ),
    ];
    for (name, r) in &reports {
        assert_clean(name, r);
    }
    let escaped = |n: &str| reports.iter().find(|(x, _)| *x == n).unwrap().1.escaped_records;
    for n in ["procs", "sched", "cmdline", "serial", "clock", "lastboot", "analyze", "irq", "nic"] {
        assert!(escaped(n) > 0, "{n} saw bad strings but flagged none");
    }
}

#[test]
fn the_flag_names_the_record_and_the_odd_name_is_a_finding() {
    let host = hostile3();
    let r = procs::run(&hostile_env(&host), &procs::Args::default()).unwrap();
    let t = r.values.iter().find(|v| v["tid"] == 10).unwrap();
    assert_eq!(t["escaped"], true);
    assert!(t["comm"].as_str().unwrap().contains("\\u{202e}"), "{t}");
    let clean = r.values.iter().find(|v| v["tid"] == 11).unwrap();
    assert!(clean.get("escaped").is_none(), "absent, never false");
    assert!(r.findings.iter().any(|f| f.id == "odd-characters"));
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"escaped\":true") && r.escaped_records >= 2, "{}", r.escaped_records);
    // A byte that is not UTF-8 shows as hex and does not make the thread unreadable.
    let t13 = r.values.iter().find(|v| v["tid"] == 13).expect("thread 13 is listed");
    assert!(t13["comm"].as_str().unwrap().contains("\\x{ff}"), "{t13}");
}

#[test]
fn long_fields_are_cut_and_say_so() {
    let host = Host::new("host3");
    let long = "a".repeat(500);
    let stat = fs::read_to_string(host.path("proc/10/task/10/stat")).unwrap().replace("cyclic (app)", &long);
    put(&host, "proc/10/task/10/stat", stat.as_bytes());
    let r = procs::run(&host.env(|_| {}), &procs::Args::default()).unwrap();
    let t = r.values.iter().find(|v| v["tid"] == 10).unwrap();
    assert_eq!(t["comm"].as_str().unwrap().len(), 64);
    assert_eq!(t["clipped"]["comm"], 500);
    assert_eq!(r.clipped_records, 2, "the record and the finding that names the thread");
}

#[test]
fn hung_exe_wchan_and_stack_are_clean_too() {
    let host = Host::new("host2");
    let stat = fs::read_to_string(host.path("proc/50/task/50/stat")).unwrap().replace("rsync", BAD);
    put(&host, "proc/50/task/50/stat", stat.as_bytes());
    put(&host, "proc/50/task/50/wchan", format!("rpc_wait_bit_killable{BAD}").as_bytes());
    put(&host, "proc/50/task/50/stack", format!("[<0>] rpc_wait_bit_killable+0x24 {BAD}\n").as_bytes());
    fs::remove_file(host.path("proc/50/exe")).unwrap();
    std::os::unix::fs::symlink(format!("/usr/bin/{BAD}"), host.path("proc/50/exe")).unwrap();
    let r = hung::run(&host.env(|_| {}), &hung::Args::default()).unwrap();
    assert_clean("hung", &r);
    assert!(r.escaped_records > 0);
}

#[test]
fn a_tool_error_line_in_unreadable_is_escaped_and_bounded() {
    let host = Host::new("host3");
    let mut env = host.env(|_| {});
    let noisy = format!("{BAD}{}", "e".repeat(2000));
    env.runner = Box::new(Scripted::default().fail("ethtool -i lan0", 1, &noisy));
    env.ethtool = Box::new(p_rover::ethtool_cli::EthtoolCli::new(std::mem::replace(
        &mut env.runner,
        Box::new(Scripted::default()),
    )));
    let r = nic::run(&env, &nic::Args { iface: "lan0".into(), delta: None, all_stats: false }).unwrap();
    assert_clean("nic stderr", &r);
    let u = r.unreadable.iter().find(|u| u.source.contains("ethtool -i")).unwrap();
    assert!(u.reason.chars().count() <= 512, "{}", u.reason.chars().count());
    assert!(u.reason.contains("\\u{202e}"));
}

#[test]
fn a_real_private_use_character_and_an_invalid_byte_never_show_alike() {
    // U+10F7FF is what the byte 0xff would look like to a naive stand-in scheme.
    let comms: [&[u8]; 2] = [&[b'q', 0xf4, 0x8f, 0x9f, 0xbf], &[b'q', 0xff]];
    let mut shown = Vec::new();
    for comm in comms {
        let host = Host::new("host3");
        let stat = fs::read(host.path("proc/10/task/10/stat")).unwrap();
        let head = b"10 (";
        let tail = &stat[stat.windows(2).position(|w| w == b") ").unwrap()..];
        put(&host, "proc/10/task/10/stat", &[head.as_slice(), comm, tail].concat());
        let r = procs::run(&host.env(|_| {}), &procs::Args::default()).unwrap();
        let t = r.values.iter().find(|v| v["tid"] == 10).expect("thread 10 is listed");
        let text = t["comm"].as_str().unwrap().to_string();
        assert_eq!(p_ermit::text::unescape_bytes(&text).unwrap(), comm, "each output stands for its own bytes");
        shown.push(text);
    }
    assert_ne!(shown[0], shown[1], "two different byte strings showed alike");
    assert!(shown[1].contains("\\x{ff}") || shown[1].contains("\\x{ff}"), "{shown:?}");
}

// --- The internal markers of p_roc::text never reach an output -----------------------------------

use p_roc::text::{BYTE_BASE, ESC, stands_for_byte};

/// A genuine U+10FFFF, a genuine character of the stand-in range, and an invalid byte, between letters.
fn marker_bytes() -> Vec<u8> {
    let mut v = "A\u{10FFFF}B\u{10F7FF}C".as_bytes().to_vec();
    v.push(0xff);
    v.push(b'D');
    v
}

/// No internal form in `out`: no doubled ESC, no ESC followed by a stand-in, and every ESC in it is
/// the genuine one of a marker string (so each is followed by `B`).
fn assert_no_internal(what: &str, out: &str) {
    let chars: Vec<char> = out.chars().collect();
    for (i, c) in chars.iter().enumerate().filter(|(_, c)| **c == ESC) {
        let _ = c;
        let next = chars.get(i + 1).copied();
        assert!(next != Some(ESC), "{what}: a doubled ESC (internal form) reached the output");
        assert!(
            next.is_none_or(|n| stands_for_byte(n).is_none()),
            "{what}: an encoded invalid byte (internal form) reached the output"
        );
        assert_eq!(next, Some('B'), "{what}: a marker ESC that is not the genuine one");
    }
    let _ = BYTE_BASE;
    assert_eq!(chars.iter().filter(|c| **c == ESC).count(), out.matches("A\u{10FFFF}B").count(), "{what}");
}

fn assert_no_internal_report(what: &str, r: &Report) {
    let json = serde_json::to_string_pretty(r).unwrap();
    assert_no_internal(&format!("{what} json"), &json);
    assert_no_internal(&format!("{what} text"), &render::text(r));
    // The invalid byte is shown as its escape wherever the marker string is shown.
    for out in [&json, &render::text(r)] {
        assert_eq!(
            out.matches("C\\\\x{ff}D").count() + out.matches("C\\x{ff}D").count(),
            out.matches("A\u{10FFFF}B").count(),
            "{what}"
        );
    }
}

/// `hostile3` with the probes replaced, in every file, by the marker string.
fn marked3() -> Host {
    let host = hostile3();
    fn walk(dir: &std::path::Path) {
        for e in fs::read_dir(dir).unwrap().filter_map(Result::ok) {
            let kind = e.file_type().unwrap();
            if kind.is_dir() {
                walk(&e.path());
            } else if kind.is_file() {
                let b = fs::read(e.path()).unwrap();
                let from = BAD.as_bytes();
                if b.windows(from.len()).any(|w| w == from) {
                    let mut out = Vec::new();
                    let mut i = 0;
                    while i < b.len() {
                        if b[i..].starts_with(from) {
                            out.extend(marker_bytes());
                            i += from.len();
                        } else {
                            out.push(b[i]);
                            i += 1;
                        }
                    }
                    fs::write(e.path(), out).unwrap();
                }
            }
        }
    }
    walk(host.dir.path());
    host
}

#[test]
fn the_internal_markers_never_reach_any_prover_output() {
    let hs: Vec<Host> = (0..9).map(|_| marked3()).collect();
    let d = Duration::from_secs(1);
    let env = |i: usize| {
        let mut e = hostile_env(&hs[i]);
        // the scripted tool outputs carry the markers too
        let m = p_roc::text::from_bytes(&marker_bytes()); // what the runner hands over for such bytes
        e.runner = Box::new(
            Scripted::default()
                .answer("chronyc tracking", &format!("Reference ID    : {m}\nStratum         : 3\n"))
                .answer("journalctl --list-boots --no-pager", &format!("-1 {m} Tue\n"))
                .answer(
                    &format!("journalctl -b -1 -k --no-pager -o short-iso --grep {} -n 120", lastboot::PATTERN),
                    &format!("h kernel: rcu: INFO: stall {m}\n"),
                )
                .answer("journalctl -b -1 --no-pager -o short-iso -n 40", &format!("h kernel: last {m}\n")),
        );
        e
    };
    let reports: Vec<(&str, Report)> = vec![
        ("procs", procs::run(&env(0), &procs::Args::default()).unwrap()),
        ("sched", sched::run(&env(1), &sched::Args { duration: d, ..Default::default() }).unwrap()),
        ("irq", irq::run(&env(2), &irq::Args { duration: d, top: 20 }).unwrap()),
        ("cmdline", cmdline::run(&env(3)).unwrap()),
        ("nic", nic::run(&env(4), &nic::Args { iface: "lan0".into(), delta: None, all_stats: false }).unwrap()),
        ("serial", serial::run(&env(5)).unwrap()),
        ("clock", clock::run(&env(6)).unwrap()),
        ("lastboot", lastboot::run(&env(7), &lastboot::Args::default()).unwrap()),
        ("analyze", analyze::run(&env(8), &analyze::Args { pid: 100, tids: vec![], static_only: true }).unwrap()),
    ];
    for (name, r) in &reports {
        assert_no_internal_report(name, r);
    }
    // hung, with the markers in the thread name, wait channel, stack and exe link
    let host = Host::new("host2");
    let m = marker_bytes();
    let stat = fs::read(host.path("proc/50/task/50/stat")).unwrap();
    let from = b"(rsync)";
    let at = stat.windows(from.len()).position(|w| w == from).unwrap();
    put(&host, "proc/50/task/50/stat", &[&stat[..at + 1], &m, &stat[at + from.len() - 1..]].concat());
    put(&host, "proc/50/task/50/wchan", &[b"rpc_wait_bit_killable".as_slice(), &m].concat());
    put(&host, "proc/50/task/50/stack", &[b"[<0>] rpc_wait_bit_killable+0x24 ".as_slice(), &m, b"\n"].concat());
    fs::remove_file(host.path("proc/50/exe")).unwrap();
    std::os::unix::fs::symlink(
        std::ffi::OsStr::from_bytes(&[b"/usr/bin/".as_slice(), &m].concat()),
        host.path("proc/50/exe"),
    )
    .unwrap();
    let r = hung::run(&host.env(|_| {}), &hung::Args::default()).unwrap();
    assert_no_internal_report("hung", &r);
    let seen = serde_json::to_string(&r).unwrap().matches("A\u{10FFFF}B").count();
    assert!(seen >= 3, "the markers were fed to hung: {seen}");
}
