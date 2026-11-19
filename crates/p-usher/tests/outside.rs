//! Strings from outside (the README's rule): a thread whose name holds every probe and a byte that
//! is not UTF-8 goes through the engine, the log line, the e-mail and the metrics file; nothing the
//! rule refuses comes out raw.

mod common;

use std::fs;
use std::path::Path;

use common::*;
use p_ermit::probe::{PROBE_ALL, assert_clean_in};
use p_usher::engine::{Engine, describe};
use p_usher::notify::email::render;
use p_usher::notify::prometheus::PrometheusTextfile;
use p_usher::procfs::ProcFs;
use p_usher::{Mode, Notifier};

fn copy(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        let kind = e.file_type().unwrap();
        if kind.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(e.path()).unwrap(), dest).unwrap();
        } else if kind.is_dir() {
            copy(&e.path(), &dest);
        } else {
            fs::copy(e.path(), dest).unwrap();
        }
    }
}

fn lines(what: &str, text: &str) {
    text.lines().for_each(|l| assert_clean_in(what, l));
}

#[test]
fn a_hostile_thread_name_is_escaped_in_the_log_the_mail_and_the_metrics() {
    let d = tempfile::tempdir().unwrap();
    copy(&fixtures().join("proc"), &d.path().join("proc"));
    // tid 101's comm: every probe, DEL, a real backslash and a byte that is not UTF-8.
    let stat = d.path().join("proc/100/task/101/stat");
    let old = fs::read(&stat).unwrap();
    let close = old.windows(2).rposition(|w| w == b") ").unwrap();
    let mut new = b"101 (".to_vec();
    new.extend_from_slice(format!("{PROBE_ALL}\u{7f}\\").as_bytes());
    new.push(0xff);
    new.extend_from_slice(&old[close..]);
    fs::write(&stat, new).unwrap();

    let clock = clock();
    let rec = Recorder::new(false);
    let mut engine = Engine::new(
        settings(Mode::Report),
        env(ProcFs::new(d.path().join("proc"), fixtures().join("sys")), FakeSetter::default(), &clock, vec![Box::new(rec.clone())]),
    );
    let events = engine.tick().unwrap();
    let ev = events.iter().find(|e| e.tid == 101).expect("the hostile thread is dealt with");

    assert_clean_in("comm", &ev.comm);
    assert!(ev.comm.contains("\\u{85}") && ev.comm.contains("\\x{ff}") && ev.comm.contains("\\\\"), "{}", ev.comm);
    lines("log line", &describe(ev));

    let (subject, body) = render(ev, &cpus("2-3"), None);
    assert!(!subject.contains('\n'), "a name must not break the subject header");
    lines("mail subject", &subject);
    lines("mail body", &body);

    let dir = tempfile::tempdir().unwrap();
    let mut prom = PrometheusTextfile::new(dir.path(), std::time::Duration::from_secs(900));
    prom.notify(ev).unwrap();
    lines("metrics", &prom.render());
}

// --- The internal markers of p_roc::text never reach an output -----------------------------------

use p_roc::text::{ESC, stands_for_byte};

/// No internal form in `out`: no doubled ESC, no ESC followed by a stand-in, and every ESC is the
/// genuine one of the marker string (followed by `B`).
fn assert_no_internal(what: &str, out: &str) {
    let chars: Vec<char> = out.chars().collect();
    for (i, _) in chars.iter().enumerate().filter(|(_, c)| **c == ESC) {
        let next = chars.get(i + 1).copied();
        assert!(next != Some(ESC), "{what}: a doubled ESC (internal form) reached the output");
        assert!(next.is_none_or(|n| stands_for_byte(n).is_none()), "{what}: an encoded invalid byte reached the output");
        assert_eq!(next, Some('B'), "{what}: an ESC that is not the genuine one");
    }
    assert_eq!(chars.iter().filter(|c| **c == ESC).count(), out.matches("A\u{10FFFF}B").count(), "{what}");
    assert_eq!(out.matches("C\\x{ff}D").count() + out.matches("C\\\\x{ff}D").count(), out.matches("A\u{10FFFF}B").count(), "{what}: the invalid byte is not shown as its escape");
}

#[test]
fn the_internal_markers_never_reach_the_log_the_mail_or_the_metrics() {
    let d = tempfile::tempdir().unwrap();
    copy(&fixtures().join("proc"), &d.path().join("proc"));
    let stat = d.path().join("proc/100/task/101/stat");
    let old = fs::read(&stat).unwrap();
    let close = old.windows(2).rposition(|w| w == b") ").unwrap();
    // a genuine U+10FFFF, a genuine character of the stand-in range, an invalid byte, between letters
    let mut name = "A\u{10FFFF}B\u{10F7FF}C".as_bytes().to_vec();
    name.extend_from_slice(&[0xff, b'D']);
    let mut new = b"101 (".to_vec();
    new.extend_from_slice(&name);
    new.extend_from_slice(&old[close..]);
    fs::write(&stat, new).unwrap();

    let clock = clock();
    let mut engine = Engine::new(
        settings(Mode::Report),
        env(ProcFs::new(d.path().join("proc"), fixtures().join("sys")), FakeSetter::default(), &clock, vec![Box::new(Recorder::new(false))]),
    );
    let events = engine.tick().unwrap();
    let ev = events.iter().find(|e| e.tid == 101).unwrap();
    assert!(ev.comm.contains("A\u{10FFFF}B\u{10F7FF}C\\x{ff}D"), "{}", ev.comm);

    assert_no_internal("log line", &describe(ev));
    let (subject, body) = render(ev, &cpus("2-3"), None);
    assert_no_internal("mail subject", &subject);
    assert_no_internal("mail body", &body);
    let dir = tempfile::tempdir().unwrap();
    let mut prom = PrometheusTextfile::new(dir.path(), std::time::Duration::from_secs(900));
    prom.notify(ev).unwrap();
    assert_no_internal("metrics", &prom.render());
}
