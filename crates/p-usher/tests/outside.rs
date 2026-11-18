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
