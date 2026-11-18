//! Stage 1 with a real sudo rule: the same real `pledge`, `pact`'s own composer and
//! signer, and this crate's service core as `stage1.rs`, but the verb is run by
//! [`SudoRunner`], that is by `sudo -n /usr/local/bin/probe --within <rating> --call <uuid> ...`
//! as root, as the service's account will do it. Only HTTP between `pact` and `probe`
//! is still in process.
//!
//! **Ignored, and it does nothing unless `PROBE_STAGE1_SUDO=1`.** It needs a Linux host
//! prepared as `proposals/RUNBOOK-stage1-linux.md` says (the account `probe-svc`, the
//! sudoers rule, the installed `probe` built with `--features test-verbs`), and it is
//! run **as that account**: person and service account are one user here, a
//! simplification of this trial (the real shape has the person on another machine's
//! pledge; stage 1 has one machine and one person).
//!
//! It has not been run by its author: the machine it was written on has no Linux and no
//! sudo rule. It compiles, and its gate works.
#![allow(unused_imports)]

mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use p_act::pact::Settings;
use p_act::pact::mcp::call_once;
use p_act::sign::{PublicKey, Signer};
use p_robe::runner::SudoRunner;
use p_robe::service::{Service, Settings as ServiceSettings};
use p_robe::store::UsedStore;
use p_robe::{pledge, setup};
use serde_json::{Value, json};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

#[test]
#[ignore = "needs the host of RUNBOOK-stage1-linux.md, run as probe-svc, with PROBE_STAGE1_SUDO=1"]
fn the_cases_through_a_real_sudo_rule() {
    if std::env::var("PROBE_STAGE1_SUDO").as_deref() != Ok("1") {
        eprintln!("PROBE_STAGE1_SUDO is not 1: nothing run");
        return;
    }
    let probe = PathBuf::from(env_or("PROBE_BIN", "/usr/local/bin/probe"));
    let sudo = PathBuf::from(env_or("SUDO_BIN", "/usr/bin/sudo"));
    assert!(probe.exists(), "{} is not installed", probe.display());
    assert!(
        unsafe { libc::geteuid() } != 0,
        "run this as the service account, not as root: the rule is for that account"
    );

    let dir = dir_for("sudo");
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
    keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &path("host")]);
    setup::run(&dir.join("host"), HOST, &dir.join("probe")).expect("probe setup");
    let mut pledge = Pledge::start(&dir);
    for purpose in ["delegation", "confirmed", "automatic"] {
        pledge.answer("y\n");
        pledge.ok(&["keys", "create", purpose]);
    }
    let keys: Value = serde_json::from_str(&pledge.ok(&["keys", "list", "--format", "json"])).unwrap();
    let key = |purpose: &str| {
        let entry = keys["keys"].as_array().unwrap().iter().find(|k| k["purpose"] == purpose).unwrap();
        PublicKey::parse(entry["public"].as_str().unwrap()).unwrap()
    };
    fs::create_dir_all(dir.join("used")).unwrap();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = log.clone();
    let service = Arc::new(Service::new(
        ServiceSettings {
            host: HOST.into(),
            person: "jan".into(),
            confirmed: key("confirmed"),
            automatic: key("automatic"),
            max_waiting: 16,
        },
        Signer::certified(dir.join("probe/service-key")).unwrap(),
        UsedStore::new(dir.join("used")),
        pledge::PledgeLink { socket: pledge.sockets.join("service.sock"), uid: unsafe { libc::geteuid() } },
        Box::new(SudoRunner { sudo, probe }),
        Box::new(move |line| sink.lock().unwrap().push(line.to_string())),
    ));
    let transport =
        Arc::new(InProcessMcp { service, posted: Mutex::new(Vec::new()), hold_calls: AtomicBool::new(false) });
    let (bundle, _) = pledge.start_agent(&dir, "bundle");
    let (agent, dropped) = pact(&bundle, &transport, Settings::new(120, None));
    assert!(dropped.is_empty(), "{dropped:?}");
    let call = |tool: &str, params: &[&str]| told(&call_once(&agent, tool, &json!({"params": params})));
    let mut expected: Vec<(&str, Option<&str>)> = Vec::new();

    // 1. A real verb, as root through sudo: `sys kit` says what it is running as.
    let kit = call("sys_kit", &[]);
    assert!(is(&kit, "done", None), "{kit:?} {:?}", log.lock().unwrap());
    assert!(kit.rest[0].contains("\"euid\":0"), "the dispatcher did not run as root: {:?}", kit.rest);
    expected.push(("approved", None));
    // 2. `test echo`: automatic.
    let echo = call("test_echo", &["via=sudo"]);
    assert!(is(&echo, "done", None) && echo.rest[0].contains("\"args\":[\"via=sudo\"]"), "{echo:?}");
    expected.push(("approved", None));
    // 3. `test peak`: asked, the presence check, the confirmed key, run by root.
    pledge.answer("y\ny\n");
    let peak = call("test_peak", &[]);
    assert!(is(&peak, "done", None), "{peak:?} {:?}", log.lock().unwrap());
    expected.push(("approved", None));
    // 4. Declined.
    pledge.answer("n\n");
    assert!(is(&call("test_peak", &[]), "declined", None));
    expected.push(("declined", None));
    // 5. A file only root may read (the rule itself, mode 0440 root:root), read through the descriptor
    //    the dispatcher opened as root. `test read` is rated at the worst outside the test sandbox, so
    //    it is asked about.
    pledge.answer("y\ny\n");
    let rule = call("test_read", &["/etc/sudoers.d/probe-svc"]);
    assert!(is(&rule, "done", None) && rule.rest[0].contains("probe-svc"), "{rule:?}");
    expected.push(("approved", None));

    let history = pledge.history();
    check_peers(&history);
    let results: Vec<(String, Option<String>)> = history
        .iter()
        .filter(|e| e["type"] == "request")
        .map(|e| (e["result"].as_str().unwrap().to_owned(), e["reason"].as_str().map(str::to_owned)))
        .collect();
    let expected: Vec<(String, Option<String>)> =
        expected.iter().map(|(r, why)| ((*r).to_owned(), why.map(str::to_owned))).collect();
    assert_eq!(results, expected);
    eprintln!("{}", log.lock().unwrap().join("\n"));
    eprintln!("PASSED: the service ran verbs through sudo as root; find them in syslog by the call identifiers above");
    let _ = fs::remove_dir_all(&dir);
}
