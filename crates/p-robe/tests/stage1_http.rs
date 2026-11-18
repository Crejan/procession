//! Stage 1 over real HTTP: the real `pledge serve`, `probe serve`'s HTTP transport (`hyper`) in this
//! process on a TCP port, and the real `pact` binary as the agent's client (`pact call TOOL ARGS <
//! bundle`), so that the call travels as `pact` sends it, over the network stack, as `_meta` of a
//! `tools/call`, answered as a stream.
//!
//! **Ignored, and it does nothing unless `PROBE_STAGE1_HTTP=1`.** It binds `127.0.0.1:$PROBE_STAGE1_PORT`
//! (default 18765), which the sandbox this was written in does not allow, and it needs the `pact`
//! binary with its HTTP client (p-act's `ureq` one, `--features p-act/pact`). It has **never been run**;
//! it compiles against p-act's merged client, and its gate works.
//!
//! With `PROBE_STAGE1_SUDO=1` too, the verb is run by `SudoRunner` (as `RUNBOOK-stage1-linux.md` sets
//! it up, as `probe-svc`); otherwise by `InProcess`, as a simulated root, on any machine with TCP.
#![allow(unused_imports)]

mod common;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use p_act::sign::{PublicKey, Signer};
use p_robe::http::{Limits, accept_loop};
use p_robe::runner::{InProcess, Runner, SudoRunner};
use p_robe::service::{Service, Settings as ServiceSettings};
use p_robe::store::UsedStore;
use p_robe::{pledge, setup};
use serde_json::{Value, json};

fn pact_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let path = exe.parent().and_then(std::path::Path::parent).unwrap().join("pact");
    assert!(
        path.exists(),
        "{} is not built: cargo build --workspace --features p-robe/test-verbs,p-act/pact",
        path.display()
    );
    path
}

/// `pact call TOOL ARGUMENTS < bundle`: the normalised result, as a JSON value.
fn pact_call(bundle: &[u8], tool: &str, arguments: &Value) -> Value {
    let mut child = Command::new(pact_binary())
        .args(["call", tool, &arguments.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pact");
    child.stdin.take().unwrap().write_all(bundle).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "pact: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
#[ignore = "binds a TCP port; needs the pact binary; PROBE_STAGE1_HTTP=1"]
fn the_real_pact_calls_the_real_probe_over_http() {
    if std::env::var("PROBE_STAGE1_HTTP").as_deref() != Ok("1") {
        eprintln!("PROBE_STAGE1_HTTP is not 1: nothing run");
        return;
    }
    let port = std::env::var("PROBE_STAGE1_PORT").unwrap_or_else(|_| "18765".into());
    // The URL pledge writes into the bundle.
    // SAFETY: set before any other thread of this test exists.
    unsafe { std::env::set_var("PROBE_STAGE1_URL", format!("http://127.0.0.1:{port}/mcp")) };

    let dir = dir_for("http");
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
    fs::create_dir_all(dir.join("locks")).unwrap();
    let runner: Box<dyn Runner> = if std::env::var("PROBE_STAGE1_SUDO").as_deref() == Ok("1") {
        Box::new(SudoRunner { sudo: "/usr/bin/sudo".into(), probe: "/usr/local/bin/probe".into() })
    } else {
        Box::new(InProcess {
            audit_file: dir.join("dispatcher.log"),
            lock_dir: dir.join("locks"),
            user: "probe".into(),
            before: None,
        })
    };
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
        runner,
        Box::new(move |line| sink.lock().unwrap().push(line.to_string())),
    ));

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")))
        .expect("a TCP port can be bound here");
    let server = runtime.spawn(accept_loop(listener, service, Limits::default(), shutdown));

    let (bundle, _) = pledge.start_agent(&dir, "bundle");
    let told_by = |tool: &str, params: &[&str]| told(&pact_call(&bundle, tool, &json!({"params": params})));
    let mut expected: Vec<(&str, Option<&str>)> = Vec::new();

    let echo = told_by("test_echo", &["via=http"]);
    assert!(
        is(&echo, "done", None) && echo.rest[0].contains("\"args\":[\"via=http\"]"),
        "{echo:?} {:?}",
        log.lock().unwrap()
    );
    expected.push(("approved", None));
    pledge.answer("y\ny\n");
    let peak = told_by("test_peak", &[]);
    assert!(is(&peak, "done", None), "{peak:?} {:?}", log.lock().unwrap());
    expected.push(("approved", None));
    pledge.answer("n\n");
    assert!(is(&told_by("test_peak", &[]), "declined", None));
    expected.push(("declined", None));
    let kit = told_by("sys_kit", &[]);
    assert!(is(&kit, "done", None), "{kit:?}");
    expected.push(("approved", None));

    let results: Vec<(String, Option<String>)> = pledge
        .history()
        .iter()
        .filter(|e| e["type"] == "request")
        .map(|e| (e["result"].as_str().unwrap().to_owned(), e["reason"].as_str().map(str::to_owned)))
        .collect();
    let expected: Vec<(String, Option<String>)> =
        expected.iter().map(|(r, why)| ((*r).to_owned(), why.map(str::to_owned))).collect();
    assert_eq!(results, expected);
    let _ = stop.send(());
    runtime.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(3), server).await;
    });
    eprintln!("PASSED: the real pact called the real probe over HTTP\n{}", log.lock().unwrap().join("\n"));
    let _ = fs::remove_dir_all(&dir);
}
