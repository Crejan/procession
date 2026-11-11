//! `pledge serve` against the real programs: `ssh-add`, `ssh-keygen` (which
//! signs through the SSH agent socket with `-U`), and `ssh`.
//!
//! Each test starts its own `pledge serve` with its own directories. The
//! dialogs read their answers from the server's standard input, so a test
//! writes the answers it wants. Everything is under a directory where a Unix
//! socket can be bound (`$TMPDIR`, or `/tmp/claude` in the sandbox of this
//! development environment).

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const PLEDGE: &str = env!("CARGO_BIN_EXE_pledge");

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = format!("pl-it-{}-{}-{name}", std::process::id() % 100_000, NEXT.fetch_add(1, Ordering::Relaxed));
        for base in [std::env::temp_dir(), PathBuf::from("/tmp/claude")] {
            let dir = base.join(&unique);
            fs::create_dir_all(&dir).expect("create dir");
            let probe = dir.join("p.sock");
            if UnixListener::bind(&probe).is_ok() {
                let _ = fs::remove_file(&probe);
                return Self(dir);
            }
            let _ = fs::remove_dir_all(&dir);
        }
        panic!("no directory where a Unix socket can be bound");
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Server {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    state: PathBuf,
    sockets: PathBuf,
    _dir: Dir,
}

impl Server {
    fn start(name: &str, known_hosts: Option<&Path>) -> Self {
        let dir = Dir::new(name);
        let (state, sockets) = (dir.join("state"), dir.join("run"));
        let mut command = Command::new(PLEDGE);
        command.args(["serve", "--state-dir"]).arg(&state).arg("--socket-dir").arg(&sockets);
        command.arg("--known-hosts").arg(known_hosts.map_or_else(|| dir.join("known_hosts"), Path::to_path_buf));
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start pledge serve");
        let stdin = child.stdin.take().expect("stdin");
        let (sender, lines) = mpsc::channel();
        let stdout = child.stdout.take().expect("stdout");
        let tx = sender.clone();
        thread::spawn(move || {
            BufReader::new(stdout).lines().map_while(Result::ok).for_each(|l| drop(tx.send(format!("out: {l}"))))
        });
        let stderr = child.stderr.take().expect("stderr");
        thread::spawn(move || {
            BufReader::new(stderr).lines().map_while(Result::ok).for_each(|l| drop(sender.send(format!("err: {l}"))))
        });
        let server = Self { child, stdin, lines, state, sockets, _dir: dir };
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(server.agent()).is_err() {
            assert!(Instant::now() < deadline, "pledge serve did not start");
            thread::sleep(Duration::from_millis(50));
        }
        server
    }

    fn agent(&self) -> PathBuf {
        self.sockets.join("agent.sock")
    }

    /// The answers the dialogs will read, in order.
    fn answer(&mut self, text: &str) {
        self.stdin.write_all(text.as_bytes()).and_then(|()| self.stdin.flush()).expect("answer");
    }

    /// Waits for a line of the server's output (stdout, stderr) that starts with `prefix`.
    fn wait_for(&self, prefix: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line)
                    if line
                        .trim_start_matches("out: ")
                        .trim_start_matches("err: ")
                        .trim_start()
                        .starts_with(prefix) =>
                {
                    return line;
                }
                Ok(_) => {}
                Err(_) => panic!("pledge serve did not print a line starting {prefix:?}"),
            }
        }
    }

    fn pledge(&self, args: &[&str]) -> Output {
        Command::new(PLEDGE)
            .args(args)
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--socket-dir")
            .arg(&self.sockets)
            .output()
            .expect("run pledge")
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.pledge(args);
        assert!(out.status.success(), "pledge {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn history(&self) -> Vec<serde_json::Value> {
        self.ok(&["history", "--format", "json", "--verify"])
            .lines()
            .map(|l| serde_json::from_str(l).expect("json"))
            .collect()
    }

    fn with_agent(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command.env("SSH_AUTH_SOCK", self.agent()).env_remove("SSH_ASKPASS");
        command
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run(command: &mut Command) -> Output {
    command.stdin(Stdio::null()).output().expect("run")
}

fn text(output: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
}

#[test]
fn it_says_at_start_that_the_form_protects_nothing() {
    let server = Server::start("warning", None);
    let line = server.wait_for("pledge: development form");
    assert!(line.contains("protects nothing"), "{line}");
}

#[test]
fn ssh_add_lists_nothing_then_the_key_pledge_made() {
    let mut server = Server::start("ssh-add", None);
    let empty = run(server.with_agent("ssh-add").arg("-l"));
    assert_eq!(empty.status.code(), Some(1), "{}", text(&empty));
    assert!(text(&empty).contains("no identities"), "{}", text(&empty));

    server.answer("y\n");
    let public = server.ok(&["keys", "create", "shared"]);
    assert!(public.starts_with("ssh-ed25519 AAAA"), "{public}");
    let listed = run(server.with_agent("ssh-add").arg("-l"));
    assert!(listed.status.success(), "{}", text(&listed));
    // The fingerprint ssh-add prints is the one pledge lists, and the one ssh-keygen computes.
    let keys: serde_json::Value =
        serde_json::from_str(&server.ok(&["keys", "list", "--format", "json"])).expect("json");
    let fingerprint = keys["keys"][0]["fingerprint"].as_str().expect("fingerprint").to_owned();
    assert!(text(&listed).contains(&fingerprint), "{} vs {fingerprint}", text(&listed));
    let file = server._dir.join("key.pub");
    fs::write(&file, &public).expect("write");
    let keygen = run(Command::new("ssh-keygen").arg("-lf").arg(&file));
    assert!(text(&keygen).contains(&fingerprint), "{}", text(&keygen));
    let full = run(server.with_agent("ssh-add").arg("-L"));
    assert_eq!(text(&full).trim(), public.trim());
}

#[test]
fn ssh_keygen_signs_through_pledge_after_the_person_admits_it_and_the_signature_verifies() {
    let mut server = Server::start("sshsig", None);
    server.answer("y\n");
    let public = server.ok(&["keys", "create", "shared"]);
    let key_file = server._dir.join("key.pub");
    fs::write(&key_file, &public).expect("write");
    let data = server._dir.join("data.txt");
    fs::write(&data, "signed by pledge\n").expect("write");

    let mut keygen = server.with_agent("ssh-keygen");
    keygen.args(["-Y", "sign", "-n", "git", "-U", "-f"]).arg(&key_file).arg(&data);
    let child = keygen.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("ssh-keygen");
    // An unknown program: pledge asks about it first, then for the presence check.
    let program_line = server.wait_for("program:");
    let program = program_line.rsplit("program: ").next().expect("program").trim().to_owned();
    assert!(program.ends_with("ssh-keygen"), "{program_line}");
    server.answer(&format!("g\n{program}\ny\n"));
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success(), "{}", text(&output));
    let signature = server._dir.join("data.txt.sig");
    assert!(fs::read_to_string(&signature).expect("sig").contains("BEGIN SSH SIGNATURE"));

    let verify = Command::new("ssh-keygen")
        .args(["-Y", "check-novalidate", "-n", "git", "-s"])
        .arg(&signature)
        .stdin(fs::File::open(&data).expect("data"))
        .output()
        .expect("verify");
    assert!(verify.status.success() && text(&verify).contains("Good \"git\" signature"), "{}", text(&verify));

    // The same program is admitted now: only the presence check.
    server.answer("y\n");
    fs::write(&data, "second\n").expect("write");
    let again =
        run(server.with_agent("ssh-keygen").args(["-Y", "sign", "-n", "file", "-U", "-f"]).arg(&key_file).arg(&data));
    assert!(again.status.success(), "{}", text(&again));
    // Declined: no signature.
    server.answer("n\n");
    let declined =
        run(server.with_agent("ssh-keygen").args(["-Y", "sign", "-n", "git", "-U", "-f"]).arg(&key_file).arg(&data));
    assert!(!declined.status.success(), "{}", text(&declined));

    let history = server.history();
    let results: Vec<(&str, &str)> = history
        .iter()
        .filter(|e| e["type"] == "signing-request")
        .map(|e| (e["result"].as_str().expect("result"), e["namespace"].as_str().expect("namespace")))
        .collect();
    assert_eq!(results, [("approved", "git"), ("approved", "file"), ("declined", "git")]);
    assert!(history.iter().all(|e| e["type"] != "signing-request" || e["program"].as_str() == Some(program.as_str())));
    // programs list shows the decision, and a restart's file has it.
    assert!(server.ok(&["programs", "list"]).contains(&format!("admitted {program}")));
}

#[test]
fn what_pledge_cannot_read_or_must_not_sign_is_refused_without_a_dialog() {
    let mut server = Server::start("refusals", None);
    server.answer("y\n");
    let public = server.ok(&["keys", "create", "shared"]);
    let key_file = server._dir.join("key.pub");
    fs::write(&key_file, &public).expect("write");
    let data = server._dir.join("data.txt");
    fs::write(&data, "x\n").expect("write");
    for namespace in ["approval-v1@procession", "call-v1@procession", "anything@procession", "other"] {
        let output = run(server
            .with_agent("ssh-keygen")
            .args(["-Y", "sign", "-n", namespace, "-U", "-f"])
            .arg(&key_file)
            .arg(&data));
        assert!(!output.status.success(), "{namespace}: {}", text(&output));
    }
    let history = server.history();
    let reasons: Vec<&str> = history
        .iter()
        .filter(|e| e["type"] == "signing-request")
        .map(|e| e["reason"].as_str().expect("reason"))
        .collect();
    assert_eq!(reasons, ["reserved-namespace", "reserved-namespace", "reserved-namespace", "key-not-offered"]);
    // No dialog was shown for any of them: only the key's own presence check printed a prompt.
    let mut dialogs = 0;
    while let Ok(line) = server.lines.try_recv() {
        dialogs += usize::from(line.contains("pledge: presence check") || line.contains("unknown program"));
    }
    assert_eq!(dialogs, 1, "only the dialog for making the key");
    assert!(!fs::exists(server._dir.join("data.txt.sig")).expect("exists"));
}

#[test]
fn a_blocked_program_stays_blocked_and_a_second_pledge_serve_is_refused() {
    let mut server = Server::start("block", None);
    server.answer("y\n");
    let public = server.ok(&["keys", "create", "shared"]);
    let key_file = server._dir.join("key.pub");
    fs::write(&key_file, &public).expect("write");
    let data = server._dir.join("data.txt");
    fs::write(&data, "x\n").expect("write");
    let mut keygen = server.with_agent("ssh-keygen");
    keygen.args(["-Y", "sign", "-n", "git", "-U", "-f"]).arg(&key_file).arg(&data);
    let child = keygen.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("ssh-keygen");
    server.wait_for("program:");
    server.answer("b\n");
    assert!(!child.wait_with_output().expect("wait").status.success());
    assert!(server.ok(&["programs", "list"]).starts_with("blocked "));
    // Blocked: refused at once, nothing to answer.
    let output =
        run(server.with_agent("ssh-keygen").args(["-Y", "sign", "-n", "git", "-U", "-f"]).arg(&key_file).arg(&data));
    assert!(!output.status.success());
    // A second serve on the same directories does not start.
    let second = Command::new(PLEDGE)
        .args(["serve", "--state-dir"])
        .arg(&server.state)
        .arg("--socket-dir")
        .arg(&server.sockets)
        .stdin(Stdio::null())
        .output()
        .expect("run");
    assert_eq!(second.status.code(), Some(3), "{}", text(&second));
    assert!(text(&second).contains("in use"), "{}", text(&second));
    let reasons: Vec<String> =
        server.history().iter().filter_map(|e| e["reason"].as_str().map(str::to_owned)).collect();
    assert_eq!(reasons, ["blocked", "blocked"], "the block itself, then the refusal without a dialog");
}

/// A login with the real `ssh` against a local `sshd`. It needs to bind a TCP
/// port and an `sshd` binary; where it cannot, it says so and does nothing.
#[test]
fn ssh_logs_in_through_pledge_to_a_local_sshd_or_is_skipped() {
    let Ok(probe) = TcpListener::bind("127.0.0.1:0") else {
        eprintln!("SKIPPED ssh login test: binding a local TCP port is not allowed here, so no sshd can run");
        return;
    };
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    let sshd = ["/usr/sbin/sshd", "/usr/bin/sshd"].into_iter().find(|p| Path::new(p).exists());
    let Some(sshd) = sshd else {
        eprintln!("SKIPPED ssh login test: no sshd found");
        return;
    };
    let dir = Dir::new("sshd");
    let host_key = dir.join("host_key");
    assert!(
        run(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&host_key)).status.success()
    );
    let host_pub = fs::read_to_string(dir.join("host_key.pub")).expect("host pub");
    let known_hosts = dir.join("known_hosts");
    fs::write(&known_hosts, format!("[127.0.0.1]:{port} {}", host_pub.trim())).expect("known_hosts");

    let mut server = Server::start("ssh-login", Some(&known_hosts));
    server.answer("y\n");
    let public = server.ok(&["keys", "create", "shared"]);
    let authorized = dir.join("authorized_keys");
    fs::write(&authorized, &public).expect("authorized");
    let config = dir.join("sshd_config");
    fs::write(
        &config,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nUsePAM no\nPasswordAuthentication no\nStrictModes no\n",
            host_key.display(),
            dir.join("sshd.pid").display(),
            authorized.display()
        ),
    )
    .expect("config");
    let mut daemon = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sshd");
    thread::sleep(Duration::from_millis(500));
    let user = std::env::var("USER").expect("USER");
    let mut ssh = server.with_agent("ssh");
    ssh.args(["-F", "/dev/null", "-p", &port.to_string(), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .arg("-o")
        .arg(format!("IdentityAgent={}", server.agent().display()))
        .arg(format!("{user}@127.0.0.1"))
        .arg("true");
    let child = ssh.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("ssh");
    let program = server.wait_for("program:").rsplit("program: ").next().expect("program").trim().to_owned();
    let shown = server.wait_for("host:");
    assert!(shown.contains("127.0.0.1"), "the dialog names the verified host: {shown}");
    server.answer(&format!("g\n{program}\ny\n"));
    let output = child.wait_with_output().expect("wait");
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert!(output.status.success(), "{}", text(&output));
    let login = server.history().into_iter().find(|e| e["use"] == "login").expect("a login was recorded");
    assert_eq!((login["result"].as_str(), login["host_verified"].as_bool()), (Some("approved"), Some(true)));
}
