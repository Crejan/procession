//! Shared by the tests that run the real `pledge` binary.
#![allow(dead_code)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

pub const PLEDGE: &str = env!("CARGO_BIN_EXE_pledge");

pub struct Dir(PathBuf);

impl Dir {
    pub fn new(name: &str) -> Self {
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
    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub struct Server {
    pub child: Child,
    pub stdin: ChildStdin,
    pub lines: Receiver<String>,
    pub state: PathBuf,
    pub sockets: PathBuf,
    pub _dir: Dir,
}

impl Server {
    pub fn start(name: &str, known_hosts: Option<&Path>) -> Self {
        Self::start_with(name, known_hosts, |_, _| {})
    }

    /// As `start`, after `setup` has put files into the state directory.
    pub fn start_with(name: &str, known_hosts: Option<&Path>, setup: impl FnOnce(&Path, &Dir)) -> Self {
        let dir = Dir::new(name);
        let (state, sockets) = (dir.join("state"), dir.join("run"));
        fs::create_dir_all(&state).expect("state dir");
        fs::set_permissions(&state, std::os::unix::fs::PermissionsExt::from_mode(0o700)).expect("chmod");
        setup(&state, &dir);
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

    pub fn agent(&self) -> PathBuf {
        self.sockets.join("agent.sock")
    }

    /// The answers the dialogs will read, in order.
    pub fn answer(&mut self, text: &str) {
        self.stdin.write_all(text.as_bytes()).and_then(|()| self.stdin.flush()).expect("answer");
    }

    /// Waits for a line of the server's output (stdout, stderr) that starts with `prefix`.
    pub fn wait_for(&self, prefix: &str) -> String {
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

    pub fn pledge(&self, args: &[&str]) -> Output {
        Command::new(PLEDGE)
            .args(args)
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--socket-dir")
            .arg(&self.sockets)
            .output()
            .expect("run pledge")
    }

    pub fn ok(&self, args: &[&str]) -> String {
        let out = self.pledge(args);
        assert!(out.status.success(), "pledge {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    pub fn history(&self) -> Vec<serde_json::Value> {
        self.ok(&["history", "--format", "json", "--verify"])
            .lines()
            .map(|l| serde_json::from_str(l).expect("json"))
            .collect()
    }

    pub fn with_agent(&self, program: &str) -> Command {
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

pub fn run(command: &mut Command) -> Output {
    command.stdin(Stdio::null()).output().expect("run")
}

pub fn text(output: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
}
