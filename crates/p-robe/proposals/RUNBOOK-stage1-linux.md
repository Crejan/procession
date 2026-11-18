# Runbook: stage 1 on one Linux machine, with a real sudo rule and real HTTP

> **For a trial machine or a virtual machine only. Not on a host that matters.**
> The `probe` this runbook installs is built with the test verbs, and the
> sudoers rule lets the account `probe-svc` run it as root. With that build and
> that rule in place, **`probe-svc` can read any file on the machine as root**
> through `test read` (the cross run of step A3 does exactly that, with the
> sudoers file); the approval of a person stands between an agent and that, and
> nothing else does. A production install has no test verbs. Take a VM, and throw
> it away, or run `undo.sh`.

For the owner, to follow by hand. Stage 1 of `doc/approvals.md` section 8 is
"one Linux machine, keys in files": pledge, `pact` and `probe` on one host, the
verb run by the dispatcher through a real sudo rule, the agent reaching the
service over HTTP. Nothing in it has been run on Linux. Terms are those of
`doc/approvals.md` section 1; a systemd unit is called a unit.

## 0. What exists and what does not

| Part | State |
|---|---|
| `pledge serve`, `pledge keys`, `pledge agents start/withdraw`, `pledge history` | built (p-ledge), tested on macOS |
| `probe` dispatcher, `sudo -n probe --within <rating> --call <uuid> <noun> <verb> ...` | built, tested on macOS with a simulated root; **never run through sudo** |
| `probe setup` (the service's key and its 30-day certificate from the host key; **the same command renews**: it keeps the key, replaces the certificate by a rename; with no arguments it takes `/etc/probe.toml` or the defaults) | built, run on macOS with a throwaway host key |
| the daily renewal timer and its unit (`stage1/probe-setup.service` and `.timer`, running `probe setup --if-due`) | written, **never run** (no systemd here); `systemd-analyze verify` is the first check |
| `sys kit` reports the certificate's days left (a warning under 5) | built and tested on macOS with certificates made by `ssh-keygen -V` |
| `probe serve`: the service core (checks, request, wait, approval, run), the MCP layer | built; run in-process against the real pledge (`tests/stage1.rs`) |
| `probe serve` **over HTTP** | **not built.** It needs an HTTP server crate that cannot be fetched in the sandbox (section 6) |
| `pact` composer, signer, catalogue, `pact call` / `pact tools` | built (p-act) |
| `pact`'s HTTP client | **not built** (`NoHttp`: every call is `unavailable`); p-act's decision (section 6) |
| the cross run through `SudoRunner` | **written, not run:** `tests/stage1_sudo.rs` |
| the scripts of Stage A (`stage1/*.sh`) | **written, not run** (syntax checked with `sh -n` on macOS) |

So the runbook has two stages. **Stage A runs today on a Linux machine**: the
sudo rule, the dispatcher as root, the audit lines, and the whole cross run
with the verb run through sudo, the HTTP hop between `pact` and `probe` still
in the test process. **Stage B needs the two HTTP pieces** and is written so
that it can be followed as soon as they exist; its commands are the ones the
programs have today, and what is not yet there is marked.

## 1. What the host needs

- Linux with `sudo` (1.9 or later is fine), `visudo`, `logger` (package
  `util-linux` or `bsdutils`), `ssh-keygen` (OpenSSH 8.x or later; the
  documents were checked with 10.2), `systemd` only for Stage B's unit, and a
  Rust toolchain (1.85 or later, edition 2024) to build.
- A shell as root (`sudo -i`), and an ordinary login for you, called `alice`
  below, who owns a checkout of the workspace.
- If `sudo` says "you must have a tty to run sudo", the host has `Defaults
  requiretty`: the scripts run `sudo` through `su`, which gives it one only
  if you run them from a terminal; use a terminal.
- **Getting the checkout onto the machine.** `integration` is a local branch on
  the owner's Mac and nothing is pushed anywhere. The owner decides between
  pushing it to a remote the Linux machine can reach and carrying it over with
  `git bundle create probe.bundle integration` (on the Mac) and `git clone
  probe.bundle checkout` (on the Linux machine). The runbook assumes the
  checkout is at `/home/alice/CHECKOUT`.
- Build, as `alice`, in the checkout:
  ```
  cargo build --workspace --features p-robe/test-verbs
  ```
  This gives `target/debug/probe`, `pledge` and `pact`. `probe` is built **with
  the test verbs** (`test echo`, `test peak`, `test read`) so that the cases
  have a harmless verb and one rated at the top of a scale. Such a build is
  for a trial host only (`sys kit` warns of it). Then:
  ```
  cargo test -p p-robe --features test-verbs --test stage1_sudo --no-run
  ```
  prints `Executable tests/stage1_sudo.rs (target/debug/deps/stage1_sudo-HASH)`.
  Note the path.

## 2. The rule and the account, in words

- **The account** `probe-svc`: a system account without login (`nologin`), home
  `/var/lib/probe-svc`. The service runs as it. It has no password and no key
  of anybody.
- **The sudoers rule**, `/etc/sudoers.d/probe-svc` (mode 0440), exactly:
  ```
  Defaults:probe-svc !lecture
  Defaults:probe-svc env_reset
  probe-svc ALL=(root) NOPASSWD: /usr/local/bin/probe --within [a-z]*,[a-z]*,[a-z]* --call ????????-????-????-????-???????????? [a-z]* [a-z]*
  ```
  It lets `probe-svc` run `/usr/local/bin/probe` as root in one form: `--within
  <rating> --call <uuid> <noun> <verb> [arguments]`. Sudoers wildcards match
  anything, spaces included, so the rule alone does not limit the words: the
  dispatcher refuses what is not a verb of its table (`run command` among it),
  and anything whose own rating is above the rating after `--within`. **The
  account can, through this rule, run every verb of the table** (the designer's
  decision, `crates/p-robe/SPEC.md`); what holds it back is the service's checks,
  not sudo. The rule is checked with `visudo -cf` before it is put in place.
- `/usr/local/bin/probe` is owned by root and writable by root only: sudo runs
  it as root, so whoever can replace it is root.
- **The environment.** The rule has `env_reset` and no `SETENV` tag, so sudo
  gives the dispatcher a clean environment and `probe-svc` cannot add to it
  (`sudo -E` and `VAR=x sudo ...` are refused for a rule without `SETENV`). The
  test build has one variable that moves things, `PROBE_TEST_SANDBOX`: it
  sends the audit lines to a file, the locks to a directory, and waives "must be
  root". It is **not reachable through this rule**: `env_reset` drops it, and
  even a site that kept it with `env_keep` would not get it, because the
  dispatcher ignores it in a process that is root (`dispatch::test_sandbox`,
  tested), which is what a call through sudo is. The only other variables the
  program reads are `SUDO_USER` (who ran sudo: sudo sets it, a caller cannot
  choose it for a root process) and `SSH_CONNECTION` (an address for the log
  line, copied only if it looks like one). A test lists every `env::var` in the
  sources so that a new one has to be argued for. After `--within` and `--call`,
  anything further that starts with `-` is refused (`-x`, `--help`, a second
  `--within`, `--` included), whatever the rule's `*` lets through; tested.

## 3. Every change to the machine, and how it is undone

| Change | By | Undone by |
|---|---|---|
| the account `probe-svc` and its home `/var/lib/probe-svc` | `a1-prepare.sh` | `undo.sh` (`userdel -r`; not if the account existed before) |
| `/usr/local/bin/probe` (root, 0755) | `a1-prepare.sh` | `undo.sh` |
| `/var/lib/probe/locks` (root, 0755), `/var/lib/probe/used` (probe-svc, 0700) | `a1-prepare.sh` | `undo.sh` (removes `/var/lib/probe`) |
| `/etc/sudoers.d/probe-svc` (0440) | `a1-prepare.sh`, after `visudo -cf` | `undo.sh` |
| lines in syslog or the journal (tag `probe`, facility `auth`) | the dispatcher, on every call | not undone: they are history |
| files in `/var/tmp` (`probe-stage1-run`, `probe-stage1.check.log*`) | `a2`, `a3` | `a3` removes its own; `undo.sh` the rest |
| temporary files under `/tmp` for pledge's state and sockets | the test | the test removes them when it passes; on a failure `rm -rf /tmp/s1-*` |
| Stage B only: `/etc/probe/` (service key and certificate), `/etc/probe.toml`, the units `probe-serve.service`, `probe-setup.service` and `probe-setup.timer`, pledge's state in your home, a TCP port on 127.0.0.1 | Stage B steps | the undo lines of Stage B |

`undo.sh` is safe to run at any time and does nothing to what is not on this list.

## 4. Stage A: the sudo part, today

All three scripts are in `crates/p-robe/proposals/stage1/`. Run them as root,
from a terminal, in this order. Each prints `PASS:` or `FAIL:` lines, and ends
with `ALL PASSED` or `SOMETHING FAILED`.

### A1. Prepare

```
sh stage1/a1-prepare.sh /home/alice/CHECKOUT/target/debug/probe
```

Passed: the last lines are `PASS: /etc/sudoers.d/probe-svc installed (visudo -cf
accepted it)` and `PASS: prepared`. Did not pass: it prints `FAIL:` and why
(a missing `logger`, `visudo`, `ssh-keygen`, a leftover file from before, or
`visudo -cf` refusing the rule, in which case **nothing was put into
`/etc/sudoers.d`**). Run `undo.sh` before trying again.

### A2. Check the rule

```
sh stage1/a2-check-rule.sh
```

It runs `sudo -n /usr/local/bin/probe ...` as `probe-svc` (through `su`) and
checks, each with its own line:

| Check | Passed means |
|---|---|
| `sys kit` through the rule | exit 0, and its answer says `"euid":0`: the dispatcher ran as root |
| `test peak` with `--within open,none,none` | exit 64: the dispatcher rated it above the approved rating and refused |
| `test peak` with `--within open,none,outage` | exit 0 |
| `run command` | exit 64: refused by the dispatcher, even with the widest rating |
| `--call` given twice | exit 64: refused by the dispatcher |
| `sudo -n /usr/local/bin/probe sys kit` (no flags) | exit 1: sudo itself refuses, the form is not in the rule |
| `sudo -n /bin/true` | exit 1: no other program is in the rule |
| the audit lines | syslog has `event=start` and `event=done` with `call=<uuid>` for the call that ran, `event=refused ... above-approved` with `call=<uuid>` for the one that was refused |

Did not pass: the line says which check, what it got and what it expected,
with sudo's own message (`a password is required` means the rule did not
match: compare `sudo -l -U probe-svc` with section 2). Syslog lines that are
not found mean the host's syslog does not keep `auth.info` where the script
looks (`journalctl -t probe`, `/var/log/auth.log`, `/var/log/syslog`,
`/var/log/messages`, `/var/log/secure`): look yourself with
`journalctl -t probe` and say where they are.

### A3. The cross run with the verb through sudo

As `alice`, make the files readable by root (they are copied):

```
ls -l target/debug/pledge target/debug/deps/stage1_sudo-HASH
```

As root:

```
sh stage1/a3-run-cross.sh /home/alice/CHECKOUT/target/debug/deps/stage1_sudo-HASH /home/alice/CHECKOUT/target/debug
```

It copies the test and `pledge` to `/var/tmp/probe-stage1-run` and runs the
test **as `probe-svc`**. The test starts its own `pledge serve` in a temporary
directory (keys in files, the person's answers scripted on its standard
input), makes the service's key and certificate with `probe setup` from a
throwaway host key, starts an agent with `pledge agents start`, has `pact`'s own
composer and signer make the calls, and hands them to the service core, which
runs the verb with `SudoRunner`: `sudo -n /usr/local/bin/probe --within ...
--call ...`.

| Case | The test checks |
|---|---|
| `sys kit` | done, and the answer says `euid` 0 |
| `test echo` | done (automatic approval) |
| `test peak` | done (asked, presence check, confirmed key) |
| `test peak`, the person declines | declined |
| `test read /etc/sudoers.d/probe-svc` (root's file, mode 0440) | done, and the text is the rule: the dispatcher, as root, opened it |
| the record | `pledge history --verify`: the five requests in order, approved, approved, approved, declined, approved |

Passed: exit 0, and the lines `PASSED: the service ran verbs through sudo as
root; ...`. Then, as root: `journalctl -t probe | grep call=` shows one
`start` and one `done` for each verb that ran, with the call identifiers the
test printed (the service's own lines, `call id=<uuid> ...`, are printed by
the test to its standard error).

Did not pass: the test panics at the first assertion that failed and prints the
service's log: look for `exact=run:` (sudo could not start), `exact=dispatcher-refused`
(the dispatcher refused: rating or words), `exact=dispatcher-unavailable` (exit
3: no audit line could be written, so `logger` or syslog is not working),
`exact=approval-invalid` (what pledge signed did not verify).

**What this does not show:** that the service runs as its own account apart
from the person (here the person's pledge and the service are one user, which
makes the door checks of `service.sock` trivial), and nothing about HTTP.

### Undo

```
sh stage1/undo.sh
```

## 5. Stage B: pledge as the person, `probe serve` as its own account, `pact`, over HTTP

**Not runnable yet**: it needs `probe serve` to listen (section 6) and `pact`
to have an HTTP client. The commands below use what exists today; the lines
marked **(needs HTTP)** are the ones that wait.

### B1. Pledge, as `alice`

```
pledge serve --state-dir /home/alice/.local/state/pledge --socket-dir /run/user/1000/pledge --known-hosts /home/alice/.ssh/known_hosts
```

(`1000` is alice's uid; `id -u alice`.) Before the first start put
`/home/alice/.local/state/pledge/config.json` in place, mode 0600, with:

```
{"person": "alice",
 "hosts": [{"host": "HOSTNAME", "key": "<the text of /etc/ssh/ssh_host_ed25519_key.pub>"}],
 "services": [{"host": "HOSTNAME", "name": "probe", "url": "http://127.0.0.1:8765/mcp"}],
 "service_group": "pledge-svc"}
```

`HOSTNAME` is the name the calls will carry (`service.host`); use the same in
B2. The group `pledge-svc` lets the service's account reach `service.sock`:
`groupadd pledge-svc; usermod -aG pledge-svc alice; usermod -aG pledge-svc
probe-svc` (undo: `userdel`/`groupdel` the other way). Log out and in so that
alice's membership counts; pledge makes the directory 0710 and the socket 0660
with that group. Make the three keys, answering the dialogs it prints:
`pledge keys create delegation`, `... confirmed`, `... automatic`. Then
`pledge keys list --format json` shows the public key lines; write the confirmed
one to `/etc/probe/alice-confirmed.pub` and the automatic one to
`/etc/probe/alice-automatic.pub` (root, 0644).

Passed: `pledge serve` prints nothing alarming and `ls -l
/run/user/1000/pledge` shows `service.sock` as `srw-rw----` with group
`pledge-svc`. Did not pass: it refuses to start naming the directory or its
mode.

### B2. The service's key and its certificate, as root; the renewal

```
probe setup --host-key /etc/ssh/ssh_host_ed25519_key --host HOSTNAME --out /etc/probe
chown probe-svc:probe-svc /etc/probe/service-key /etc/probe/service-key.pub /etc/probe/service-key-cert.pub
```

Makes `/etc/probe/service-key` (kept for good) and `service-key-cert.pub`, valid 30
days for the principal `probe@HOSTNAME`. Passed: it prints that it made them and
that a root timer renews them; `ssh-keygen -L -f /etc/probe/service-key-cert.pub`
shows `Principals: probe@HOSTNAME` and a `Valid:` that ends in 30 days. Did not
pass: it prints `probe setup: ssh-keygen: ...` (a host key it cannot read, a name
that is not a key) and **leaves no key behind**. Undo: `rm -rf /etc/probe`.

**It is also the renewing command, and idempotent.** Run again (as root, with
the same arguments or none once B3 is in place; with `--if-due` only when due) it keeps the key, makes a new
certificate in a directory of its own and renames it over the old one, owned by
the key's owner (so after the `chown` above it stays the service's). The running
service reads the certificate on every signature, so it needs no restart: the
old certificate is used until the rename, the new one after, never half of one. A
renewal that fails leaves the old certificate as it was and exits non-zero.
Passed: it prints `Kept the service's key and replaced its certificate`; `cmp
/etc/probe/service-key` before and after says they are the same file contents (copy
it first), and the certificate's `Valid:` end moved. Did not pass: as above, and the
old certificate is still there.

**The timer.** `probe setup --if-due` is the form the timer runs: it does nothing
and exits 0 while **more than 10 of the 30 days remain**, renews (key kept,
certificate replaced) when 10 or fewer remain, and renews at once when there is
no certificate, when the one there cannot be read or has no end, when it is for
another key than the service's, or when there is no key at all. A renewal that
fails ends non-zero. Run by hand without the flag, `probe setup` renews
unconditionally. The timer runs the unit once a day (`OnCalendar=daily`, within an
hour, `Persistent=true` so that a run missed while the host was off happens at the
next boot): a failed run shows the unit as failed and is tried again the next day,
instead of waiting weeks. Put `stage1/probe-setup.service` and
`stage1/probe-setup.timer` in `/etc/systemd/system/` and:

```
systemd-analyze verify /etc/systemd/system/probe-setup.service /etc/systemd/system/probe-setup.timer
systemctl daemon-reload
systemctl enable --now probe-setup.timer
systemctl start probe-setup.service
systemctl status probe-setup.service
systemctl list-timers probe-setup.timer
```

It needs nothing off the host and waits for nothing else. Passed: `verify` prints
nothing; right after B2 the manual `start` prints in the journal `Not due: 30 days
left of the service's certificate (renewed when 10 or fewer remain).` and
`status` shows `status=0/SUCCESS`; `list-timers` shows NEXT within a day. Did
not pass: `status` shows `failed` and the journal says why (`probe setup
--if-due: ...`: a host key it cannot read, ...); the old certificate is
untouched and the next day's run tries again. A settings file that exists and does
not parse makes it refuse (exit 64), which also shows as a failed unit.

To see a renewal happen, as root: make a certificate that ends in 9 days (`ssh-keygen -s
/etc/ssh/ssh_host_ed25519_key -I probe@HOSTNAME -n probe@HOSTNAME -V +9d -O clear
/etc/probe/service-key.pub`, which writes `service-key-cert.pub` beside the
key file; then `chown probe-svc:probe-svc /etc/probe/service-key-cert.pub`), run
`systemctl start probe-setup.service`, and read the journal: `Due (Remaining(...))`
and the note that the key was kept; `ssh-keygen -L -f
/etc/probe/service-key-cert.pub` then shows 30 days again. Remove the file instead of
replacing it and the journal says `Due (NoCertificate)`.

**What `sys kit` says.** `probe` reports the certificate's days left. Run it as a login that has
sudo (the dispatcher takes only a call that came through sudo): `sudo
/usr/local/bin/probe sys kit` shows in its
`installation` record `service_certificate` (the path) and
`service_certificate_days_left` (30 right after a renewal), and in its `summary`
a warning when fewer than 5 are left (`the service's certificate has 3 days left
(fewer than 5): run probe setup as root`), and one that says it has ended at 0 or
less. It never makes `usable` false by itself. To see the warning, as root:
copy the certificate aside, make one that ends soon (`ssh-keygen -s
/etc/ssh/ssh_host_ed25519_key -I probe@HOSTNAME -n probe@HOSTNAME -V +3d -O clear
/etc/probe/service-key.pub` writes `service-key-cert.pub` beside the key file),
run `sudo /usr/local/bin/probe sys kit`, then run `probe setup` and `sudo
/usr/local/bin/probe sys kit` again: the
warning is gone and the days are 30. **Undo of the timer:** `systemctl disable --now probe-setup.timer; rm
/etc/systemd/system/probe-setup.service /etc/systemd/system/probe-setup.timer;
systemctl daemon-reload`. (Without the timer the certificate ends in 30 days and
`sys kit` warns from 5 days before.)

### B3. `/etc/probe.toml`

```
host = "HOSTNAME"
host_key = "/etc/ssh/ssh_host_ed25519_key"
person = "alice"
confirmed_key = "/etc/probe/alice-confirmed.pub"
automatic_key = "/etc/probe/alice-automatic.pub"
service_key = "/etc/probe/service-key"
pledge_socket = "/run/user/1000/pledge/service.sock"
pledge_uid = 1000
used_dir = "/var/lib/probe/used"
listen = "127.0.0.1:8765"
probe = "/usr/local/bin/probe"
```

### B4. Start `probe serve` as `probe-svc` **(needs HTTP)**

```
sudo -u probe-svc /usr/local/bin/probe serve --config /etc/probe.toml
```

Today this builds the service and says `the HTTP transport on 127.0.0.1:8765 is
not built yet` (exit 2), and whether pledge is reachable (`pledge reachable`
or `not reachable`): that part can be run now, and `reachable` shows the
door of `service.sock` works for the account. Once the transport exists it
listens. As a unit, `/etc/systemd/system/probe-serve.service`:

```
[Unit]
Description=probe: diagnostics for agents, with approval
After=network.target

[Service]
User=probe-svc
ExecStart=/usr/local/bin/probe serve --config /etc/probe.toml
Restart=on-failure
NoNewPrivileges=false
ProtectSystem=strict
ReadWritePaths=/var/lib/probe/used

[Install]
WantedBy=multi-user.target
```

(`NoNewPrivileges` must stay `false`: sudo needs to become root.) Undo:
`systemctl disable --now probe-serve; rm /etc/systemd/system/probe-serve.service`.

### B5. An agent and a call **(needs HTTP)**

As `alice`: `pledge agents start --groups admins --output /home/alice/bundle`
(answer the dialog). Then, as the user the agent runs as:

```
pact tools < /home/alice/bundle
pact call test_echo '{"params":["hello"]}' < /home/alice/bundle
pact call test_peak '{"params":[]}' < /home/alice/bundle
```

Passed: `pact tools` lists `sys_kit`, `test_echo`, `test_peak`, `test_read`; the
second prints one line whose first text is `{"type":"outcome","outcome":"done",...}`;
the third waits, pledge asks alice (dialog and presence check), and ends `done`
or, if alice says no, `declined`. `pledge history --verify` shows the entries;
`journalctl -t probe | grep call=<uuid>` shows what ran. Today `pact call` ends
`unavailable`, because the HTTP client is not there.

## 6. Dependencies, and what I need decided

The sandbox cannot reach crates.io, so the owner fetches. The cache of the
sandbox's cargo holds the crates below as downloads that it may not unpack, so
`cargo generate-lockfile --offline` resolves them (checked: 26 packages) and a
build there does not.

**`probe serve` (p-robe), in `crates/p-robe/Cargo.toml`, `[dependencies]`:**

```
hyper = { version = "1.11", default-features = false, features = ["server", "http1"] }
hyper-util = { version = "0.1.20", default-features = false, features = ["tokio"] }
http-body-util = "0.1.5"
bytes = "1"
tokio = { version = "1", features = ["rt-multi-thread", "net", "time", "sync", "macros"] }
```

Why `hyper` and not a smaller server: the stream the service must write
(`agent-to-service.md` section 7, `pact.md` section 7) is an SSE response whose
head goes out at acceptance and with a comment line at least every 15 seconds,
for as long as the person takes, and a closed connection must be noticed at
once to cancel the call. `hyper` 1 does that with a response body fed from a
channel and notices the client's end through the body. `tiny_http` and
`httparse` alone would be a server written by hand, which was ruled out. The
resolved set (in the sandbox's cache): `hyper` 1.11.0, `hyper-util` 0.1.20,
`http-body-util` 0.1.5, `http` 1.5.0, `http-body` 1.1.0, `httparse` 1.10.1,
`bytes` 1.12.1, `tokio` 1.54.1 (with `mio` 1.2.4, `socket2` 0.6.5),
`pin-project-lite`, `futures-channel`, `futures-core`, `atomic-waker`,
`itoa`, `httpdate`, `smallvec`. Nothing for TLS: between agent and service TLS
is open for stage 2 (the decision on `approvals.md`).

**What `pact`'s client needs (p-act's choice):** an HTTP/1.1 client over TCP
(and `https` with a root later) that reads a response as it arrives (a
chunked `text/event-stream`), with an idle timeout of 45 seconds on the
read, no redirects, no proxy variables, a 4 MiB limit on the message, and that
stops when the model cancels. It is synchronous (at most 16 waiting calls, a
thread each, no runtime), which suggests `ureq` 3, which p-act's `pact.md`
names as option (e); if the owner accepts `tokio` anyway (for the broker,
`p-age`), `hyper-util`'s client would also do, at the price of a runtime in
`pact`, which holds a key. I do not decide it; p-act's document does.
**Please decide:** the line for `ureq` (or the alternative), and whether a
runtime in `pact` is acceptable.

Then I build `probe serve` on `hyper`: a listener on `listen`, each request read
with a 64 KiB limit and handed to `Mcp::serve` on a blocking thread, whose
`ResponseWriter` sends each piece into the body's channel at once; a failed send
is the client gone. The MCP layer is written for that already.

## 7. What was run, and where

All of it on one macOS machine (Darwin 25.5), in a sandbox with no network, no
root, no sudo rule, no systemd, no Linux.

- Run: `cargo test -p p-robe` with and without `--features test-verbs` (unit
  tests, including `probe setup` made twice, a renewal that fails, a signer that keeps working across a renewal, and the days left read from certificates of both key types; the CLI tests, `tests/stage1.rs` five times in a row: the real
  `pledge serve`, `pact`'s composer and signer, the service core, the dispatcher
  in this process as a simulated root). `tests/stage1_sudo.rs` **compiles**, and
  its gate works: without `PROBE_STAGE1_SUDO=1` it does nothing and passes.
  `cargo generate-lockfile --offline` resolved the dependency lines of section 6.
  `sh -n` accepted the four scripts.
- **Not run:** anything with real `sudo` or `visudo`; the rule's wildcards
  against a real `sudo`; `logger` as a Linux one; syslog or the journal; the
  scripts; `tests/stage1_sudo.rs` itself; `SudoRunner` (only its argument
  vector is unit-tested); `/proc/self/fd` (the path of an open file, Linux
  only); `SO_PEERCRED`; pledge's `service_group` with a group of its own; any
  HTTP; any unit.
- Where I am least sure: the sudoers wildcard line (that `*` matches a space
  and `????????-????-????-????-????????????` an identifier, as `sudoers(5)`
  says, but untested), `su -s /bin/sh -c` for an account with `nologin`
  (standard), and that the host keeps `auth.info` lines where `a2` looks.
