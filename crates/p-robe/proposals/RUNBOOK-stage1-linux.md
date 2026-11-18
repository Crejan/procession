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
| `probe setup` (the service's key and its 30-day certificate from the host key; **the same command renews**: it keeps the key, replaces the certificate by a rename; with no arguments it takes `/etc/probe.json` or the defaults) | built, run on macOS with a throwaway host key |
| the daily renewal timer and its unit (`stage1/probe-setup.service` and `.timer`, running `probe setup --if-due`) | written, **never run** (no systemd here); `systemd-analyze verify` is the first check |
| `sys kit` reports the certificate's days left (a warning under 5) | built and tested on macOS with certificates made by `ssh-keygen -V` |
| `probe serve`: the service core (checks, request, wait, approval, run), the MCP layer | built; run in-process against the real pledge (`tests/stage1.rs`) |
| `probe serve` over HTTP (`hyper`) | **built** (`src/http.rs`), tested over memory and over a Unix socket; **never run over TCP** (no port can be bound in the sandbox) |
| `pact` composer, signer, catalogue, `pact call` / `pact tools` | built (p-act) |
| `pact`'s HTTP client | p-act's, `ureq` 3 (`pact::http::HttpTransport`), merged; its socket tests never ran over a real socket either |
| the cross run through `SudoRunner` | **written, not run:** `tests/stage1_sudo.rs` |
| the cross run over real HTTP with the real `pact` | **written, not run:** `tests/stage1_http.rs` (needs a TCP port and `pact`'s client) |
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
  cargo build --workspace --features p-robe/test-verbs,p-act/pact
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
  probe-svc ALL=(root) NOPASSWD: /usr/local/bin/probe --within [a-z]*\,[a-z]*\,[a-z]* --call ????????-????-????-????-???????????? --until [0-9]* [a-z]* [a-z]*
  ```
  It lets `probe-svc` run `/usr/local/bin/probe` as root in one form: `--within
  <rating> --call <uuid> --until <seconds> <noun> <verb> [arguments]`. Sudoers wildcards match
  anything, spaces included, so the rule alone does not limit the words: the
  dispatcher refuses what is not a verb of its table (`run command` among it),
  and anything whose own rating is above the rating after `--within`. **The
  account can, through this rule, run every verb of the table** (the designer's
  decision, `crates/p-robe/SPEC.md`); what holds it back is the service's checks,
  not sudo. The rule is checked with `visudo -cf` before it is put in place.
- **The rule's characters, checked against `sudoers(5)`.** In command arguments sudoers
  wants `,` `:` `=` and `\` escaped (a comma separates commands in a list); the rule has
  commas in the rating, written `\,`. Its other characters need nothing: `*` any string
  (spaces included), `?` any one character, `[a-z]` and `[0-9]` one character of the range,
  `-` and the spaces literal. **Confirmed on Debian 13 (the owner's run of 2026-11-18):** `visudo -cf` accepts the `\,` form (the
  first form, with plain commas, was refused: `expected a fully-qualified path name`), and `sudo` matched a real
  invocation of this form including `--until`. **That is all that is shown:** the dispatcher that ran refused
  that call at its `--until` check, which comes after its root check, so it ran as root under `probe-svc`; but
  **no verb has yet run as root through the rule** (the next run shows it). `a1` checks the rule with `visudo -cf`
  before it changes anything.
- **What the wildcards match, and what they do not pin.** `[a-z]*` is not "letters": it is one
  letter followed by **anything**, spaces included, and so is every `*` slot (the rating, the
  digits after `--until`, the noun and the verb). The rule pins only the prefix shape: the
  path, `--within` and a first letter, the two commas somewhere after it, `--call` with 36
  characters of the shape of an identifier, `--until` and a digit, then two more
  space-separated words. It does **not** pin that the rating is three known words, that the
  number is a number, or that no more flags follow. The dispatcher covers all of it, because it
  parses the flags itself, from the first argument, each at most once with its value
  checked (the rating against the table of words, the identifier, the number), then reads a
  noun and a verb that must be a row of the table and arguments of the argument class, and
  refuses anything starting with `-` after the flags; sudo joins the arguments with single
  spaces and matches that string, but the dispatcher sees the separate arguments, so a
  single argument that contains spaces and imitates several is refused (a rating with spaces
  is not a rating; an argument with a space is not in the class). I found no way to match the
  rule and be read by the dispatcher differently from what the rule appears to say; the
  checks of A2 and the dispatcher's tests ("nothing that starts with a dash gets past the
  flags", ten shapes, and the `--until` shapes) cover the cases I could think of. **A tighter
  rule is possible** with a regular expression (`^...$` in the arguments, where no
  escaping is needed): for example `^--within (open|internal|secret),(none|recoverable|lasting),(none|brief|outage)
  --call [0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12} --until [0-9]{1,11}
  [a-z][a-z0-9-]* [a-z][a-z0-9-]*( [^ ]+)*$` (all on one line) parses with `visudo -cf` on the
  author's macOS. It is not used: the designer's decision is the wildcard form; it is here to
  choose from if the rule is to say more.
- **The lock and the deadline.** `--call` is the waiting form: the dispatcher
  waits up to 10 seconds for the one lock of the calling identity (`probe-svc`:
  one call at a time) instead of failing at once, so that a call the person has
  approved does not fail because another is finishing. `--until <seconds>` is the
  call's deadline, passed by the service: **seconds since the epoch, UTC, the deadline to the second,
  unchanged** (never a later time); the dispatcher refuses one more than 10 minutes ahead of its own
  clock (660 seconds: ten minutes with the 60 seconds of tolerated clock difference applied, as the service
  applies it), so that the flag cannot park a root process for long: the wait is cut at it, and **the verb is
  not started at or after it** (the dispatcher decides that itself, after it holds
  the lock, by its own clock; exit 76, `event=expired`, the service tells the agent
  `expired`). Still held after the wait: exit 75, `event=busy ... waited=10.00s`,
  `refused / try-later`. The waiting form exists only with `--call`; `--until`
  is refused without it; by hand, without either flag, a busy lock is immediate.
  **This is why the rule has `--until`**: without it the dispatcher cannot know
  the deadline, and the service cannot stop a root process that has not started
  its verb yet (it can signal only its own `sudo`, and not at the right moment).
  The rule's line is therefore one pattern longer than it was.
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
| Stage B only: `/etc/probe/` (service key and certificate), `/etc/probe.json`, the units `probe-serve.service`, `probe-setup.service` and `probe-setup.timer`, pledge's state in your home, a TCP port on 127.0.0.1 | Stage B steps | the undo lines of Stage B |

`undo.sh` is safe to run at any time and does nothing to what is not on this list.

## 4. Stage A: the sudo part, today

The scripts are in `crates/p-robe/proposals/stage1/`. Run them as root, from a
terminal, **one at a time, in this order, and read the last line of each before
the next**: each prints `PASS:` or `FAIL:` lines and ends with `ALL PASSED` or
`SOMETHING FAILED`, or with `STOP:` and one line when it cannot go on. Do not run a
script after one that did not end well: the next one tells you so (`a2` refuses to
check anything unless a1 passed), but a wrong order would only confuse the output.

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
| `sudo -n /usr/local/bin/probe sys kit` (no flags), and the form without `--until` | exit 1: sudo itself refuses, the form is not in the rule |
| `--until` more than ten minutes ahead | exit 64: refused, so that it cannot park a root process |
| `--until 1` (a deadline already past) | exit 76: the verb is not started |
| the lock held by someone else for 3 seconds (`flock`, as root), then a call with `--call` | exit 0: it waited and ran; its syslog line says `waited=` about 2 seconds |
| the lock held for 6 seconds and the deadline 2 seconds away | exit 76 after about 2 seconds: the wait is cut at the deadline and the verb is not started (`event=expired`) |
| `sudo -n /bin/true` | exit 1: no other program is in the rule |
| the audit lines | syslog has `event=start` and `event=done` with `call=<uuid>` for the call that ran, `event=refused ... above-approved` with `call=<uuid>` for the one that was refused, `event=expired` for the two that ran out of time |

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

`probe serve` now listens (`hyper`; the owner fetched the crates, section 6).
`pact`'s HTTP client is merged too (p-act's): all of B1 to B5 can be followed. Nothing of Stage B has been run on Linux, and the
HTTP transport has never been run over TCP by its author.

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
with that group. **Only after the `pledge: serving.` line (see below)** make the three keys, answering the dialogs it prints:
`pledge keys create delegation`, `... confirmed`, `... automatic`. Then
`pledge keys list --format json` shows the public key lines; write the confirmed
one to `/etc/probe/alice-confirmed.pub` and the automatic one to
`/etc/probe/alice-automatic.pub` (root, 0644).

**Wait for `pledge: serving.`** on its output before anything else: it binds `agent.sock`, `control.sock`
and `service.sock` one after another and prints that line only after all three. A `pledge keys create`
or `pledge agents start` in the gap fails with `pledge serve is not running (no answer on its control socket)`
though nothing is wrong: run it again once the line is there. Keep `pledge serve` in a terminal of its own (its
dialogs are answered there). Passed: the line `pledge: serving. SSH agent socket: ...`, and `ls -l
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

### B3. `/etc/probe.json`

One JSON object, mode 0644 or 0640, owned by root or by the user that runs the program (**a file that its group or
anyone else can write is refused**, and so are an unknown member, a member given twice, trailing
text and a byte order mark; the reading is `p_act::settings`'s, the same for all programs):

```
{
  "host": "HOSTNAME",
  "host_key": "/etc/ssh/ssh_host_ed25519_key",
  "person": "alice",
  "confirmed_key": "/etc/probe/alice-confirmed.pub",
  "automatic_key": "/etc/probe/alice-automatic.pub",
  "service_key": "/etc/probe/service-key",
  "pledge_socket": "/run/user/1000/pledge/service.sock",
  "pledge_uid": 1000,
  "used_dir": "/var/lib/probe/used",
  "listen": "127.0.0.1:8765",
  "probe": "/usr/local/bin/probe"
}
```

(`max_waiting`, default 16, is the only other member.) `probe setup` and `probe
sys kit` read it too: `setup --if-due` for the key path and the host key, `sys kit` for
the certificate's path. Passed: `probe serve --config /etc/probe.json` gets as far as
`probe serve: for alice, pledge reachable`. Did not pass: `probe serve: /etc/probe.json:
...` with the reason (`can be written by someone other than its owner`, `owned by user N, who is neither root nor the
user running this program`, `unknown field ...`, `missing field `confirmed_key``).

### B4. Start `probe serve` as `probe-svc`

```
sudo -u probe-svc /usr/local/bin/probe serve --config /etc/probe.json
```

It builds the service, says whether pledge is reachable, and **listens on `listen`**
(`probe serve: listening on 127.0.0.1:8765`); HTTP/1.1 only, one request per
connection, MCP at `POST /mcp`. Passed: that line, and from another shell
`curl -s -X POST -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream'
-d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' http://127.0.0.1:8765/mcp` prints the tools (`sys_kit`,
`test_echo`, `test_peak`, `test_read`) with the rating in each description. Did not pass:
`cannot listen on ...` (the port is taken or the address is not the host's), or an exit 64 with the
settings problem. **The HTTP transport has never been run over TCP by its author** (no port can be bound
in the sandbox): it is tested over memory and over a Unix socket (`hyper`, the stream with its head at
acceptance and its keepalive comments, a client that goes away cancelling the call). A failure here that
those tests did not show is a finding.

As a unit, `/etc/systemd/system/probe-serve.service` (`stage1/probe-serve.service`):

```
cp stage1/probe-serve.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now probe-serve.service
systemctl status probe-serve.service
```

**In an LXC container (Proxmox).** The unit has **no sandboxing lines** on purpose.
`ProtectSystem=`, `ReadWritePaths=`, `PrivateTmp=` and `ProtectHome=` need mount
namespaces, which an unprivileged container gives to its units only with nesting
(`features: nesting=1` in the container's configuration; without it the unit fails
with `status=226/NAMESPACE`). **Dropped for that reason: all four.** The unit does not
set `NoNewPrivileges` (it must stay off: the dispatcher is run through sudo); `User=probe-svc`
and `Restart=on-failure` are plain and work anywhere. If the container has nesting on,
`stage1/probe-serve-hardening.conf` (copy it to
`/etc/systemd/system/probe-serve.service.d/hardening.conf` and `systemctl daemon-reload;
systemctl restart probe-serve`) adds them back. The same holds for `probe-setup.service`
(`stage1/probe-setup-hardening.conf`). Other things a container changes: `sudo`, `su`, `useradd`,
`logger` and journald behave as on a host; pledge's `service_group` needs the group to exist
inside the container; the sockets are Unix sockets inside it; `/etc/ssh/ssh_host_ed25519_key` is the
container's own host key (a container made by cloning has the host key of the template until
`ssh-keygen -A` is run after removing them: do that first, or the key that certifies the
service is shared with the template). Passed: `status` shows `active (running)`. Undo:
`systemctl disable --now probe-serve; rm /etc/systemd/system/probe-serve.service;
rm -rf /etc/systemd/system/probe-serve.service.d; systemctl daemon-reload`.

### B5. An agent and a call

As `alice`: `pledge agents start --groups admins --output /home/alice/bundle` (answer the dialog).
Then, as the user the agent runs as (the bundle is the agent's key: guard it):

```
pact tools < /home/alice/bundle
pact call test_echo '{"params":["hello"]}' < /home/alice/bundle
pact call test_peak '{"params":[]}' < /home/alice/bundle
```

Passed: `pact tools` lists `sys_kit`, `test_echo`, `test_peak`, `test_read`; the second prints one line
whose first text is `{"type":"outcome","outcome":"done",...}`; the third waits, pledge asks alice (dialog and
presence check), and ends `done` or, if alice says no, `declined`. `pledge history --verify` shows the
entries (`received` then the answer for the asked one); `journalctl -t probe | grep call=<uuid>` shows what
ran. **This needs `pact` with its HTTP client**, which is p-act's (`pact::http::HttpTransport`, `ureq` 3, merged): the
`pact` binary is built only with p-act's `pact` feature, which is why the build command above names it
(`p-act/pact`; for `https` between agent and service, stage 2, `p-act/pact-tls`). `pact call TOOL ARGUMENTS < bundle`
prints the normalised result on one line. By its report it sends `Accept: application/json, text/event-stream`, `Content-Type: application/json`,
`MCP-Protocol-Version: 2025-06-18` and no `Origin`, reads the stream as it arrives with its 45-second idle
timeout, reads the stream as it arrives with a 45-second idle timeout per read (no total limit), does not follow redirects,
reads no proxy variables, and takes `http` only on loopback (`https` needs `pact-tls`): all of which the runbook's
bundle (`http://127.0.0.1:8765/mcp`) satisfies. **Not yet shown by anyone: that `ureq`'s chunked decoding hands the
stream over piece by piece** (the head at acceptance, the comments every 15 seconds). Its own socket tests skipped
themselves in the sandbox, as mine did; if a call hangs until the deadline instead of returning, look there first.

**The same, as a test.** `tests/stage1_http.rs` runs the real `pledge serve`, this crate's HTTP transport on a
TCP port in the test process, and the real `pact` binary for each call; with `PROBE_STAGE1_SUDO=1` the verb is
run through the sudo rule as in Stage A. It is ignored and gated:

```
cargo build --workspace --features p-robe/test-verbs,p-act/pact
PROBE_STAGE1_HTTP=1 cargo test -p p-robe --features test-verbs --test stage1_http -- --ignored --nocapture
```

(or, through the rule, built as in A3 and run as `probe-svc` with both variables set.) Passed: `PASSED: the real
pact called the real probe over HTTP`, and the four calls `test_echo`, `test_peak` (asked and confirmed),
`test_peak` declined, `sys_kit` match pledge's record. Did not pass: the first assertion that failed, with the
service's log; `a TCP port can be bound here` means the port (`PROBE_STAGE1_PORT`, default 18765) is not
available; `pact: ...` is `pact`'s own message. **Never run by its author**: no TCP port and no `pact` HTTP
client here.

## 6. Dependencies

Fetched by the owner (the sandbox cannot reach crates.io). For `probe serve`, in
`crates/p-robe/Cargo.toml`: `hyper` 1 (`server`, `http1`), `hyper-util` 0.1 (`tokio`),
`http-body-util`, `bytes`, `tokio` (`rt-multi-thread`, `net`, `time`, `sync`, `macros`);
the lock pins `hyper` 1.12.0 and `hyper-util` 0.1.21. `tokio`'s `io-util` is a
dev-dependency only, for the in-memory streams of the tests. No TLS crate: between
agent and service TLS is open for stage 2. `pact`'s client is p-act's: `ureq` 3, no runtime.

## 7. What was run, and where

All of it on one macOS machine (Darwin 25.5), in a sandbox with no network, no
root, no sudo rule, no systemd, no Linux.

- Run: `cargo test -p p-robe` with and without `--features test-verbs` (unit
  tests, including `probe setup` made twice, a renewal that fails, a signer that keeps working across a renewal, and the days left read from certificates of both key types; the CLI tests, `tests/stage1.rs` five times in a row: the real
  `pledge serve`, `pact`'s composer and signer, the service core, the dispatcher
  in this process as a simulated root). `tests/stage1_sudo.rs` **compiles**, and
  its gate works: without `PROBE_STAGE1_SUDO=1` it does nothing and passes.
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
