# Report: the runbook for stage 1 on Linux

Commit on `agent/p-robe` (after `git merge integration`, 43d175d). Files:

- `crates/p-robe/proposals/RUNBOOK-stage1-linux.md`: the runbook, in two stages.
- `crates/p-robe/proposals/stage1/a1-prepare.sh`, `a2-check-rule.sh`,
  `a3-run-cross.sh`, `undo.sh`: the scripts of Stage A.
- `crates/p-robe/tests/stage1_sudo.rs`: the cross run with `SudoRunner`
  instead of `InProcess`, `#[ignore]`d and gated by `PROBE_STAGE1_SUDO=1`.
- `crates/p-robe/tests/common/mod.rs`: what `stage1.rs` and `stage1_sudo.rs`
  share (moved out of `stage1.rs`, which is unchanged in what it does).

## What exists, what does not

Stage A (the sudo part, the dispatcher as root, the audit lines, the whole
cross run with the verb through sudo) is written and runs **today** on a Linux
machine; the HTTP hop between `pact` and `probe` stays in the test process.
Stage B (pledge as the person, `probe serve` as its own account, `pact`, real
HTTP) is written with the commands the programs have, and marked **needs HTTP**
where it cannot run: `probe serve` does not listen, and `pact` has no HTTP
client. `probe serve --config` can already be run and says whether pledge's
socket is reachable for the account.

## Decision for you: the dependencies

For `probe serve`, in `crates/p-robe/Cargo.toml` `[dependencies]` (there is no
workspace dependency table; the lines go into my crate's manifest):

```
hyper = { version = "1.11", default-features = false, features = ["server", "http1"] }
hyper-util = { version = "0.1.20", default-features = false, features = ["tokio"] }
http-body-util = "0.1.5"
bytes = "1"
tokio = { version = "1", features = ["rt-multi-thread", "net", "time", "sync", "macros"] }
```

`hyper` because the service must stream SSE with the head at acceptance and a
comment at least every 15 seconds, and must notice a closed connection; a body
fed from a channel does both. These lines resolve offline in a scratch project
(`cargo generate-lockfile --offline`: 26 packages: hyper 1.11.0, hyper-util
0.1.20, http-body-util 0.1.5, http 1.5.0, http-body 1.1.0, httparse 1.10.1,
bytes 1.12.1, tokio 1.54.1, mio 1.2.4, socket2 0.6.5 and a few small ones);
building them here fails at unpacking (`Operation not permitted` under
`~/.cargo/registry/src`), as before. No TLS crate is needed for stage 1.

For `pact`'s client I know only the requirement (p-act's decision, its option
(e)): synchronous HTTP/1.1, response read as it arrives (chunked SSE), a 45 s
idle timeout, no redirects, no proxy variables, a 4 MiB limit, stops on cancel.
`ureq` 3 fits (no runtime in the program that holds a key); `hyper-util`'s client
would need a runtime in `pact`. Not decided by me.

## What was run, and where

Everything on one macOS machine in the sandbox: no Linux, no root, no sudo, no
systemd, no network.

- **Run:** `cargo test -p p-robe`, with and without `--features test-verbs`
  (unit, CLI, `stage1` after the refactor to a shared module: passes);
  `stage1_sudo` compiles and its gate works (without the variable it prints
  that nothing ran and passes); clippy and fmt clean; `sh -n` on the four
  scripts; `cargo generate-lockfile --offline` on the dependency lines.
- **Not run:** `visudo`, real `sudo`, the sudoers wildcards, `logger`, syslog or
  the journal, the four scripts, `stage1_sudo` itself, `SudoRunner` (only its
  argument vector is unit-tested), Linux-only code (`/proc/self/fd`,
  `SO_PEERCRED`), pledge's `service_group`, any HTTP, any unit. Where I am least
  sure: that sudoers `*` matches a space and `?` an identifier character as
  `sudoers(5)` says; `su -s /bin/sh` for an account with `nologin`; where the
  host keeps `auth.info`.

## Every change the runbook makes to the machine

Listed with its undo in the runbook, section 3: the account `probe-svc`,
`/usr/local/bin/probe`, `/var/lib/probe/{locks,used}`, `/etc/sudoers.d/probe-svc`
(checked with `visudo -cf` first), syslog lines (not undone), files in
`/var/tmp` and `/tmp`; and for Stage B `/etc/probe/`, `/etc/probe.toml`, a unit,
pledge's state and a group. `undo.sh` removes the Stage A changes.

## Update: `probe setup` renews, the timer, the days left (designer's decision)

- `probe setup` is now idempotent and the renewing command: it **keeps the
  service's key**, replaces the certificate (30 days) in a directory of its own
  and renames it into place, owned by the key's owner; a failed renewal leaves
  the old certificate, a failed first run leaves no key. With **no arguments**
  it takes `/etc/probe.toml` (new optional key `host_key`) or the defaults, and
  refuses a settings file that does not parse. The service reads the
  certificate on every signature (`ssh-keygen -Y sign` is given the certificate
  file), so a renewal needs no restart: tested with a `Signer` made before the
  renewal that signs with the new certificate afterwards.
- `sys kit` reports `service_certificate` and `service_certificate_days_left`
  (read from the certificate line itself, Ed25519 and ECDSA P-256), and warns
  below 5 days, and at 0 or less says it has ended; never a problem by itself.
- The timer: `stage1/probe-setup.service` (oneshot, root, `probe setup`) and
  `stage1/probe-setup.timer` (`OnBootSec=10min`, `OnUnitActiveSec=20d`, a random
  delay up to an hour). In the runbook with how to start it, what passing and
  failing look like, how to see the warning, and how to undo it.
- Tests added (134 unit with `test-verbs`, 128 without; all targets pass, clippy
  and fmt clean): setup made twice, key kept, certificate new, no leftover;
  a failed renewal and a failed first run; `--no-args` defaults; the days left
  for both key types and for ended ones; the warning thresholds. Not run: the
  timer and the units (no systemd here), anything as root.
- One thing found on the way, not a defect of the product: a lock held through
  `flock` is also held, until it execs, by a child another thread forks at that
  moment; three lock tests that dropped a lock and took it again at once were
  flaky under parallel tests and now wait up to 3 seconds for the release.

## Update: the designer's changes to the runbook

Done on `agent/p-robe` (`integration` was already merged):

1. **Top of the runbook:** a warning before section 0: a trial machine or a VM
   only; with the test-verbs build and the rule in place `probe-svc` can read any
   file as root through `test read`, and only a person's approval stands in the way.
2. **`a1-prepare.sh`** refuses if `/var/lib/probe` exists, like for the rule and
   the binary, because `undo.sh` removes that directory whole (syntax checked with
   `sh -n`; not run).
3. **Getting the checkout onto the machine:** one paragraph in section 1: `integration`
   is a local branch, nothing is pushed; push to a reachable remote or `git bundle
   create` / `git clone`; the owner decides. I pushed nothing.
4. **Dispatcher tests:** after `--within` and `--call`, anything further that starts with
   `-` is refused (ten shapes, with and without a second flag, `--`, a lone `-`, a
   flag after the verb); a test lists every `env::var` / `env!` in the library's
   sources and fails on a new one; and `PROBE_TEST_SANDBOX`, the one variable that
   moves the audit sink and the lock directory in a test build, is now **ignored by a
   process that is root** (`dispatch::test_sandbox`, tested), so it cannot be reached through
   sudo even if a site keeps it with `env_keep`; with the rule's `env_reset` and no
   `SETENV` it is dropped before the dispatcher starts anyway. The runbook says so
   (section 2, "The environment"). A consequence: the tests of the test build must
   run as an ordinary user, as they do.
5. **Already done in the previous update:** `probe setup` as the idempotent renewing
   command, the root timer with its undo, `sys kit` reporting the days left.

I did not add the hyper lines.

## Update: the daily timer and `probe setup --if-due`

The designer's reason: with `OnUnitActiveSec=20d` a failed run is not tried again for 20 days
and the certificate lapses. Now:

- **The timer** `stage1/probe-setup.timer`: `OnCalendar=daily`, `Persistent=true`,
  `RandomizedDelaySec=1h`; its unit runs `probe setup --if-due`.
- **`--if-due`**: does nothing and exits 0 while **more than** 10 days remain (exactly 10
  is not more); renews at 10 or fewer, including ended ones; renews at once when there is
  no key, no public half, no certificate, a certificate that cannot be read or has no end, or
  one that certifies another key than the service's (compared by key bytes). A failed renewal
  exits 1, so the unit shows failed and the next day tries again. `probe setup` by hand
  still renews always. `sys kit`'s warning under 5 days is unchanged.
- **Tests, each branch of the rule:** the pure rule (30, 20, 10 days + 1 s, exactly 10, 9, 1 s,
  0, ended; no key; no public half; no certificate; junk; another key; no end); on files with
  a real `ssh-keygen`: nothing there is made, a fresh one is not touched (bytes compared),
  11 days left is not due, 9 renews with the key kept, an ended one, a junk one and a
  missing one each renew; a changed key renews at once; a failed renewal is an error that
  keeps the old certificate; the CLI: `--if-due` twice (made, then `Not due`), by hand
  renewing always, a missing host key exits 1, a bad flag exits 64. 141 unit with
  `test-verbs`, 134 without; clippy and fmt clean.
- **Runbook:** step B2 describes the rule, the unit and timer, how to see a renewal happen
  (a certificate that ends in 9 days), pass and fail, and the undo of the timer. Not run:
  the timer and the unit (no systemd here), anything as root.
- A limit: "the key changed" is seen as a certificate for another key than the public half
  beside the private key; a private key replaced without its `.pub` is not noticed until the
  next unconditional run.

## Update: `probe serve` over HTTP, settings in JSON, units for a container

- **`probe serve` listens** (`src/http.rs`, `hyper` 1.12.0): HTTP/1.1, one request per connection, a 64 KiB request
  limit (413 above), a 10 s limit for the request head, at most 64 connections. The MCP layer runs on a blocking
  thread and writes its response piece by piece into a channel that is the response body, so the head of a stream
  goes out at acceptance and every keepalive comment goes out at once. **A client that goes away cancels the call
  at once**: `hyper` drops the response body, which sets the call's cancel flag (a failed send does the same at
  the next piece). `probe serve` binds `listen`, says so, and serves until the process ends.
- **Settings are JSON**: `/etc/probe.json`, one object, an unknown member refused, and the file refused if its group
  or others can write it (`config::Config::load`, `read_checked`). The TOML reader is gone; `probe setup`,
  `setup --if-due`, `sys kit` and `probe serve` all use it. Runbook B3 has the file.
- **Container (LXC on Proxmox):** `stage1/probe-serve.service` and `probe-setup.service` have **no sandboxing lines**
  (they need mount namespaces: nesting in an unprivileged container, else `status=226/NAMESPACE`). Dropped:
  `ProtectSystem`, `ReadWritePaths`, `PrivateTmp`, `ProtectHome`. `NoNewPrivileges` stays off for the service (sudo).
  `probe-serve-hardening.conf` and `probe-setup-hardening.conf` are optional drop-ins for where they work. The
  runbook also warns that a cloned container carries its template's SSH host key, which is what certifies the
  service's key.
- **Tests (no port bound):** over an in-memory stream: a plain answer, 403, 405, 413, a refusal of what is not HTTP,
  the header timeout (a client that sends no head is dropped), the stream head at acceptance (before an approval that
  takes 1.2 s) with at least five keepalive comments and no silence over 0.5 s on the wire, no progress notice; a
  client that disconnects while the call waits cancels it at pledge within seconds although the keepalive is 15 s and
  nothing runs; over a **Unix socket through the accept loop**: two calls at once and a clean shutdown. Settings:
  JSON parsing, every refusal, the permission rule for seven modes, a missing file, a directory. 147 unit with
  `test-verbs`; clippy and fmt clean.
- **Never run over TCP.** `tests/stage1_http.rs` (the real `pledge`, this transport on a TCP port, the real `pact`
  binary for each call; ignored, gated by `PROBE_STAGE1_HTTP=1`, optionally `PROBE_STAGE1_SUDO=1`) compiles and its gate
  works; the sandbox allows no TCP bind and `pact` has no HTTP client here yet. It is what the owner runs on Linux once
  p-act's client is merged.
- **What I need from p-act:** a `pact` binary built with the `ureq` client by the same workspace command; `pact call
  TOOL ARGS < bundle` as now; confirmation of the headers (`Accept: application/json, text/event-stream`,
  `Content-Type: application/json`, `MCP-Protocol-Version: 2025-06-18`, no `Origin`), of reading the SSE response as
  it arrives (not after it ends) with the 45 s idle timeout, and that the head arrives at acceptance. If a failure shows
  at the seam of `ureq`'s chunked decoding and this stream, that is the first place to look.

## Update: p-act's client merged; `Hello`

- `Message::Hello` (new in p-act's exchange) is handled in `pledge.rs` as any message a service does not
  expect from pledge: the exchange ends (`Waited::Broken`, the call is `unavailable`). `c7369ab`.
  (`p-ledge` and `p-age` have their own exhaustive matches on it; not mine.)
- **`tests/stage1_http.rs` against `pact::http::HttpTransport`:** it compiles, and what it uses fits: `pact call TOOL
  ARGS < bundle` (the same `cli`), the result printed as the MCP result (`content`, which the test's `told` reads), the
  bundle's `http://127.0.0.1:PORT/mcp` (http on loopback is allowed), the headers `Accept: application/json,
  text/event-stream`, `Content-Type: application/json`, `MCP-Protocol-Version: 2025-06-18`, no `Origin` (as the MCP layer
  requires), no redirects, a 45 s per-read timeout, an SSE response read until the answer to its request id. One change in the
  commands: `pact` is built only with p-act's `pact` feature, so the build line is now `cargo build --workspace --features
  p-robe/test-verbs,p-act/pact` everywhere (runbook, tests' messages). Stage B (B5) now says the client is merged and
  names `pact-tls` for stage 2. **Not shown by anyone:** `ureq`'s chunked decoding handing the stream over piece by piece;
  p-act's socket tests and mine both skip or never ran over TCP.
- The dropped-answer invariant (`0c9ca11`) stands: tested with a valid approval of another request's bytes under another
  hash, dropped and logged; the wait goes on; only the real answer is acted on, once.

## Update: the dispatcher waits for the lock with `--call`, and the deadline is `--until`

Designer's decision, built:

- **Waiting form:** with `--call` the dispatcher waits for the identity's lock up to 10 s (`LOCK_WAIT`, polling every
  20 ms); without `--call` the immediate "busy" stays. Still held after the wait: exit 75, `refused / try-later` for the agent,
  and the busy line says `identity-busy: waited 10.00s`; every audit line of a waiting call has `waited=<secs>`.
  One call per identity at a time still holds.
- **Who enforces the deadline, and how a waiting dispatcher cannot start the verb after the service gave up:**
  the documents gave the dispatcher no way to know the deadline, and the service cannot stop a root process that is
  waiting (it can signal only its own `sudo`, with a race against the moment the verb starts). So this needed
  something the documents do not give, and **I built the proposal: `--until <seconds>`**, the call's deadline, passed by
  the service next to `--call`. The dispatcher (a) refuses at once if it has passed (exit 76, `event=expired`), (b) cuts
  its wait at it, (c) **after it holds the lock, checks the clock again and does not start the verb at or after the
  deadline**, so the decision to start is made in one place, after the lock, by the dispatcher's own clock; the service
  also starts the dispatcher only while the deadline has not passed. Exit 76 reaches the agent as `expired`, not
  `try-later` (`dispatcher-deadline`). `--until` exists only with `--call`, and only as a plain number.
- **Sudoers consequence (needs the designer's yes):** the rule's line gains `--until [0-9]*`:
  `... --call ????????-????-????-????-???????????? --until [0-9]* [a-z]* [a-z]*`. The form without `--until` is no longer
  in the rule. Updated: `a1-prepare.sh`, `a2-check-rule.sh` (all calls carry `--until`; new checks: the form without it is
  refused by sudo, a past deadline is 76, a held lock is waited for and the line says `waited=`, a deadline that passes
  while waiting is 76 and nothing starts), and runbook section 2 and the A2 table. **Not run on Linux.**
- **SPEC:** `crates/p-robe/SPEC.md` says which part enforces what.
- **Tests:** `take_waiting` (waits, times out, zero is none, a symlink or missing directory at once); the dispatcher: waits and
  says how long, no wait without `--call`, busy after the wait with the line, past deadline, deadline while waiting (the
  wait is cut at about 1 s, not 10), lock freed after the deadline (not started), a far deadline, `--until` only with `--call`
  and only as a plain number (nine bad shapes); the service: the exit codes 75/76/64/3/0 map to try-later/expired/
  not-allowed/unavailable/done, the runner is given the call's id and deadline, and a call whose dispatcher waits past the
  deadline is `expired` with no `start` line. The in-process runner's retry loop is gone (the waiting form replaces it).
  156 unit with `test-verbs`.

## Update: what `--until` is, and its bound

`--until` is seconds since the epoch, UTC, the call's deadline to the second; the service passes it unchanged (a test
compares it with the signed call's deadline, never later). The dispatcher refuses one more than **660 seconds** ahead of its own
clock (10 minutes plus the 60 seconds of tolerated clock difference, as the service applies it to a deadline; the limit is
inclusive): exit 64, `event=refused ... --until is more than ten minutes ahead`, before any wait. Tests: the pure bound at
-5, 0, 600, 660, 661, 3600; through the dispatcher at 700, 3600 and 86400 seconds; 600 runs. A2 has the check. SPEC and runbook say
what the number is.

## Update: when `pledge serve` is ready

`pledge serve` binds `agent.sock`, `control.sock` and `service.sock` in that order and prints "pledge: serving." after
all three. Found: the shared test module (`tests/common/mod.rs`, used by `stage1.rs`, `stage1_sudo.rs`, `stage1_http.rs`,
also for a restart) waited only for `service.sock`, the last one bound, which was sufficient by that order but not by
anything stated; it now waits for all three. `stage1_sudo.rs` and `stage1_http.rs` start pledge through it.
`a3-run-cross.sh` does not start pledge (the test does). The runbook's Stage B (B1) now says what the owner waits for: the
line `pledge: serving.`, and what the error in the gap looks like.

## Update: visudo rejected the rule (first run on Debian 13 in an LXC container)

- **Cause and fix (unconfirmed by a run on the target):** a comma separates commands in a sudoers list, so in arguments `,`, `:`,
  `=` and `\` must be escaped (`sudoers(5)`, "Command line arguments"). The rating's commas are now `\,`:
  `--within [a-z]*\,[a-z]*\,[a-z]*`. Every other character of the rule was checked against the man page text
  (read here, macOS sudo 1.9.x): none needs escaping. **Could I run `visudo -cf` here?** Yes, as an ordinary user on a
  file under `$TMPDIR` (mode 0440): it reproduces the owner's error on the old line (`expected a fully-qualified path name`,
  at the first comma) and says `parsed OK` for the `\,` line. That shows the syntax only; `sudo` itself was not run, so the
  matching is not shown. The runbook and `a1` mark the `\,` form as not yet confirmed on the owner's host.
- **What the wildcards match:** every `*` slot is "anything, spaces included", and `[a-z]*` is one letter then anything. The rule pins only
  the prefix shape; the dispatcher parses its flags from the first argument (each once, values checked), then a table noun and verb
  and arguments of the argument class, refusing a leading `-`, and sees separate arguments where sudo matches the joined string. I
  found no way to match and be read differently (tested in the dispatcher and by A2); a regular-expression rule that pins more
  parses with `visudo -cf` here and is in the runbook as an alternative, not used.
- **a1:** the rule is written to a temporary file and checked with `visudo -cf` **before anything is changed** (the failed run left the
  account behind); then the account, the program, the directories; the rule is installed and `visudo -c` checks the whole
  configuration, removing the rule again if that fails. Syntax checked with `sh -n`; not run.
- **a2:** stops with one `STOP:` line when `/etc/sudoers.d/probe-svc`, `/usr/local/bin/probe` or the account is absent, and
  stops after the first call (the positive control: a verb through the rule) if that did not run through it, so the refusal
  checks (`sudo -n` says the same when no rule matches as when the rule forbids) cannot pass for the wrong reason.
- **Runbook:** run the scripts one at a time and read the last line of each (section 4).
