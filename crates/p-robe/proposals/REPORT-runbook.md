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
