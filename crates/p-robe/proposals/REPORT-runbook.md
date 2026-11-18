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
