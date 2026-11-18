# p-rover / p-roc report

## Phase 1: p-roc extracted from p-usher

**Changed**
- New crate `crates/p-roc`: `cpuset` (list and hex-mask both ways, union, ranges, last, serde as list string; errors `CpuSetError`), `cpus` (online, possible, sysfs_isolated), `task` (Policy, ThreadInfo, parse_stat/status/sched, read_thread, rt_threads -> `Scan{items, unreadable}`), `sys` (writers, moved unchanged), `root` (`Root{proc,sys,dev}`, `Unreadable`, `Scan`), `error`.
- p-usher depends on p-roc. `cpuset`, `sys`, `model::{Policy,ThreadInfo}` are re-exports; `procfs::ProcFs` wraps `Root`, keeps its anyhow API and logs unparsable tasks as before. p-usher test files and `main.rs` are untouched.
- Changes behaviour for callers: `CpuSet::parse_list` / `FromStr` return `CpuSetError`, not `anyhow::Error` (p-usher converts with `?`). `parse_stat/status/sched` return `p_roc::Error`.
- A task whose `status` is missing is treated as exited (ENOENT) and skipped silently, as in p-usher.

**Not moved yet (later phases):** `trait Knobs`, `Change`, `Ledger`, `describe`, `stats`, `Isolation` (with cmdline sources), clockwork merge (clockwork is not in this repo).

**Verified**
- `cargo test --workspace --offline`: all ok, no failures (p-roc 5 unit + 2 integration, p-usher 8 + 6 + 10 + 10).
- `sh -c 'umask 002; cargo test --offline -p p-roc -p p-usher'`: ok.
- `cargo clippy --workspace --all-targets --offline`: no warnings in p-roc; 2 `collapsible_if` warnings in `p-usher/src/main.rs` (lines 57, 72), existing, file untouched.
- NOT RUN: `p-usher/tests/linux_rt.rs` is cfg-gated to Linux (0 tests here). Linux-only code in p-roc: `sys.rs` `mod imp` for linux (moved unchanged from p-usher), never compiled here.

**Manifest lines for the orchestrator:** workspace member `"crates/p-roc"` (added in my worktree); p-usher `p-roc = { path = "../p-roc" }`; p-roc deps `libc 0.2`, `serde 1` (derive), `thiserror 2`, dev `serde_json 1`, `tempfile 3`. `Cargo.lock` changed by cargo.

## Phase 2: static observe subcommands

**Built** (`prover <sub> [--format text|json] [--output F] [--config F]`; hidden `--proc-root --sys-root --dev-root --etc-root --boot-root` to read a copied tree):
`procs [--max]`, `sched [--cpus] [--duration] [--max]`, `irq [--duration] [--top]`, `cmdline`, `nic <if> [--delta D] [--all-stats]`, `serial`, `clock`, `lastboot [--boot]`, `hung [--all] [--duration] [--stack-lines] [--max]`, `analyze --pid P [--tid T]... --static`. Without `--static`, `analyze` is refused (exit 4): tracing is phase 3.
JSON: one object, members as the SPEC, records tagged `type`, fields in struct order, goldens in `crates/p-rover/tests/golden/`. Exit codes 0/1/2 results, 3 failed, 4 refused/usage (clap usage errors too).
p-roc gained `cmdline`, `irq`, `net` (interfaces, statistics, packet/udp/tcp/xdp tables), `pci`, `fd`, `change` (data model and `revert`, no `apply`), and in `task`: full scan, sched counters, syscall, vm, comm lookup.

**Verified** (this worktree, merged with `integration` 1ac8d0d)
- `cargo test --offline -p p-roc -p p-rover -p p-usher`: all pass, under umask 022, 002 and 077. p-roc 18, p-rover 54 (12 unit + 42 integration over fixture trees), p-usher unchanged 34.
- `cargo clippy --workspace --all-targets --offline`: no warning in p-roc, p-rover, p-usher.
- `cargo test --workspace --offline` fails only in p-ledge `broker_tls_tests` (7 tests: `Settings(Invalid("missing field v"))`). It fails the same on a clean checkout of `integration` 1ac8d0d, and with p-rover's p-act feature removed, so it is not from this branch.

**Not verified**
- No real `/proc`, `/sys`, `/dev` was read: every parser (interrupts, stat, schedstat, mounts, /proc/net/*, ethtool, chronyc, journalctl) is tested on fixtures I wrote from the documented layouts. /proc/net/xdp matching is a guess (any column equal to a socket inode).
- ethtool parsers and the JSON key names are **not yet checked against a capture**; the commands to capture are in the runbook.
- Thresholds chosen by me: tick finding above 2 x CONFIG_HZ, busy at 90 % run time, polling above 10 000 voluntary switches/s (SPEC), `hung-tasks` Crit at 5 tasks or an NFS/RPC wait for the whole window else Warn, `two-clock-masters` Warn, `irq` flags (effective on isolated and moved) or mask drift.
- Linux-only code blocks: none new. `p-roc/src/sys.rs` `mod imp` (linux) is unchanged and still never compiled here.

**Decided without the SPEC saying**
- `procs`: RT threads first, then by tid; no `pcpu`; `--max` (80) and 100-finding cap. `irq`: caps 100 flagged records and findings. `sched --max` 60.
- `cmdline`: declared = `GRUB_CMDLINE_LINUX` then `_DEFAULT` (grub's order); drift ignores live-only tokens, as the Python verb did. `isolation-drift` compares live (sysfs isolated + nohz_full) with declared (isolcpus + nohz_full).
- `nic`/`analyze` coalescing, EEE and queue findings only for interfaces matching `fieldbus_interfaces` (all when none configured). Their `changes` are empty: p-roc has no `Ethtool` change variant yet.
- `stale-probe` looks for `<ledger_dir>/<id>/plan.json` without a `restored` file; the ledger format is phase 4's.
- Config is read by `p_act::settings::read_toml` (owner, mode, unknown keys refused; the probe sections are modelled and unused). Tests set mode 0644 on config files themselves.
- `SystemRunner` runs programs by absolute path (looked up in /usr/sbin, /usr/bin, /sbin, /bin), cleared environment except LC_ALL=C, timeout, 1 MiB output cap.
- `analyze --static` cannot do: thread classes, hollow-spin, deadline-miss, helper-on-rt-core (need tracing), unbound packet sockets (counted as unresolved), faults per activation. `relative-sleep` is one snapshot of the `syscall` file (x86_64 and aarch64 numbers).

**Changes a shared dependency's features:** none. p-rover enables `raw_value` on serde_json (p-act already does) and `toml` on p-act (off by default; adds p-act's own toml code to other users of p-act, nothing else).
**New dependencies** (all unpacked, for the owner): clap 4 (derive), globset 0.4, humantime 2; dev tempfile. toml no longer a direct dependency.
**Sizes** (estimates, not measured on a big host): `procs` at most about 80 thread records x 0.3 KB + 100 findings x 0.9 KB = 115 KB; `irq` at most about 120 flagged/shown records x 0.35 KB + 100 findings x 1 KB + one timer record (one entry per isolated CPU) = 150 KB; 1 MiB is not reachable.

**Needs from you:** the ethtool captures (runbook), the owner's word on clap/globset/humantime, a decision when you want `apply`/`Ethtool` changes (phase 5).
