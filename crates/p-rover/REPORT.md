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

## Unit: strings read from the host (audit for `p_ermit::text`, no behaviour changed)

What `prover` does today: **no string read from the host is checked against a character rule.**
- JSON (`--format json`): serde escapes C0 controls (`\u001b`) and quotes, but passes bidirectional marks (U+202A-202E, U+2066-2069) and other format characters through as raw UTF-8.
- Text (`render::scalar`, `render::text`): a record string containing a space is printed with Rust `{:?}` (escapes control characters; I did not verify it for bidi marks); **a string without a space is printed raw**, so an ESC or a bidi mark in a comm or interface name reaches the terminal. `unreadable` lines (`source`, `reason`) and the header host name are printed raw.
- A string that is not UTF-8 makes the whole `/proc` file unreadable (`read_to_string`), so the thread is listed in `unreadable` and skipped; command lines (`task::cmdline`) and tool output are converted lossily.

Places where host-controlled text enters the output (all in `crates/p-rover/src`):
- thread `comm` (any user can set it with prctl): `observe/procs.rs`, `sched.rs`, `hung.rs`, `analyze.rs` (thread records, findings subjects), IRQ thread comm in `nic.rs`/`analyze.rs`.
- process command lines and `exe`/`cwd` links (set by whoever runs the process): `observe/clock.rs` (`cmdlines`), `serial.rs` (getty `cmdline`), `hung.rs` (`exe`, `cwd`, `mount`), `analyze.rs` (`exe`).
- kernel and driver names: IRQ action and `/proc/interrupts` names (`irq.rs`, `nic.rs`, `analyze.rs`), interface names and MAC address, driver names, PCI ids, `wchan` and kernel stack frames (`hung.rs`), module/tty names (`serial.rs`), sysctl values (`cmdline.rs`, `lastboot.rs`), workqueue cpumask (`irq.rs`).
- the live and declared kernel command line, bootloader assignments (`observe/cmdline.rs`).
- external tool output: `chronyc` fields and sources (`clock.rs`), journal lines and boot list (`lastboot.rs`: kernel and userspace messages, attacker-influenceable), the first line of an ethtool or chronyc error (`ethtool_cli.rs`, `lastboot.rs`, into `unreadable.reason`), ethtool driver strings and counter names (`ethtool_cli.rs`).
- `report.host` (hostname) and every `unreadable.source`/`reason` built from OS error texts (all subcommands).
Arguments given by the caller are validated before use (`nic` interface names to `[A-Za-z0-9._-]`, `lastboot --boot` to digits).

## Unit: escaping every string from outside

Built as agreed (flag `escaped`, `clipped`, top-level `escaped_records` and `clipped_records`, finding `odd-characters`, bounds as proposed). **Changes behaviour for callers:**
- Members added: `escaped_records`, `clipped_records` (top level); `escaped`, `clipped` (on a record or finding that needs them, absent otherwise); finding `odd-characters` (info). Findings and `unreadable` are written after the rule; findings are now one compact line each in the pretty JSON; goldens re-made.
- A backslash in a host string is now doubled (`\\`); control and direction characters show as `\u{..}`; bytes that are not UTF-8 show as `\x{..}`.
- Changes behaviour: a thread whose comm is not UTF-8 is no longer `unreadable` and skipped: every `/proc`, `/sys` file and link target is read as bytes (`p_roc::text::read_to_string`, `from_os`, `from_bytes`), invalid bytes carried as private-use stand-ins U+10F700+byte until the output stage escapes them. A genuine character in U+10F700..U+10F7FF would be shown as a byte; none is known to occur.
- Text output: values with a space or quote are in double quotes (no longer Rust `{:?}`); no string is printed raw; findings are rendered from the escaped JSON.
- Where enforced: `sanitize::json` over each record at `Report::push`, and `Report::sanitize` (called by `observe::finish`) over the host name, `unreadable` and findings; so a new record type or a forgotten field is covered. Bounds count characters of the escaped text (`escape_bytes_clipped`); `full_len` in `clipped` is bytes of the host string.
- Test: `tests/hostile.rs` feeds U+0085, U+009B, U+202E, ESC, DEL and a byte 0xff through comm, command lines, cmdline, sysctl, IRQ and interface names, tty type, chronyc, journalctl, ethtool and a tool's stderr for every subcommand (procs, sched, irq, cmdline, nic, serial, clock, lastboot, hung, analyze), text and JSON, with one `assert_clean`; mutating the sanitizer makes it fail (checked).
- Not covered by that test: `nic --delta` counter names and `analyze` kernel-bypass names beyond those fed; they pass through the same `Report::push`. The unit of the bound (characters of escaped text) differs from the bytes I first proposed, stated in the SPEC.
