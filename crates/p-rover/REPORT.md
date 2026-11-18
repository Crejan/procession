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
