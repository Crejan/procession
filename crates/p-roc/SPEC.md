# p-roc - specification (draft)

The shared library of procession: reads, and where asked writes, what the
kernel exposes about CPUs, threads, IRQs, sockets and devices. No daemon, no
CLI, no policy. The name reads as `/proc`.

License: MIT OR Apache-2.0. Distribution: crates.io, as a dependency of
`p-usher`, `p-rover`, `p-layer` and `p-lumber`.

## Problem

The three tools read the same files. Today they do it three times: p-usher's
`procfs` and `cpuset`, clockwork's `readers` and `writers`, the Python
`aidxdiag` helpers that p-rover ports, labcommander's process and scheduler
adapters. Each copy parses `stat`, cpulists and `/proc/interrupts` a little
differently, and each has its own idea of which CPUs are isolated.

## Scope

- Synchronous. No async runtime; a caller that has one wraps calls in
  `spawn_blocking`.
- Rooted: every reader works on a `Root { proc, sys, dev }`, default `/proc`,
  `/sys`, `/dev`, so tests run on fixture trees on any OS. Writers are Linux
  only and behind a trait, so callers can test against a fake.
- Partial results instead of failure: a scan returns what it read plus a
  list of `Unreadable { source, reason }` (permission, missing file,
  missing kernel option). A task that exits mid-scan (`ENOENT`, `ESRCH`) is
  skipped silently.
- Typed errors (`thiserror`) in the public API, no `anyhow`.
- Dependencies kept small: `libc`, `serde`, `thiserror`, `regex` (for
  `describe`). No `procfs` crate: the parsers are short, and owning them
  keeps the fixture tests honest.
- No policy: p-roc says which CPUs the kernel calls isolated; whether a
  thread may run there is decided by the tool.

## Modules

| Module | Contents | Source |
|---|---|---|
| `cpuset` | `CpuSet`: list format (`0-3,8`) and hex masks (`smp_affinity`, comma-separated 32-bit groups) in both directions, set algebra, ranges out, upper bound against `0-4294967295` | p-usher `cpuset`, aidxdiag `mask_to_cpus` |
| `cpus` | online, possible; `Isolation { sysfs_isolated, isolcpus, nohz_full, rcu_nocbs, irqaffinity }` from sysfs and the cmdline (flag tokens such as `managed_irq`, `domain` skipped); topology: packages, cores, SMT siblings, NUMA nodes, role per CPU (housekeeping, isolated, mixed) | p-usher `procfs`, clockwork `topology`, aidxdiag `isolation_from` |
| `cmdline` | tokens, key/value view, the RT-relevant key set | clockwork `cmdline`, aidx `rt cmdline` |
| `task` | the thread table: `stat`, `status`, `sched`, `schedstat`, `syscall`, `comm`, `cmdline`, `exe`; `Policy` (other, batch, idle, fifo, rr, deadline), RT priority, nice, last CPU, allowed set, voluntary and involuntary switches, minor and major faults, utime and stime, kthread flag, uid, gid, groups; `ThreadKind` (user, kernel, kworker, irq, softirq, ksoftirqd, rcu, migration); filtered scans (RT only reads `status` only for RT tasks, as p-usher does today); two snapshots → rates (CPU %, switches/s, migrations/s) | p-usher `procfs`, clockwork `threads`, `cpu_usage` |
| `fd` | fd table of a process: socket inodes, device paths (`/dev/vfio/*`, `/dev/uio*`, other char devices) | p-rover |
| `net` | `/proc/net/{packet,udp,udp6,tcp,tcp6,xdp}` by inode, ifindex map, interfaces with driver, PCI address, MSI IRQs | aidxdiag `packet_sockets`, `ifindex_map` |
| `irq` | `/proc/interrupts` (per-CPU counts, chip, name, devices, the named rows `LOC`, `CAL`, `RES`, `TLB`), `/proc/irq/<n>/{smp,effective}_affinity_list`, IRQ thread by comm `irq/<n>-<name>` | clockwork `irqs`, aidx `rt irq` |
| `pci` | network-class devices, bound driver, kernel bypass (`vfio-pci`, `uio_pci_generic`, `igb_uio`) | p-rover |
| `fieldbus` | interfaces matching configured globs; evidence that a fieldbus master runs (packet sockets by ethertype, sockets on fieldbus interfaces, `ec_master`/`ec_generic`, kernel-bypass binding) | aidxdiag `fieldbus_evidence` |
| `sys` | writers: thread affinity, scheduler policy and priority, nice, IRQ affinity, `mlockall`, `gettid`; behind `trait Knobs` with a fake for tests | p-usher `sys`, clockwork `writers` |
| `change` | `Change` (below), apply with a check of `from` against the live value, revert; `Ledger`: the on-disk record of applied changes and children, fsynced before each change, restored in reverse | p-rover spec, aidxdiag `Probe` |
| `describe` | one-line explanations and documentation links for thread comms, IRQ names and kernel parameters, so a report and a web page say the same | clockwork `descriptions` |
| `stats` | percentiles, log2 histograms | p-rover, clockwork |

Not in p-roc: the decision logic of p-usher, the analyses and rules of
p-rover, systemd and the web server of p-layer, the cyclictest parser (only
p-rover uses it).

### Change

```rust
enum Change {                  // each carries the value it replaces
    SetAffinity { tid, from: CpuSet, to: CpuSet },
    SetPolicy { tid, from: (Policy, u8), to: (Policy, u8) },
    SetNice { tid, from: i8, to: i8 },
    SetIrqAffinity { irq, from: CpuSet, to: CpuSet },
    SetIrqThreadPriority { irq, tid, from: u8, to: u8 },
    Ethtool { ifname, setting: EthtoolSetting, from: String, to: String },
}

enum Applied { Done, Skipped { live: String }, Gone, Failed { errno } }

impl Change {
    fn apply(&self, k: &mut dyn Knobs) -> Applied;   // Skipped when live != from
    fn revert(&self) -> Change;                      // from and to swapped
}
```

`Ethtool` needs netlink; it sits behind the feature `ethtool`, which p-usher
does not enable.

### Isolation

p-roc reports every source; it does not merge them silently. Each tool's
spec says which it uses:

- p-usher: `sysfs_isolated` (unchanged), configurable.
- p-rover: `sysfs_isolated` ∪ `nohz_full`, and the difference between live
  and declared (`isolation-drift`).
- p-layer: shows all sources; tuning checks against p-usher's allowed set.

## Users

| Module | p-usher | p-rover | p-layer |
|---|---|---|---|
| `cpuset`, `cpus`, `task`, `sys`, `change` | ✓ | ✓ | ✓ |
| `cmdline`, `irq`, `describe`, `stats` | watchdog | ✓ | ✓ |
| `fd`, `net`, `pci`, `fieldbus` | | ✓ | ✓ |

p-lumber uses `cpuset`, `sys`, `stats` and the reader for p-usher's allowed
set; it builds on macOS, so these modules must compile there (writers
return `Unsupported`).

## Extraction from p-usher

1. Move `cpuset`, `procfs` (as `task` and `cpus`), `model::{Policy,
   ThreadInfo}` and `sys` into p-roc; p-usher keeps `decide`, `engine`,
   `config`, `notify`, `throttle`, `accounts`, `log`.
2. p-usher's fixture tests for parsing move with the code. p-usher's own
   tests must pass with only their imports changed.
3. Merge clockwork's readers into the same types (its `ThreadInfo`,
   `SchedPolicy`, `ThreadType`, `CpuTopology`, `IrqInfo`); clockwork's
   `parse_cpu_list` and p-usher's `CpuSet::parse_list` become one.
4. Add the modules p-rover needs as p-rover's phases reach them.

## Versioning

0.x until all three binaries use it; semver after. The binaries depend on an
exact minor version and are released from the same workspace.

## Tests

- Every reader against fixture trees, including kernels without
  `CONFIG_SCHED_DEBUG` (no `sched` file) and without BTF.
- `CpuSet`: list and mask round trips, malformed input, bounds.
- `Change::apply` against the fake `Knobs`: done, skipped on a moved value,
  gone, failed; revert restores; the ledger survives a simulated crash
  between record and change.
- `describe`: every pattern compiles; known comms and IRQ names resolve.
