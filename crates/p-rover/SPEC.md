# p-rover - specification (draft)

A rover for realtime Linux hosts: one toolkit for diagnosing realtime
behaviour - threads, scheduling, IRQs, NICs, fieldbus cycles, clocks, boot
configuration - and, as its flagship, `analyze`, which explores one running
process and reports how its parts work together per cycle and what to
change. Binary `prover`. Part of procession: p-usher enforces where RT
threads may run, p-layer starts and tunes processes and shows p-rover's
findings, p-roc is the shared library.

License: MIT OR Apache-2.0. Distribution: crates.io (`cargo install p-rover`).
The crate is a library and a binary: p-layer calls `analyze` and the rule
engine in-process.

## Problem

Users of realtime hosts rarely know which of their threads is the cyclic
one, which NIC queue and IRQ thread their frames travel through, on which
CPU that IRQ runs, or that their loop spins on `-EAGAIN`. The kernel exposes
all of it (procfs, sysfs, tracepoints); the tools that read it are scattered
(ps, ethtool, tcpdump, bpftrace, cyclictest, chronyc, journalctl), each with
its own output and none that puts it together for one process.

## Scope

- **One binary, subcommands.** Every diagnostic is a subcommand with the
  same conventions (output, modes, exit codes). `analyze` is built from the
  same collectors the single subcommands use.
- **Standalone.** No dependency on any site tooling. Site specifics
  (expected IRQ masks, fieldbus interfaces, a loopback pair, probe limits)
  come from a config file, never from code. A site wrapper (e.g. an admin
  diag framework) calls p-rover with `--format json` and adds its own
  access control.
- **Two modes, never mixed:**
  - `observe`: reads only. The default and the only mode of every
    subcommand outside `probe`.
  - `probe`: actively loads the host or changes knobs. Only under
    `p-rover probe <name>`, only with `--arm`, every changed knob recorded
    in a ledger on disk before it is touched and restored on exit, on
    signal and on the wall-clock cap; the restore list printed in the
    result (see Guards and Ledger under Probe).
- Non-goals: no daemon, no continuous or automatic tuning, no enforcement
  (p-usher), no fixing application code (only naming the problem).
- **Later: `apply` / `revert`** executes the changes `analyze` proposes (see
  Findings); the data model carries them from the start.

## Subcommands

### Observe

| Subcommand | What it reports |
|---|---|
| `procs` | RT threads (FIFO/RR: priority, policy, current CPU, affinity) and every thread currently on an isolated CPU, kernel threads included |
| `sched [--cpus <set>] [--duration 5s]` | Two samples of every FIFO/RR/DEADLINE thread and every thread on or allowed onto the chosen CPUs (default: isolated set): run, wait and switch rates from `schedstat`/`sched`, per-CPU totals; a thread above 10 000 voluntary switches/s is a micro-sleep poller, busy threads flagged; a reused tid is dropped; a missing `sched` file (no `CONFIG_SCHED_DEBUG`) is reported as degraded |
| `irq [--duration 5s]` | IRQ affinity and effective affinity, `/proc/interrupts` delta. Flagged: effective affinity touches an isolated CPU **and** the count moved there (managed IRQs and per-queue NIC IRQs may sit outside a mask legitimately), or the affinity deviates from the expected masks of the config. `LOC`, `CAL`, `RES`, `TLB` rates per isolated CPU against `CONFIG_HZ` (a tick rate far above HZ is a thread sleeping and waking at that rate there, see `sched`); `workqueue/cpumask`; irqbalance state |
| `cmdline` | RT-relevant keys of the live `/proc/cmdline` (isolcpus, nohz_full, rcu_nocbs, rcu_nocb_poll, irqaffinity, kthread_cpus, threadirqs, skew_tick, tsc, nosmt, idle, `*.max_cstate`, `*_pstate`, mitigations, nmi_watchdog, hugepages, transparent_hugepage, console), diffed against the declared cmdline: `declared_cmdline` from the config, otherwise a replay of `/etc/default/grub` plus `/etc/default/grub.d/*.cfg` in grub-mkconfig order with `$GRUB_CMDLINE_LINUX*` substitution (`BOOT_IMAGE`, `root=`, `ro` ignored); kernel release and PREEMPT_RT (`uname -v`, `/sys/kernel/realtime`); sysctls as they stand: the watchdogs and `watchdog_cpumask`, `hung_task_timeout_secs`, `sched_rt_runtime_us`, `timer_migration`, `vm.stat_interval`, `perf_event_paranoid`, `net.core.busy_poll`/`busy_read` |
| `nic <if>` | Link, driver, error counters (`rx_missed`, `rx_fifo`, `rx_crc`, `rx_no_buffer`, …), rings, coalescing, offloads, EEE, queues, their IRQs and IRQ threads with affinity and priority |
| `nic <if> --delta 10s` | Only the counters that moved, errors and drops first: an overflow in progress |
| `cycle [<if>] [--duration 10s] [--period <us>] [--protocol auto\|ethercat\|none]` | Cyclic traffic on an interface from the frames on the wire, per flow (ethertype, addresses, UDP ports): send interval (late/early beyond ±20 % of the nominal period, `--period` or the median), frame sizes, bursts. With a matching decoder additionally tx/rx pairing: round trip, frames without answer, protocol annotations. EtherCAT (`0x88A4`): pairing by datagram index, working-counter changes, direction without knowing the master (the first slave sets the locally-administered bit of the source MAC on the way back). Without `<if>`: the one fieldbus interface that is up, otherwise refused. Header bytes only; no payload is stored or leaves the host |
| `wake <a> <b> [--duration 10s]` | Two threads (a tid, or a comm that exactly one FIFO/RR thread carries) over the sched tracepoints: period of each, phase of b after a, who wakes b (by comm and tid), wake-to-run latency and b's runtime per activation, as histograms |
| `clock` | Who disciplines `CLOCK_REALTIME`: chrony state and sources, ptp4l/phc2sys state, PTP hardware clocks; flags two disciplining services at once |
| `lastboot [--boot -1]` | Freeze post-mortem: the previous boot's kernel log filtered for rcu, watchdog, stall, hung, blocked, oom, lockup, panic, `BUG:`, Oops, NMI, Call Trace, thermal, throttling; its last lines and whether they end in an orderly shutdown; the boot list; which hang detectors the RT tuning has disabled (absence of a stall report is not evidence of a clean shutdown) |
| `serial` | Serial ports: which ttyS is the console, IRQ, tx/rx counters, modem lines, PCI path, `console=` on the cmdline, getty units |
| `analyze --pid <pid>` | The flagship, below |

### Probe (`p-rover probe <name> --arm`)

| Probe | What it does | Restores |
|---|---|---|
| `jitter [--duration 60s]` | cyclictest on the isolated set at the configured priority and interval, one thread per isolated CPU, its main thread pinned to the housekeeping CPUs: min/avg/max per thread, count over threshold | cyclictest stopped |
| `nic-sweep <if> [--matrix quick\|full] [--cell 5s]` | Loopback harness on the configured cabled pair: `<if>` is the measured receiver, the peer the sender. Cyclic bursts of synthetic frames (EtherCAT's ethertype, a magic and a sequence number, no protocol payload) under a matrix of ring size × coalescing × IRQ core × RT hog; `quick` is the fault cell plus one knob flipped at a time, `full` all 16 cells. Needs two isolated CPUs (dirty: IRQ and hog; clean: IRQ and sink) and one housekeeping CPU (sender). A pre-flight of 50 frames proves the loop is closed before the sweep spends minutes on it. Per cell: `rx_missed`, `rx_fifo`, `rx_no_buffer`, application losses, with the knobs as actually applied | ring, coalescing, IRQ affinity, link admin state (IFF_UP, not operstate), child processes |

Limits (maximum durations, priorities, matrix axes) come from the config;
a probe refuses arguments outside them.

**Guards.** Every probe refuses, before it touches anything, when

- the live isolated set differs from the declared one (`declared_cmdline`
  or the bootloader config, see `cmdline`), or none is declared;
- a userspace FIFO/RR/DEADLINE thread with priority > 0 runs on a target
  CPU (kernel threads excluded);
- a fieldbus master seems to run: a packet socket with a known fieldbus
  ethertype (`0x88A4`, `0x8892`), a packet socket on an interface matching
  `fieldbus_interfaces`, a fieldbus NIC bound to `vfio-pci` /
  `uio_pci_generic` / `igb_uio`, or the module `ec_master` / `ec_generic`
  loaded (`nic-sweep` ignores sockets on its own pair and refuses when one
  is bound there);
- a process matches `guard_processes` or a path in `guard_paths` exists
  (site hooks, e.g. a seat reservation file);
- another probe holds the lock.

The result lists what each guard checked, also when nothing matched.

**Ledger.** A probe records every knob (name, current value, restore
action) and every child pid in `/run/p-rover/probe/<id>/plan.json`, fsynced
before the knob is changed. Restore kills the children and applies the
actions in reverse order; it runs on normal exit, on SIGINT/SIGTERM/SIGHUP
and on the wall-clock cap, is idempotent (a `restored` marker), re-reads
every knob afterwards and prints the diff against the recorded values. A
probe that dies without restoring (SIGKILL, abort) leaves its ledger:

- `p-rover probe status` lists ledgers and whether they are restored;
- `p-rover probe restore [<id> | --all]` applies them;
- every subcommand, observe included, emits the finding `stale-probe`
  while an unrestored ledger exists;
- the next probe restores stale ledgers before it writes its own.

No dead-man timer in p-rover: a wrapper that wants one runs
`systemd-run --on-active=<cap+grace> p-rover probe restore --all` next to
the call, which is all the Python original's timer did.

## Conventions for every subcommand

- `--format text|json`, `--output <file>`. JSON: `{schema_version,
  subcommand, host, started_at, mode, cost, unreadable: [...],
  records: [...], restored: [...], findings: [...]}`.
  Records are flat, typed, one per observed object, so a wrapper can map
  them onto its own record format. `unreadable` names every source the run
  could not read (a path, a netlink query, a tracepoint) with the reason,
  so a wrapper tells a partial result from a clean one without parsing
  findings.
- Exit code: 0 nothing above info, 1 warnings, 2 critical findings,
  3 the diagnostic itself failed, 4 refused (guard, limit, missing `--arm`).
- Cost class per subcommand (`light` or `heavy`, i.e. tracing or long
  windows) shown in `--help` and in the JSON header.
- Every finding of any subcommand uses the `Finding` type below, so
  `analyze` and the single subcommands report alike.

## Configuration

`/etc/p-rover.toml`, every key optional; without it every subcommand runs
with defaults and probes refuse (they need explicit limits).

```toml
fieldbus_interfaces = ["lab*"]          # globs; used by analyze and as default for nic/cycle
# declared_cmdline = "isolcpus=…"        # what cmdline should say; otherwise read from the bootloader config

[irq]
# expected = { "lan0-TxRx-*" = "4-7" }   # IRQ name glob → expected affinity

[probe]
guard_processes = []                     # comm regexes that make every probe refuse
guard_paths = []                         # paths whose existence makes every probe refuse (e.g. a seat reservation)
ledger_dir = "/run/p-rover/probe"

[probe.jitter]
max_duration = "5m"
priority = 80                            # above threaded IRQ handlers (50), below the kernel's own (99)
interval_us = 1000
threshold_us = 100

[probe.nic_sweep]
pair = []                                # [sender, receiver]; empty: probe refuses
max_duration = "10m"                     # whole sweep: cells × (cell + overhead)
cell_duration = "5s"
cell_max_duration = "30s"
matrix = "quick"
hog_priority = 90
ring_small = 256
coalesce_us = 50
freq_hz = 2000
burst = 16
frame_bytes = 128
```

## Requirements

- Most observe subcommands run unprivileged with partial results; full
  results need CAP_SYS_PTRACE (other users' fds and schedstat),
  CAP_NET_ADMIN (ethtool queries, `AF_PACKET`), CAP_BPF and CAP_PERFMON
  (tracing), or root. The JSON header's `unreadable` names what was not
  readable; a wrapper can grant the capabilities instead of root.
- Tracing: eBPF with kernel BTF (CO-RE). Fallback without BTF: tracefs,
  covering the scheduler analyses.
- External tools only where they are the reference implementation:
  cyclictest (`probe jitter`), chronyc (`clock`), the systemd journal
  (`lastboot`, via `sd-journal` or `journalctl`). Everything else native:
  procfs, sysfs, ethtool over netlink, BPF, `AF_PACKET`.

## analyze

```
p-rover analyze --pid <pid> [--tid <tid>]... [--duration 30s]
                [--static] [--protocol auto|ethercat|none]
                [--stacks] [--format text|json] [--output <file>]
```

- `--pid`: the process; all its threads are analysed.
- `--tid`: marks threads the user declares critical: they always get a
  class, a cycle chain and a per-thread section, whatever the ranking;
  without it p-rover ranks threads itself (cyclic RT threads first).
- `--static`: procfs/sysfs/ethtool only, no tracing; instant, no
  perturbation, fewer findings.
- `--stacks`: additionally samples userspace call stacks of busy threads
  (`perf_event_open`); useful only with symbols (no help for JIT runtimes).

### Data model

```
Host      cpus{online, isolated, nohz_full, rcu_nocbs, housekeeping},
          settings{sched_rt_runtime_us, irqbalance, cmdline, governor, cstates}
Process   pid, comm, exe, uid, mem{VmRSS, VmLck}, threads[]
Thread    tid, comm, policy, rt_priority, affinity, last_cpu,
          ctx_switches{voluntary, involuntary}, class, metrics
Endpoint  fd, kind{packet, udp, tcp, xdp, vfio, uio, device, other}, ifindex?, proto?, pci?
Interface name, ifindex?, pci, driver, attached{kernel, vfio-pci, uio, igb_uio, none},
          link, queues[], coalesce, channels, eee, offloads
Queue     index, irq, irq_affinity, irq_effective_affinity, irq_thread{tid, policy, prio}
```

### Collectors

Shared with the observe subcommands (`procs`, `sched`, `irq`, `nic`, `cycle`,
`wake` are views onto the same collectors).

**Static** (always):
- `/proc/<pid>/task/*/{stat,status,sched,schedstat,syscall}`
- `/proc/<pid>/fd` → socket inodes → `/proc/net/{packet,udp,udp6,tcp,tcp6,xdp}`;
  device fds such as `/dev/EtherCAT<n>` (IgH master)
- `/sys/class/net/<if>/…`, `…/device/msi_irqs`, `/proc/irq/<n>/{smp,effective}_affinity_list`,
  IRQ threads by comm `irq/<n>-<name>`
- `/sys/bus/pci/devices/<addr>` of class `0x02` (network): the bound driver.
  A device bound to `vfio-pci`, `uio_pci_generic` or `igb_uio` is a
  kernel-bypass interface, tied to the process through its `/dev/vfio/<group>`
  or `/dev/uio<n>` fds and to its IRQs through `/proc/interrupts`
  (`vfio-msi`, `uio`)
- ethtool (netlink): coalesce, channels, EEE, link, features, statistics
- `/proc/cmdline`, `/sys/devices/system/cpu/{isolated,nohz_full}`, sysctl,
  presence of irqbalance

**Traced** (default, filtered in kernel by tgid / ifindex / ethertype):
- `sched:sched_switch`, `sched:sched_waking`/`sched_wakeup` with the waker
- `raw_syscalls:sys_enter`/`sys_exit`: per-thread counts, error returns,
  arguments of sleep calls
- `timer:hrtimer_expire_entry` (attributing timer wakeups)
- `irq:irq_handler_entry`/`exit`, `irq:softirq_entry` (NET_RX) with CPU
- `net:net_dev_xmit`, `net:netif_receive_skb`: ifindex, length, ethertype,
  the first bytes for protocol decoders
- `exceptions:page_fault_user`: minor/major faults per thread

Lost events are counted and reported; a window with losses is flagged.

Filter keys: `sched:*` by the CPU set the process's threads may run on, not
by tgid (co-runners and foreign RT threads on the same CPU are the point of
A7); `net:*` by ifindex and ethertype; everything else by tgid. Syscall
counts, error returns and sleep arguments are aggregated in BPF maps per
thread, never streamed per event: a hollow-spin thread issues millions of
syscalls per second, and streaming them would be the perturbation.

### Analyses

**A1 Thread class.** Per thread over the window:
`cyclic-timer` (fixed period, hrtimer waker), `event-driven` (woken by IRQ,
softirq or another thread, named), `busy-poll` (≈100 % runtime, voluntary
switches flat), `hollow-spin` (busy-poll plus a high rate of failing
syscalls, e.g. `read(fd 135) = -EAGAIN` 2.1 M/s, with what fd 135 is),
`idle`. Metrics: period, jitter p50/p99/max, runtime per activation, slack
(period − runtime), migrations, preemptions and by whom.

**A2 Sleep API.** `clock_nanosleep` absolute vs relative (relative drifts),
clock id, `nanosleep`, `timerfd`, poll/epoll timeouts.

**A3 Memory.** `VmLck` vs `VmRSS` (missing `mlockall`), faults in the
window, faults inside a cyclic activation.

**A4 Endpoints → interfaces.** Socket and device fds to interfaces; for
unbound packet sockets (ifindex 0) the interface comes from traced tx of
the process's threads. Per interface: tx/rx rate, period, jitter.

**A5 Protocol decoders.** A trait; without a matching decoder a flow still
gets period, jitter and sizes (A4), only pairing needs one. v1 ships
EtherCAT (ethertype `0x88A4`): tx/rx pairing by datagram index → round-trip
time, frames without answer, working-counter changes. PROFINET RT
(`0x8892`, frame id and cycle counter) is the next decoder: the site's
traffic is not EtherCAT alone. The same decoders serve `cycle`.

```rust
trait ProtocolDecoder {
    fn matches(&self, ethertype: u16, head: &[u8]) -> bool;
    fn key(&self, head: &[u8]) -> Option<u64>;   // pairs tx with rx
    fn annotate(&self, head: &[u8]) -> Vec<(String, String)>;
}
```

**A6 Cycle chain.** For each cyclic thread, per activation: wakeup → tx →
rx IRQ (CPU) → NET_RX → thread wakeup; median and p99 per segment, the CPU
of each hop.

**A7 Placement.** Thread CPU and affinity vs isolated set; IRQ CPU vs the
CPU of the thread it feeds; priority order IRQ thread vs application
thread; other RT threads and co-runners (their runtime) on the same CPU.

**A8 Host settings.** RT throttling, irqbalance, coalescing, EEE, queue
count, GRO, governor and C-states.

**Kernel-bypass masters.** A master that drives the NIC from userspace
through VFIO or UIO (optimised link layers of commercial stacks, DPDK) or
through its own kernel driver (IgH native `ec_*`) takes the interface out
of the network stack: no netdev, no `net:*` tracepoints, no `AF_PACKET`.
p-rover detects this from the PCI binding and the process's fds, says so
in the report, and still delivers what remains: thread classes and cycle
(A1–A3), the device's IRQ from `/proc/interrupts` and its affinity against
the thread's CPU (A7), host settings (A8). A4–A6 and `cycle` need a netdev;
a master on a raw socket over a netdev is fully visible. The site's master
is proprietary; which link layer it uses is to be read off a host
(`/proc/<pid>/fd`, `/sys/bus/pci/devices/*/driver`) and decides how much
of phase 3 applies there.

## Findings

```rust
struct Finding {
    id: &'static str,          // stable, e.g. "irq-off-core"
    severity: Severity,        // Info | Warn | Crit
    subject: Subject,          // thread, irq, interface, host
    evidence: Vec<Metric>,     // the numbers it rests on
    recommendation: String,
    changes: Vec<Change>,      // empty when only the code can fix it
}

```

`Change` is p-roc's type (`crates/p-roc/SPEC.md`): each variant carries the
value it replaces, so `apply` can check it and revert it. p-layer applies
the same `Change`s from its UI.

Initial rules (`analyze` unless noted):

| id | when | change |
|---|---|---|
| `hollow-spin` | A1 class hollow-spin | none; names syscall, fd, rate |
| `rt-on-housekeeping` | RT thread may run on a housekeeping CPU (also `procs`) | SetAffinity |
| `irq-off-core` | rx IRQ of the thread's interface runs on another CPU | SetIrqAffinity |
| `irq-below-app` | IRQ thread priority below the application thread it feeds | SetIrqThreadPriority |
| `irq-on-isolated` | an unrelated IRQ's effective affinity touches an isolated CPU (also `irq`) | SetIrqAffinity |
| `irq-mask-drift` | IRQ affinity differs from the configured expectation (`irq`) | SetIrqAffinity |
| `shared-rt-core` | two cyclic RT threads share a CPU | SetAffinity |
| `helper-on-rt-core` | non-cyclic thread of the process on the RT core | SetPolicy / SetAffinity |
| `relative-sleep` | cyclic loop sleeps relative | none |
| `no-mlock` | VmLck < VmRSS, or faults in activations | none |
| `coalescing-on` | rx-usecs > 0 on a cyclic interface (also `nic`) | Ethtool |
| `multi-queue` | cyclic interface has several queues | Ethtool (channels 1) |
| `eee-on` | EEE enabled on a cyclic interface (also `nic`) | Ethtool |
| `nic-drops` | error or drop counters move (`nic --delta`) | none |
| `irqbalance` | irqbalance running | none |
| `deadline-miss` | runtime + jitter exceeds the period | none |
| `cmdline-drift` | live cmdline differs from the declared one (`cmdline`) | none |
| `two-clock-masters` | two services discipline the clock (`clock`) | none |
| `freeze-signature` | stall, hung-task or watchdog lines in the previous boot (`lastboot`) | none |
| `unclean-shutdown` | the previous boot's log does not end in an orderly shutdown (`lastboot`) | none |
| `isolation-drift` | live isolated set differs from the declared one (`cmdline`; refuses every probe) | none |
| `tick-on-isolated` | LOC rate on an isolated CPU far above `CONFIG_HZ` (`irq`) | none; points at `sched` |
| `stale-probe` | an unrestored probe ledger exists (every subcommand) | none; names `probe restore` |

## Report

- Text: summary, per-thread table, the cycle chain of each cyclic thread,
  findings by severity with evidence and recommendation.
- JSON: the full data model plus findings, with `schema_version`; the input
  `apply` will read.

## Perturbation

Kernel-side filtering, per-CPU ring buffers, default window 30 s. The
report states the event count, lost events and the backend, so a reader
can judge how much the measurement disturbed what it measured.

## Later: apply / revert

- `p-rover apply <report.json> [--only <finding-id>...] [--dry-run]`:
  checks each `Change`'s `from` against the live value and skips (and
  reports) one that has moved since the report, executes the rest,
  re-measures for the same window, prints before / after per finding,
  saves a revert file. The revert file is a probe ledger, so `probe status`
  and `probe restore` see it too.
- `p-rover revert <revert-file>`.
- Respects p-usher's allowed set (never moves a thread onto housekeeping)
  and warns when a change will be undone at boot by static IRQ pinning.

## Phases

1. `p-roc` extracted from p-usher (see Shared base); p-usher depends on it.
2. Static observe subcommands: `procs`, `sched`, `irq`, `cmdline`, `nic`
   (+ `--delta`), `serial`, `clock`, `lastboot`; the JSON conventions;
   `analyze --static`, including the kernel-bypass detection.
3. Tracing and packets: `wake`, `cycle`, traced `analyze` (A1-A8).
4. Probes: `probe jitter`, `probe nic-sweep`.
5. `apply` / `revert`.

## Porting source

The observe and probe subcommands replace the `rt` verbs of an existing
site diagnostics framework (TUM AIDX lab, `tum-provisioning`,
`roles/diag_tools/files/verbs/rt/*`, Python). They are the reference for
behaviour and heuristics (micro-sleep poller detection in `sched`, the
filter and disabled-detector report in `lastboot`, the guards of `jitter`,
the matrix and restore logic of `nic-sweep`, the frame decoding of `ecat`,
the probes of `wake`, the ledger and guards in `lib/aidxdiag.py`). Port the
behaviour, not the framework: no policy file of that framework, no
allow-lists, no host gating, no arming file, no dispatcher; site values
become config keys above. Not ported: the expected IRQ mask read from
`rt-irq-affinity.sh` (now `[irq] expected`), the DCV seat owner check (now
`guard_paths`), the dead-man timer (see Ledger). The notes that carry site
anecdotes become neutral recommendations.

## Shared base: p-roc

Procfs and sysfs readers, `CpuSet`, isolation sources, the thread table,
fd and socket tables, IRQs, PCI binding, fieldbus evidence, the writers,
`Change` and the probe ledger live in p-roc (`crates/p-roc/SPEC.md`).
p-roc is extracted from p-usher first; p-rover adds what it needs there as
its phases reach it. Specific to p-rover and kept here: the collectors and
analyses, the BPF programs, the protocol decoders, the rule engine, the
cmdline replay of the bootloader config, the cyclictest parser. Isolation
for p-rover is `sysfs_isolated` ∪ `nohz_full`. `apply` reads p-usher's
allowed set from `/etc/p-usher.toml` through p-roc.

## Tests

- Static collectors against fixture `/proc` and `/sys` trees, per subcommand.
- A1/A6 on synthetic event streams (cyclic, jittery, busy, hollow-spin,
  event-driven).
- Decoders on captured frames (pcap fixtures); flow statistics on a
  synthetic cyclic UDP stream without a decoder; kernel-bypass detection on
  a fixture `/sys/bus/pci` tree.
- Rule engine: table tests from data model to findings and changes.
- JSON output: snapshot tests of the schema of every subcommand.
- Probes: guard and limit refusals, including a `nic-sweep` pre-flight
  that sees no frame; restore on normal exit, error, SIGINT/SIGTERM and the
  cap against a fake knob backend; a stale ledger restored by the next
  probe, listed by `probe status`, applied by `probe restore`; the
  post-restore diff.
- Integration test (root and BPF gated): a FIFO thread with a 1 ms
  `clock_nanosleep` loop and a packet socket on a veth pair.

## Open decisions

- **BPF toolchain vs `cargo install`.** aya needs `bpf-linker` to build the
  BPF part; libbpf-rs needs clang. Both burden every `cargo install`.
  Proposed: aya in userspace (pure Rust, does the CO-RE relocations
  itself), the BPF objects built by the maintainer with `bpf-linker` in a
  `cargo xtask` step, committed and shipped in the crate, CI checking that
  object and source agree; tracing behind a Cargo feature so a build
  without it still has every static subcommand.
- **Link layer of the site's master.** Proprietary; whether it sits on a
  raw socket or bypasses the kernel (see Kernel-bypass masters) is to be
  checked on a host. It decides whether A4–A6 and `cycle` apply there or
  the report stops at A1–A3 and A7–A8.

## Resolved

- **BTF on the target kernel** (Ubuntu realtime, checked 2026-10-29): present
  and usable. A bpftrace probe dereferencing `struct sk_buff` via BTF on
  `net:net_dev_xmit`, plus `netif_receive_skb` and `sched_switch` with maps,
  loads and runs under PREEMPT_RT and sees the EtherCAT frames (`0x88A4`).
  So eBPF with CO-RE is the primary backend; the tracefs fallback only needs
  to cover the scheduler analyses (A1, A2) for kernels without BTF.
