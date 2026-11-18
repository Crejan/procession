# Runbook: trying `prover` (phase 2) on the Debian 13 container

Status: written without ever running `prover` on Linux. Everything under
"Expect" is what the code is built to print on a plain unprivileged LXC
container, read from its logic and its fixture tests, not observed. When a
line differs, that is the finding: send me the JSON.

**Nothing here changes the machine.** Every `prover` subcommand of phase 2 is
read-only: it reads `/proc`, `/sys`, `/etc/default/grub*`, `/boot/config-*`,
and runs only `chronyc` and `journalctl` (read-only queries). The only file
written is the one you name with `--output`. No probe, no `--arm`, no sysctl,
no affinity or priority is touched; the proposed `changes` in a finding are
printed, never applied.

## The short sequence (Debian container)

    cargo build --release -p p-rover
    target/release/prover procs
    target/release/prover irq --duration 3s
    target/release/prover cmdline
    target/release/prover nic eth0
    target/release/prover hung
    target/release/prover analyze --pid 1 --static

Each prints a header line, record lines and findings (none expected on a
container); `echo $?` should give 0. The sections below say what each line
should show and what a container cannot show.

## Build

On the container (needs Rust 1.91 or newer and the crates for this workspace;
there is no network need beyond what `cargo fetch` already did):

    cargo build --release -p p-rover
    ls target/release/prover

or build on the Linux host that has the toolchain and copy the single binary.
Then, in any directory:

    export PATH=target/release:$PATH
    prover --version

Linux-only code in phase 2 is only in `p-roc/src/sys.rs` (writers, unused by
`prover`), so the first Linux compile is of code that was moved unchanged.

## Run, one at a time

Add `--format json` to any of them for the full object; the text form is the
quick look. Exit codes: 0 nothing above info, 1 warnings, 2 critical, 3 failed,
4 refused. `echo $?` after each.

    prover procs
    prover sched --duration 3s
    prover irq --duration 3s
    prover cmdline
    prover nic eth0
    prover nic eth0 --delta 5s
    prover serial
    prover clock
    prover lastboot
    prover hung --duration 2s
    sleep 600 &
    prover analyze --pid 1234 --static

For the last one use the process id that `sleep 600 &` printed instead of
1234. Stop it with `kill 1234` afterwards.
Replace `eth0` with the container's interface (`ls /sys/class/net`).

## Expect in a plain unprivileged container

| Command | Expect |
|---|---|
| `procs` | Header line, then `thread` lines for RT threads and threads on isolated CPUs, then `summary`. The container sees its own processes only, so usually no RT thread: `rt_threads=0`. `isolated_cpus` is the **host's** value if `/sys/devices/system/cpu/isolated` shows through (empty on a host without isolcpus). Exit 0. |
| `sched` | A `thread` line per RT thread and per thread allowed on the isolated CPUs (with an empty isolated set: only RT threads, so possibly none), `cpu` lines, `summary` with `sched_debug=true` when `/proc/<pid>/task/<tid>/sched` exists. `unreadable` may list `schedstat` if the kernel has it off. |
| `irq` | `policy`, `timer`, `irq` lines (busiest IRQs that moved in the window), `summary`. `/proc/interrupts` is the host's; the affinity files may be unreadable or absent in the container: then `irq` lines are missing and `unreadable` says why. `kernel_hz` is `null` unless `/boot/config-<release>` is visible. Findings only if the host has isolated CPUs. |
| `cmdline` | `live` is the **host's** command line. `declared` has `source: none` (no `/etc/default/grub` in the container), so no drift finding. `kernel` shows the host's release and whether it is PREEMPT_RT. `sysctl`: the readable ones, `null` for the rest. |
| `nic eth0` | `link` from sysfs (veth: no `driver`/`pci`, queues 1), `driver`, `stats`. Rings, coalescing, channels, EEE and offloads come from the `ethtool` binary when it is installed; a veth supports few of them, so `unreadable` lists each refused one (`ethtool -c eth0: Operation not supported`) and `ethtool: not installed` if the binary is missing. The ethtool parsers are **not yet checked against a capture**. |
| `nic eth0 --delta 5s` | `counter` lines for what moved (traffic only, on a quiet container maybe none), `summary` with `clean: true`. |
| `serial` | `cmdline` with `console=` of the host, `active_console`, probably no `port` lines; `unreadable` names `proc/tty/driver/serial` if absent. |
| `clock` | `unreadable` entry `chronyc` if not installed; `service` lines only for time daemons inside the container; `summary` with `conflict: false`. |
| `lastboot` | Likely `unreadable` entries for `journalctl` (no persistent journal, or no access to the kernel log from a container), and no findings: it does not guess a verdict. |
| `hung` | `detector` line and `summary` with `hung: 0`. If a task is in D state in both samples it is listed; `unreadable` says the kernel stacks need root. |
| `analyze --pid <p> --static` | `host`, `process`, one `thread`, `endpoint` lines for its sockets (none for `sleep`), `summary`. `unreadable` lists `ethtool` is not relevant (no interface). Findings: possibly `irqbalance` if the container sees the process. |

## What a container cannot show (needs a real host)

- The isolated CPU set, `nohz_full`, RT threads, IRQ affinity of real
  devices, and everything that is a finding of `procs`, `sched`, `irq`,
  `cmdline` on an RT host: a container shows the host's cpu files but not
  its processes, and `/proc/irq` access is limited.
- Real NICs: PCI binding (`/sys/bus/pci/devices`), `vfio-pci`/`uio`
  kernel-bypass detection, MSI IRQ lists and IRQ threads of a NIC queue,
  `nic --delta` on a counter that really moves.
- `ethtool` data of any kind (needs the transport decision and a real NIC).
- PTP hardware clocks (`/sys/class/ptp`), serial ports, the previous boot's
  journal (`lastboot`), kernel stacks (`hung`, root), other users' fds and
  syscalls (`CAP_SYS_PTRACE`).
- Phases 3 to 5 need privileges on a host: BPF (`CAP_BPF`, `CAP_PERFMON`),
  tracefs, `perf_event_open`, `AF_PACKET` raw sockets (`CAP_NET_RAW`), veth
  pairs and cyclictest for the probes. An unprivileged LXC has none of them.
  A privileged container with nesting can get some, but the realtime
  results (isolated CPUs, jitter) only mean something on the real host.

## Cross-check on the real host (when you have one)

Run `prover procs --format json` and the Python `rt procs` verb side by side
on an RT host and compare: the same RT threads, the same `cpus_allowed`,
`on_isolated`. Same for `irq` against `rt irq` (flagged IRQs) and `cmdline`
against `rt cmdline`. Differences I expect and chose: `procs` lists RT
threads first and has no `pcpu`; `cmdline` compares `GRUB_CMDLINE_LINUX`
before `_DEFAULT` as grub does.

## Captures I need from a real host (ethtool)

The ethtool parsers were written from ethtool's documented layout, not from
real output. On a host with a real NIC (Intel igb/ixgbe/i40e if possible; a
second driver if there is one), as any user (these only read), with `eth0`
the NIC. The files go to `crates/p-rover/tests/captures/<ethtool version>/`,
where `tests/ethtool_captures.rs` picks them up (its README there names the
files). Exactly:

    ethtool --version
    mkdir cap
    cd cap
    for opt in -i -S -g -c -l --show-eee -k; do ethtool $opt eth0 > "$opt.txt" 2> "$opt.err"; echo $? > "$opt.code"; ethtool --json $opt eth0 > "--json_$opt.txt" 2> "--json_$opt.err"; echo $? > "--json_$opt.code"; done
    ls

Then copy the folder `cap` into the repository as
`crates/p-rover/tests/captures/6.7/` (use the version `ethtool --version`
printed instead of 6.7). A command the NIC or the ethtool version refuses
leaves a nonzero `.code` and a message in `.err`; that is wanted, the parser
must handle it. Until the files are there the test prints `SKIPPED` and counts
as not run, and every ethtool parser stays "not yet checked against a capture".
