# p-usher - specification (draft)

An usher for realtime threads: keeps unprivileged `SCHED_FIFO`/`SCHED_RR`
threads off the housekeeping CPUs of a realtime Linux host and tells the
owner when it had to step in.

License: MIT OR Apache-2.0. Distribution: crates.io (`cargo install p-usher`).

## Problem

On a PREEMPT_RT host with RT throttling disabled, a user thread at any RT
priority that never blocks owns its CPU. On a housekeeping CPU it starves
kernel threads (`rcuc/N`, `ksoftirqd/N`, kworkers) and with them the network,
NFS and ssh: the host looks dead and is reported as broken hardware. On the
isolated CPUs the same thread only competes with its owner's own work.

## Scope

- Enforces where RT threads may run. It does not cure starvation (that is
  stalld's job), does not throttle, never kills. It demotes a thread only
  when the watchdog's `demote` is switched on (see Watchdog).
- Watches the housekeeping CPUs for starvation that affinity enforcement
  cannot prevent: exempt threads, failed moves, IRQ floods.
- One host, one daemon, no network dependency for enforcement.

## Model

**Housekeeping set** H: all online CPUs minus the allowed set.
**Allowed set** A: default the content of `/sys/devices/system/cpu/isolated`;
overridable in the config. Empty A: there is no target, so no thread is
evaluated in either mode; the daemon logs an error once per change of A and
exports `p_usher_allowed_cpus 0`, so the pipeline can alert on it.

**Candidate thread**: every task under `/proc/<tgid>/task/<tid>` with
- policy `SCHED_FIFO` or `SCHED_RR`,
- not a kernel thread (`PF_KTHREAD` in `stat` flags),
- not exempt (below).

`SCHED_DEADLINE` threads are logged, never touched (their affinity is bound
to the root domain; `sched_setaffinity` fails for them).

**Violation**: affinity of a candidate ∩ H ≠ ∅.

**Action** (convention over configuration):
- affinity ∩ A ≠ ∅ → `restrict`: new affinity = affinity ∩ A.
- affinity ∩ A = ∅ → `move`: new affinity = the first CPU of A
  (overridable: `move_target`).

## Exemptions

Default: uid 0 only. Configurable additionally:
- `exempt_users` (names or uids),
- `exempt_groups` (match on any group of the thread, `Groups:` in
  `/proc/<tid>/status`, plus the primary gid),
- `exempt_comm` (regex on the thread's comm, e.g. `^ptp4l$`).

## Daemon behaviour

- Scan interval default 1 s (`interval`).
- Self-protection, configurable: `SCHED_FIFO` priority 95 (above the usual
  user cap of 90), `mlockall`, pinned to the first housekeeping CPU.
- `mode = "enforce" | "report"`. Both modes evaluate and notify the same way;
  report never calls `sched_setaffinity`. An intervention carries the mode
  as `enforced` (below), so report produces exactly the events enforce would,
  minus `failed`.
- Races: `ESRCH` (thread gone) is ignored. `EINVAL`/`EPERM` from
  `sched_setaffinity` (e.g. a cgroup cpuset without any CPU of A) produce a
  `failed` intervention, then backoff per tid so it is not retried every tick.
- A thread that re-pins itself onto H is enforced again each time, but
  notified at most once per `notify_throttle` (default 1 h) per
  (user, comm, action).
- Logs every intervention to stderr (journal under systemd).

## Interventions and notification

```rust
struct Intervention {
    host: String, at: SystemTime,
    tgid: i32, tid: i32, comm: String, exe: Option<PathBuf>,
    uid: u32, user: String,
    policy: Policy, rt_priority: u8,
    cpus_before: CpuSet,
    cpus_after: CpuSet,      // the target affinity; applied iff enforced
    action: Action,          // Restrict | Move | Failed - the decision, in either mode
    enforced: bool,          // false in report mode; Failed implies true
}

trait Notifier: Send {
    fn notify(&mut self, ev: &Intervention) -> anyhow::Result<()>;
}
```

Per action configurable whether it notifies (`[notify]`); default: every
action notifies. The switches apply in both modes; there is no separate
switch for report, since `enforced` tells the two apart downstream.
A failing notifier is logged and never blocks enforcement.

### Reference adapter 1: Prometheus textfile

Writes `<dir>/p_usher.prom` atomically (tmp + rename) after each change:

```
p_usher_interventions_total{user, action, enforced}                       counter
p_usher_last_intervention_timestamp_seconds{user, comm, action, enforced} gauge
p_usher_allowed_cpus                                                      gauge (count of A)
p_usher_up                                                                gauge
```

Gauge series expire after `retain` (default 15 m), so label cardinality stays
bounded. Mapping a user to a person or to the admin is left to the alerting
pipeline (e.g. Alertmanager routes on `user`, and on `enforced="false"` to
the admin only during a report-mode rollout).

### Reference adapter 2: email

SMTP relay (host, port, from; optional STARTTLS/auth). Recipient:
- `recipient = "{user}@example.org"` template, or a `[email.users]` map;
- functional accounts (`functional_users`, `functional_groups`, or a user
  without a map entry when no template is set) → `admin`.

Text names host, process, PID/TID, CPUs before and after, what it means and
what to do (block or sleep in the loop, pin RT threads to the allowed CPUs),
plus an optional `help_url`. Wording follows `enforced`: "was moved" versus
"would have been moved (report mode, nothing changed)".

## Watchdog

Affinity enforcement keeps unprivileged RT threads off H. It cannot help
when the thread on H is exempt (root, `exempt_*`), when the move failed
(`failed`, e.g. a cgroup cpuset), when the thread is `SCHED_DEADLINE`, or
when an IRQ thread on H floods. The watchdog notices the result instead:
a housekeeping CPU that no longer runs ordinary work. Ported from
clockwork's watchdog, with the changes noted below.

**Canaries.** One thread per housekeeping CPU, pinned there, `SCHED_OTHER`
at nice 0 (the class of `ksoftirqd` and the kworkers it stands in for),
waking every `canary_interval` and stamping a monotonic time.
- Only on H. On the isolated CPUs an RT thread owns its CPU by design; a
  starved canary there is the normal case. (clockwork ran canaries on every
  CPU and would demote the user's own cyclic thread on an isolated CPU.)
- Nice 0, not 19: a nice-19 canary falls behind under ordinary load and
  raises false alarms.

**Sentinel.** The daemon's main loop, at its own priority (`[self]`) on its
own housekeeping CPU, every `check_interval`:
- staleness of each canary ≥ `starvation_warn` → `starvation` event, once
  per episode; ≥ `starvation_act` → action (below); back under
  `starvation_warn` → `recovered`;
- attribution: from two thread-table snapshots (p-roc `task` rates), the
  threads with the most runtime on that CPU in the window, RT first, with
  policy, priority, owner and whether they are exempt;
- IRQ threads (`irq/<n>-<name>`) on a housekeeping CPU above
  `irq_warn_percent` → `irq-flood` event, above `irq_act_percent` → action.
- The sentinel cannot watch the CPU it runs on when that CPU is the one
  starved by a thread above `[self] priority`; with one housekeeping CPU the
  watchdog says so at start.

**Actions**, each off by default, so the watchdog reports first:

| Switch | When | What |
|---|---|---|
| `demote` | starvation ≥ `starvation_act`, top offender is a user RT thread | `SCHED_OTHER`, nice 0; exempt threads are never demoted, only named |
| `irq_move` | IRQ thread ≥ `irq_act_percent` | IRQ affinity to `irq_target`, default the housekeeping CPU with the fewest interrupts in the window |

At most one action per CPU per `cooldown`. `mode = "report"` applies here
too: actions are evaluated and notified with `enforced = false`. Kernel
threads are never acted on.

**Relation to stalld.** stalld cures starvation by briefly boosting the
starved thread; the watchdog names the culprit and tells its owner. Both
can run; the README recommends stalld for production.

**Events.** Watchdog events go through the same notifiers:

```rust
enum Event { Intervention(Intervention), Watchdog(WatchdogEvent) }

struct WatchdogEvent {
    host: String, at: SystemTime, cpu: u32,
    kind: WatchdogKind,            // Starvation | Recovered | IrqFlood | Demoted | IrqMoved | Failed
    staleness: Duration,
    offenders: Vec<Offender>,      // tid, comm, user, policy, priority, cpu %, exempt
    change: Option<Change>,        // p-roc Change of the action, with its `from`
    enforced: bool,
}

trait Notifier: Send {
    fn notify(&mut self, ev: &Event) -> anyhow::Result<()>;
}
```

Email: `demoted` goes to the thread's owner (as interventions do),
`starvation`, `irq-flood` and `irq-moved` to `admin`. Prometheus adds:

```
p_usher_watchdog_staleness_seconds{cpu}             gauge
p_usher_watchdog_events_total{kind, enforced}       counter
```

## Status file

`/run/p-usher/state.json`, written atomically after every change of state:
mode, allowed and housekeeping sets, the watchdog's staleness per CPU, the
last 100 events. Read by p-layer; nothing else depends on it. p-usher has
no network API.

## Configuration

`/etc/p-usher.toml`, every key optional:

```toml
mode = "enforce"
interval = "1s"
# allowed_cpus = "8-15"        # default: /sys/devices/system/cpu/isolated
# move_target = 8              # default: first allowed CPU
exempt_users = []
exempt_groups = []
exempt_comm = []
notify_throttle = "1h"

[self]
priority = 95

[notify]
restrict = true
move = true
failed = true

[prometheus]
dir = "/var/lib/node_exporter"
retain = "15m"

[watchdog]
enabled = false
canary_interval = "100ms"
check_interval = "500ms"
starvation_warn = "2s"
starvation_act = "5s"
irq_warn_percent = 60
irq_act_percent = 80
cooldown = "5s"
demote = false
irq_move = false
# irq_target = 0               # default: least-loaded housekeeping CPU

# [email]
# relay = "mail.example.org:25"
# from = "p-usher@example.org"
# recipient = "{user}@example.org"
# admin = "admin@example.org"
# functional_groups = ["svc"]
# help_url = "https://example.org/realtime"
```

## Shipped with the crate

- `contrib/p-usher.service` (systemd, `Restart=always`).
- `contrib/p-usher.toml` (the example above).
- README: what it does, what it deliberately does not do, pairing with stalld.

## Tests

- `/proc` parsing (`stat`, `status`, `sched`) against fixture trees.
- The decision function (thread, A, H, exemptions) → action: pure, table-tested.
- Report mode: the same inputs yield the same `action` and `cpus_after` as
  enforce, with `enforced = false` and no `sched_setaffinity` call; empty A
  yields no interventions in either mode.
- Throttle and backoff logic with a fake clock.
- Adapters: textfile output format and expiry; email rendering and recipient
  resolution (no SMTP in tests).
- An integration test that spawns a FIFO thread pinned to H, gated on
  `CAP_SYS_NICE`, skipped otherwise.
- Watchdog with a fake clock and synthetic thread tables: warn, act and
  recover thresholds; one event per episode; cooldown; attribution order;
  exempt and kernel threads never acted on; no canary on an isolated CPU;
  report mode yields the same events with `enforced = false`.
- Status file: content and atomic replace.

## Shared code

The `/proc` parsing, `CpuSet`, `Policy`, `ThreadInfo` and the `sys` writers
move to p-roc (see `crates/p-roc/SPEC.md`); p-usher keeps its decision,
engine, configuration and notifiers. The extraction must not change
behaviour: the existing tests pass with only their imports changed.
