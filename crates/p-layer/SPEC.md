# p-layer - specification (draft)

A player for realtime hosts: starts, places and tunes the processes of a
host and shows them running. One daemon per host, a web UI, a script-friendly
CLI and a view-only TUI. Binary `player`.

It merges two earlier tools: clockwork (host view and tuning: CPU topology,
threads, IRQs, kernel parameters) and the process lifecycle of labcommander
(workspaces of systemd user units, start and stop, persistent tuning, debug
wrappers, logs). Siblings: p-usher enforces where RT threads may run, p-rover
diagnoses, p-roc is the shared library.

License: MIT OR Apache-2.0. Distribution: crates.io (`cargo install p-layer`).

## Problem

Working on a realtime host means starting a set of programs, pinning each to
the right CPUs at the right priority, checking where their threads and the
IRQs that feed them actually run, and changing that while they run. Today
that is `systemctl --user`, unit files edited by hand, `chrt`, `taskset`,
`/proc/irq/*/smp_affinity_list`, `journalctl` and `top`, each with its own
view, and a tuning that lives either in a unit file or only in the running
process, with nothing showing which.

## Scope

- One host, one daemon (`player serve`), many users.
- User services in workspaces (systemd user units), not system units.
- Tuning of threads, IRQs and units: affinity, policy, priority, nice.
- Monitoring of units, threads, CPUs and IRQs at about 1 Hz.
- Non-goals: no enforcement (p-usher), no diagnosis rules of its own (it
  shows p-rover's findings), no IPC monitoring (p-lumber), no automatic
  tuning, no multi-host dashboard in v1.

## Architecture

```
browser ──ssh -L──┐
player CLI ───────┼──> /run/p-layer/p-layer.sock ──> player serve (root)
player tui ───────┘         HTTP + WebSocket          ├─ p-roc (proc, sys, knobs)
                                                      ├─ user managers (D-Bus, as the user)
                                                      └─ journal
```

- `player serve` runs as a system service and listens on a Unix socket.
  HTTP for pages and commands, one WebSocket per client for live data.
- **Identity from the socket.** The daemon reads the peer's uid with
  `SO_PEERCRED`. A browser reaches the socket through SSH local forwarding
  (`ssh -L 8080:/run/p-layer/p-layer.sock host`): sshd connects as the
  logged-in user, so the uid is that user's. No passwords, no TLS, no
  sessions. Anyone who can open the forwarded port on the client machine
  acts as that user; the README says so.
- An optional TCP listener (`listen`, default off, loopback only) serves
  read-only: it has no peer identity.
- Requests from a browser must carry an `Origin` that matches `Host`
  (HTTP commands and the WebSocket upgrade), against cross-site requests to
  a forwarded port.
- The CLI and the TUI use the same socket and the same API.

## Authorization

| Who | May |
|---|---|
| everyone | view everything (as `ps` does) |
| a user | manage units of their own workspaces; tune their own threads |
| admin (root or `admin_group`) | the above for every user; IRQ affinity, IRQ thread priority, kernel threads, enable lingering |

Tuning limits for non-admins:
- A FIFO or RR setting needs an affinity inside p-usher's allowed set (read
  from `/etc/p-usher.toml` through p-roc); otherwise it is refused with the
  reason, since p-usher would move the thread anyway.
- RT priority at most `max_user_priority` (default 90), and never above the
  user's `RLIMIT_RTPRIO` when that is lower.

## Workspaces and units

From labcommander:

- A workspace is a directory of `.service` files: `<ws>/<hostname>/` for
  this host, `<ws>/` as shared fallback. A user registers workspaces in
  `~/.config/p-layer/workspaces.toml` or in the UI.
- Units are linked into the user's systemd manager (`LinkUnitFiles`), so the
  workspace stays the source; link state is enabled, disabled or conflict
  (another file of that name is linked). Replacing a conflicting link is an
  explicit action.
- Lifecycle: start, stop, restart, enable, disable, daemon-reload. State
  shown: active and sub state, main PID, restarts, start time.
- A user's units only outlive their session with lingering; the UI shows
  whether it is on, and an admin can enable it.
- **Acting as the user.** Talking to a user manager and writing into a
  workspace happen in a short-lived child that has dropped to the user's
  uid and groups before it connects to `/run/user/<uid>/bus` or opens a
  file. The daemon never writes as root into a path a user controls.

## Tuning

Every change is a p-roc `Change`: it records the value it replaces, is
checked against the live value before it is applied, and is logged to the
journal with the uid that asked for it. The UI offers undo of a user's
recent changes (the reverted `Change`).

- **Unit (persistent).** `CPUAffinity`, `CPUSchedulingPolicy`,
  `CPUSchedulingPriority`, `Nice` written into the workspace unit file
  (atomically, the rest of the file and its comments kept), then applied
  live to every thread of the unit's processes that still carries the
  unit's previous setting, which is what a restart would produce.
- **Thread (live).** Affinity, policy, priority, nice of a single thread;
  not persistent. The UI marks a thread whose live setting differs from its
  unit file.
- **IRQ (admin).** Affinity of an IRQ, priority of its IRQ thread; effective
  affinity shown next to the requested one. Not persistent; the UI says
  where a boot-time pinning (a script, irqbalance) would undo it.
- **From p-rover.** For a unit's main process, `prover analyze --static`
  runs in-process (p-rover is also a library); its findings and their
  `Change`s are shown and can be applied through the same path.

## Debug wrappers

From labcommander: presets `strace`, `ltrace`, `gdbserver`, `valgrind`,
`perf record`, `heaptrack`, plus custom commands from the config.

- Implemented as a drop-in, `~/.config/systemd/user/<unit>.d/50-p-layer-debug.conf`,
  that resets `ExecStart=` and sets the wrapped command. The workspace unit
  file is not touched; removing the drop-in removes the wrapper.
  (labcommander rewrote `ExecStart` and kept the original in an
  environment variable.)
- Output files go to `$XDG_RUNTIME_DIR/p-layer/<unit>.<tool>`, not `/tmp`.
- `gdbserver` binds to loopback.
- A wrapper takes effect on the next start; the UI says so.

## Monitoring

| View | Content |
|---|---|
| Host | topology map (packages, cores, SMT siblings, NUMA, role per CPU) with load per CPU; load average and run queue; isolation sources; p-usher state and recent interventions; count of p-rover findings |
| Units | per workspace: state, PID, CPU %, RSS, threads, fds, restarts, switch rates, minor/major faults, I/O bytes, uptime, tuning (file vs live) |
| Threads | filter by kind, CPU, policy, unit, text; per thread: policy, priority, nice, last CPU, allowed set, CPU %, switch rates, kind, description |
| IRQs | per IRQ: name, chip, devices, affinity and effective affinity, rate per CPU, IRQ thread and its priority, description; `LOC` and IPI rates per CPU |
| Kernel | cmdline parameters with descriptions, isolation, RT throttling, irqbalance |
| Logs | journal of a unit, paged by cursor, live tail |

Values are sampled at 1 Hz, and only for what some client subscribes to.
p-usher's state comes from its status file (`/run/p-usher/state.json`).

## Web UI

- Server-rendered HTML (`maud`), `htmx` with its WebSocket extension for
  live updates, the topology map as SVG rendered by the server. No Node, no
  build step: templates and the few vendored files (`htmx`, its WebSocket
  extension, a stylesheet) live in `crates/p-layer/templates/` and
  `assets/` and are embedded into the binary, so `cargo install` ships them
  and the UI works offline.
- Pages: Host, Units, Threads, IRQs, Kernel; light and dark.
- The page layout of clockwork's views is the reference; its Vue code is not
  ported.

## WebSocket protocol

One WebSocket per client at `/ws`. Every message is one JSON object in an
envelope:

```json
{ "v": 1, "type": "...", "id": "optional request id", "topic": "...", "data": {} }
```

- Client → server: `subscribe { topics, format: "html" | "json" }`,
  `unsubscribe { topics }`, `ping`.
- Server → client: `snapshot` (the full state of a topic, each tick),
  `event` (lifecycle changes, applied changes, journal lines), `error`,
  `pong`.
- Topics: `host`, `units/<workspace>`, `unit/<name>`, `threads?<filter>`,
  `irqs`, `logs/<unit>`, `events`.
- `format: "html"` sends fragments with `hx-swap-oob` for htmx; `json` the
  same data as typed records for the TUI and the CLI.
- Commands go over HTTP (`POST /api/...`, JSON in, JSON or an HTML fragment
  out) in v1. The envelope reserves `type: "command"` with `id`, and a
  matching `result`, so commands can move onto the socket later without a
  new protocol version.

## HTTP API

```
GET  /api/host | /api/threads | /api/irqs | /api/kernel
GET  /api/workspaces | /api/units/<ws> | /api/units/<ws>/<unit>/logs?cursor=
POST /api/units/<ws>/<unit>/{start,stop,restart,enable,disable,force-enable}
POST /api/units/<ws>/<unit>/tuning        { affinity?, policy?, priority?, nice? }
POST /api/units/<ws>/<unit>/debug         { preset | command } / DELETE
POST /api/threads/<tid>/tuning            { affinity?, policy?, priority?, nice? }
POST /api/irqs/<n>/affinity               { cpus }
POST /api/changes/<id>/revert
GET  /ws
```

Responses carry `schema_version`; an error names the check that refused it
(authorization, allowed set, priority limit, value moved since it was read).

## CLI and TUI

- `player <command> [--format text|json]`: `ws list`, `status [<unit>]`,
  `start|stop|restart|enable|disable <unit>`, `tune <unit> | --tid <tid>
  [--cpus] [--policy] [--priority] [--nice]`, `irq <n> --cpus`, `debug
  <unit> <preset> | --clear`, `logs <unit> [-f]`. Exit codes as in p-rover
  (0 ok, 3 failed, 4 refused).
- `player tui`: view only (units, threads, CPU map), JSON over the
  WebSocket.

## Configuration

`/etc/p-layer.toml`, every key optional:

```toml
socket = "/run/p-layer/p-layer.sock"
# listen = "127.0.0.1:3100"          # read-only TCP, off by default
admin_group = "wheel"
max_user_priority = 90
sample_interval = "1s"

[[debug_wrapper]]                    # in addition to the presets
id = "ltrace-net"
command = "/usr/bin/ltrace -e socket+connect -o {out}"
```

## Privileges

`player serve` runs as root under systemd (`contrib/p-layer.service`) with
the hardening that leaves `/proc/irq` writable. It needs `CAP_SYS_NICE`
(other users' threads), write access to `/proc/irq/*` (root-owned files) and
`CAP_SETUID`/`CAP_SETGID` (acting as a user); in practice root. Without
them it serves read-only and says which capability is missing.

## Porting source

- clockwork (`backend/`): readers and writers → p-roc; routes → HTTP API;
  `descriptions` → p-roc `describe`; the watchdog → p-usher. Vue frontend
  not ported.
- labcommander: `core/domain.rs` (`UnitConfig`, `UnitStatus`,
  `ProcessInfo`, `UnitMetrics`, `LinkInfo`, debug wrappers),
  `adapter-system-linux` (systemd over D-Bus, unit file editing, process
  metrics), the CLI commands and the TUI's process view.
- Not ported: the iceoryx2 transport, agent discovery and the per-workspace
  agent (one daemon per host replaces them), the IPC monitor and benchmarks
  (p-lumber), the async ports-and-adapters layer (p-roc's rooted readers
  and a fake systemd backend cover testing).

## Tests

- HTTP and WebSocket handlers against p-roc fixture trees and a fake
  systemd backend: subscribe, snapshot, event, error envelope.
- Authorization table: user × target × action → allowed or the refusal
  reason; RT outside the allowed set; priority over the limit.
- Unit file editing: tuning keys written, other lines and comments kept,
  atomic replace; debug drop-in written and removed.
- Change path: applied, skipped because the value moved, reverted.
- `SO_PEERCRED` identity on a real socket; TCP listener refuses commands.
- Integration (Linux, root-gated): a user unit in a temp workspace started,
  tuned, wrapped and stopped.

## Phases

1. Read-only daemon: socket, identity, WebSocket, Host, Threads, IRQs and
   Kernel pages.
2. Tuning of threads and IRQs with authorization and the change journal.
3. Workspaces and lifecycle, logs, debug wrappers.
4. CLI and the view-only TUI.
5. p-rover findings and p-usher state in the UI.

## Later

Multi-host overview, system units, `SCHED_DEADLINE`, cgroup cpusets,
traced `analyze` from the UI, commands over the WebSocket, the iceoryx2
services of a unit (from `plumber nodes --format json`, matched by pid,
without linking iceoryx2 into p-layer).

## Open decisions

- **One root daemon or one daemon per user.** labcommander ran an agent per
  workspace as the user, with `CAP_SYS_NICE` set on the binary, which lets
  any user re-prioritise any process. One root daemon that acts as the user
  for user things is proposed above; it is the larger attack surface in one
  process.
- **Template library.** `maud` (Rust syntax, checked at compile time) or
  `askama` (HTML files, closer to what a web designer edits).
