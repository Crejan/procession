# p-lumber - specification (draft)

A plumber for zero-copy IPC: lists the iceoryx2 services of a host,
subscribes to any of them without knowing its type, shows and decodes the
samples, measures rate, jitter and loss, and benchmarks a pub/sub path at
realtime priority. Binary `plumber`.

Part of procession: p-layer starts and tunes the processes that publish and
subscribe, p-rover diagnoses their threads and NICs, p-roc is the shared
library. p-lumber knows nothing of either tool; p-layer may link to it.

License: MIT OR Apache-2.0. Distribution: crates.io (`cargo install p-lumber`).
Runs on Linux and macOS (iceoryx2 does); realtime priority only on Linux.

## Problem

iceoryx2 moves samples through shared memory, so nothing on the wire shows
them. A developer who wants to know whether a publisher runs, at what rate,
how regularly and with what content, writes a throwaway subscriber that
needs the publisher's Rust type. The iceoryx2 CLI lists services and nodes,
but does not decode payloads or measure timing.

## Scope

- iceoryx2 publish/subscribe first; events and request/response listed,
  not measured.
- The middleware sits behind a trait (`Transport`), so another can be
  added later without touching the views.
- Non-goals: no process management (p-layer), no broker, no tuning of the
  publishers (p-layer, p-rover), no recording in v1.

## Subcommands

| Subcommand | What it does |
|---|---|
| `list [<glob>]` | Services: name, messaging pattern, payload type name, size and alignment, user header type, number of publishers and subscribers; dead nodes flagged |
| `nodes` | Nodes with name, pid, comm and state (alive, dead, inaccessible) |
| `inspect <service>` | The static configuration of one service: type details, buffer and history sizes, max publishers and subscribers, attributes |
| `echo <service> [--pattern <fmt>] [--count <n>]` | Samples as they arrive: arrival time, size, user header, payload decoded by a pattern or as hex |
| `stat <service> [--duration 10s] [--period <us>] [--cpu <n>] [--priority <p>]` | Arrival statistics: rate, interval min/avg/max/stddev, jitter (deviation from the nominal period, `--period` or the median) p50/p90/p99/max as histogram, payload sizes; loss and the longest gap in sequence numbers when the pattern names a sequence field |
| `bench pub\|sub\|pair <service> [--rate <hz>] [--size <bytes>] [--duration] [--cpu] [--priority]` | Benchmark with its own payload (sequence number, publisher timestamp): latency publisher → subscriber, jitter, loss, longest loss run, throughput; `pair` runs both ends in one process on two CPUs |
| `tui` | Live view: service tree, a subscription with decoded samples and running statistics |

Every subcommand follows the conventions of the workspace: `--format
text|json` with `schema_version`, exit codes 0 ok, 3 failed, 4 refused.

## Measurement

- **Where the time comes from.** `stat` and `echo` see when plumber receives
  a sample, not when it was published; the output says so. Publisher time is
  only known in `bench`, or when the pattern names a timestamp field and
  both ends share `CLOCK_MONOTONIC` (same host).
- **How samples are noticed.** With a notifier on the service (an event
  service of the same name, iceoryx2's convention), plumber waits on it.
  Without one it polls; `stat` then busy-polls on the CPU given with
  `--cpu`, at the priority given with `--priority`. The output names the
  method and, for polling, the resolution it limits the result to.
- **Realtime thread.** The measuring thread's affinity and priority are
  set through p-roc. On Linux it refuses an RT priority on a CPU outside
  p-usher's allowed set (p-usher would move it mid-measurement) and names
  the set. On macOS the options are refused.
- **Benchmark payload.** A fixed `#[repr(C)]` struct (sequence, timestamp,
  padding to `--size`), written in place. labcommander serialised the
  benchmark sample as JSON into a 4 KiB buffer, which put allocation and
  formatting into the measured path.

## Decoding payloads

- Format strings in the style of Python's `struct` (from labcommander's
  `binary_pattern`): byte order `< > =`, `b B h H i I q Q f d`, `Ns` bytes,
  `Nx` padding, optional field names (`seq:Q ts:Q x:f y:f`).
- Field roles by name: a field named `seq` drives loss detection, `ts_ns`
  publisher-side latency.
- Patterns per service glob in `~/.config/p-lumber/types.toml` (the
  `types.yaml` planned in labcommander's TODO), or `--pattern` on the
  command line. A pattern whose size differs from the service's payload
  size is refused with both sizes.
- Without a pattern: the type name iceoryx2 records and a hex dump.

## Untyped subscription

To subscribe without the publisher's Rust type, plumber opens the service
with the type details it reads from the service's static configuration.
labcommander did this with `__internal_set_payload_type_details`, an
internal iceoryx2 API. p-lumber pins the iceoryx2 version, has a test that
fails when the API changes, and tracks a public way upstream (see Open
decisions).

## Configuration

`/etc/p-lumber.toml` and `~/.config/p-lumber/types.toml`, every key
optional:

```toml
[stat]
duration = "10s"
# cpu = 7
# priority = 80

[[type]]
service = "robot/*/joint_state"
pattern = "<seq:Q ts_ns:Q 6d"
```

## Build

iceoryx2 needs clang to build. p-lumber is therefore not in the workspace's
`default-members`: `cargo build` and `cargo test` in the repository root
build the other crates without clang; `cargo build -p p-lumber` and its own
CI job build this one. `cargo install p-lumber` needs clang on the machine.

## Shared code

From p-roc: `stats` (percentiles, histograms), `sys` (affinity, priority),
`cpuset`, and the reader for p-usher's allowed set. Nothing from p-layer or
p-rover.

## Porting source

labcommander:
- `core/src/binary_pattern.rs` (pattern parser and decoder, with its tests),
- `core/src/benchmark.rs` (`BenchmarkSample`, `JitterMetrics`),
- `core/src/domain.rs` (`Iox2ServiceInfo`, `Iox2ServiceType`,
  `Iox2ServiceTree`, `Iox2Sample`),
- `adapter-ipc-iceoryx2/src/ipc.rs` (`discover_services`, `subscribe_once`,
  `create_subscriber`, `discover_service_types`) and `benchmark.rs`,
- `adapter-benchmark` (publisher, subscriber, monitor),
- the TUI's service tree and subscription popup (`view/popups/iox2_subscribe.rs`).

Not ported: the agent's state publishing, discovery and RPC over iceoryx2
(p-layer's daemon replaces the agent), and the ard-rs adapter, which only
carried that agent traffic and depends on a local path outside crates.io.

## Tests

- Pattern parser and decoder: table tests (from labcommander), size
  mismatch, named fields.
- Statistics on synthetic arrival streams: regular, jittery, bursty, with
  gaps in the sequence.
- An in-process publisher and plumber on a test service (iceoryx2 runs in
  tests on Linux and macOS): `list`, `inspect`, `echo`, `stat`, `bench
  pair` end to end; JSON snapshots.
- The untyped subscription against the pinned iceoryx2 version.

## Phases

1. `list`, `nodes`, `inspect`, `echo`, `stat`.
2. `bench`.
3. `tui`.

## Later

Other hosts through the iceoryx2 zenoh tunnel (labcommander's remote hosts
went that way); recording samples to a file and replaying them; events and
request/response timing; in p-layer, the services of a unit, matched by the
pids of `plumber nodes --format json`.

## Open decisions

- **Untyped subscription.** Stay on the internal API with a pinned version,
  or ask iceoryx2 upstream for a public one before release.
- **ard-rs.** If ard-rs is a middleware the lab uses for application data,
  not only for labcommander's agent, it becomes a second `Transport`; it
  then needs to be on crates.io first.
