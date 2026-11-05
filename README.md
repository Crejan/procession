# procession

Tools for the processes of a realtime Linux host. Each tool is its own crate
and binary; they share one library and one set of conventions.

| Crate | Binary | Role | Spec |
|---|---|---|---|
| `p-roc` | - | Library: reads and writes what the kernel knows about CPUs, threads, IRQs, sockets and devices (`/proc`, `/sys`) | [`crates/p-roc/SPEC.md`](crates/p-roc/SPEC.md) |
| `p-usher` | `pusher` | Daemon: keeps unprivileged RT threads off the housekeeping CPUs; watchdog for starved housekeeping CPUs | [`crates/p-usher/SPEC.md`](crates/p-usher/SPEC.md) |
| `p-rover` | `prover` | Diagnosis: one command per question, and `analyze`, which explores one process per cycle | [`crates/p-rover/SPEC.md`](crates/p-rover/SPEC.md) |
| `p-layer` | `player` | Starts, places and tunes the processes of a host and shows them running; web UI | [`crates/p-layer/SPEC.md`](crates/p-layer/SPEC.md) |
| `p-lumber` | `plumber` | Lists and subscribes to iceoryx2 services, decodes samples, measures rate, jitter and loss, benchmarks pub/sub | [`crates/p-lumber/SPEC.md`](crates/p-lumber/SPEC.md) |

Each name reads twice: an usher who seats threads (pusher), a rover who
explores (prover), a player on stage (player), a plumber for the pipes
between processes (plumber), and `/proc` (p-roc).

## Conventions

- License MIT OR Apache-2.0; edition 2024; MSRV 1.85; published on
  crates.io, so `cargo install p-usher` etc. needs nothing but cargo.
- Linux at runtime; p-lumber also on macOS. Readers take a root (`/proc`,
  `/sys`) so tests run against fixture trees on any OS.
- Configuration in `/etc/<crate>.toml`; every key optional; defaults work.
- Machine output: `--format json` with `schema_version`, one record type per
  observed object.
- Every change a tool makes to a thread, an IRQ or a NIC is a `Change` from
  `p-roc`: it carries the value it replaces, so it can be checked before it
  is applied and reverted afterwards.
- Each crate is versioned and released on its own; tags `<crate>-v<version>`.

## Layout

```
Cargo.toml          workspace
crates/p-roc/
crates/p-usher/     contrib/ (unit file, example config)
crates/p-rover/     bpf/ (BPF sources and the shipped objects)
crates/p-layer/     templates/, assets/ (embedded into the binary)
crates/p-lumber/
xtask/              maintainer tasks: build and check the BPF objects
```

p-lumber depends on iceoryx2, which needs clang to build. It is left out of
the workspace's `default-members`, so `cargo build` and `cargo test` in the
root need no clang; `cargo build -p p-lumber` builds it, in its own CI job.

`xtask` is a small, unpublished binary crate run as `cargo xtask <task>`
(alias in `.cargo/config.toml`); it replaces shell scripts and a Makefile.

## Order of work

1. Extract `p-roc` from `p-usher`; `p-usher` depends on it, behaviour unchanged.
2. `p-usher` watchdog.
3. `p-rover` phases (static observe subcommands first).
4. `p-layer` phases (read-only views first).
5. `p-lumber` phases (independent of 2-4; can start any time after 1).

## Build

```sh
cargo build              # default members: everything but p-lumber
cargo test
cargo build -p p-lumber  # needs clang
```
